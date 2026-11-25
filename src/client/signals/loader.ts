/**
 * Two-phase entropy-source loader, adapted from FingerprintJS v5
 * (`src/utils/async.ts` + `src/utils/entropy_source.ts`).
 *
 * This module is deliberately generic and dependency-free: it knows nothing
 * about the concrete signal collectors in `index.ts`. It provides the five
 * observable primitives of the FingerprintJS OSS loader:
 *
 *  - `loadSource`: start a source's `load` phase immediately and return a
 *    getter that yields `{ value, duration }` or `{ error, duration }`.
 *  - `loadSources`: load a fixed declaration-order registry with ONE shared
 *    options/cache object, returning `getComponents()` which assembles the
 *    components in the same declaration order.
 *  - `mapWithBreaks`: synchronous map that releases the event loop every 16ms
 *    through a *fresh* `MessageChannel` (never `setTimeout` — Chrome throttles
 *    timers, which can stall the agent for a long time).
 *  - `releaseEventLoop` / `suppressUnhandledRejectionWarning`: the two small
 *    async helpers the loader is built from.
 *  - `transformSource`: map a source's value while preserving its sync/async
 *    and 1-stage/2-stage shape.
 *
 * There is intentionally NO generic timeout (matching the FingerprintJS OSS
 * build). Collectors are total and own their own internal bounds.
 */

export type MaybePromise<T> = T | Promise<T>;

/**
 * A collector: receives the shared source options and returns either the final
 * value or a second-stage getter. Both stages may be sync or async.
 */
export type Source<TOptions, TValue> = (
  options: TOptions
) => MaybePromise<TValue | (() => MaybePromise<TValue>)>;

/** Generic dictionary of unknown sources. */
export type UnknownSources<TOptions> = Record<string, Source<TOptions, unknown>>;

/** Extract the value type produced by a source. */
export type SourceValue<TSource extends Source<any, any>> = TSource extends Source<any, infer T> ? T : never;

/** The result of getting one entropy component. */
export type Component<T> = ({ value: T } | { error: unknown }) & { duration: number };

/** Generic dictionary of unknown components. */
export type UnknownComponents = Record<string, Component<unknown>>;

/** Map a registry of sources to the matching registry of components. */
export type SourcesToComponents<TSources extends UnknownSources<any>> = {
  [K in keyof TSources]: Component<SourceValue<TSources[K]>>;
};

function isPromise<T>(value: MaybePromise<T> | unknown): value is PromiseLike<T> {
  return !!value && typeof (value as PromiseLike<T>).then === 'function';
}

/** A non-function load result is final; a function is a second-stage getter. */
function isFinalResultLoaded<TValue>(loadResult: TValue | (() => MaybePromise<TValue>)): loadResult is TValue {
  return typeof loadResult !== 'function';
}

function excludes<T>(list: readonly T[], item: T): boolean {
  return !list.includes(item);
}

/**
 * Yields one turn of the browser event loop with a *fresh* MessageChannel.
 * `setTimeout` is avoided on purpose: Chrome throttles it in some cases, which
 * can make a long synchronous batch take a very long time to finish.
 */
export function releaseEventLoop(): Promise<void> {
  return new Promise((resolve) => {
    const channel = new MessageChannel();
    channel.port1.onmessage = () => {
      // A fresh channel per call is required; closing it after delivery also
      // avoids keeping Node handles alive when this runs under tsx.
      channel.port1.close();
      channel.port2.close();
      resolve();
    };
    channel.port2.postMessage(null);
  });
}

/**
 * Attaches a no-op rejection handler so a promise never emits an unhandled
 * rejection warning, while still forwarding errors to downstream chains.
 * Returns the input promise for convenience.
 */
export function suppressUnhandledRejectionWarning<T extends PromiseLike<unknown>>(promise: T): T {
  promise.then(undefined, () => undefined);
  return promise;
}

/**
 * Calls a maybe-async action without inserting extra microtasks when it is
 * synchronous (so source durations stay accurate), and normalizes throws and
 * rejections into `callback(false, error)`.
 */
function awaitIfAsync<TResult, TError = unknown>(
  action: () => MaybePromise<TResult>,
  callback: (...args: [success: true, result: TResult] | [success: false, error: TError]) => unknown
): void {
  try {
    const returnedValue = action();
    if (isPromise(returnedValue)) {
      returnedValue.then(
        (result) => callback(true, result),
        (error: TError) => callback(false, error)
      );
    } else {
      callback(true, returnedValue);
    }
  } catch (error) {
    callback(false, error as TError);
  }
}

/**
 * Maps synchronously but periodically awaits `releaseEventLoop()` so that
 * pending async work (network, rendering, other sources) can progress. Does
 * not await the values returned by `callback`; it only slices the loop.
 */
export async function mapWithBreaks<T, U>(
  items: readonly T[],
  callback: (item: T, index: number) => U,
  loopReleaseInterval = 16
): Promise<U[]> {
  const results = Array<U>(items.length);
  let lastLoopReleaseTime = Date.now();

  for (let i = 0; i < items.length; ++i) {
    results[i] = callback(items[i], i);

    const now = Date.now();
    if (now >= lastLoopReleaseTime + loopReleaseInterval) {
      lastLoopReleaseTime = now;
      await releaseEventLoop();
    }
  }

  return results;
}

/**
 * Starts one source's load phase immediately and returns a function that gets
 * the component. The getter is returned synchronously (so `loadSources` never
 * waits for one source before starting the others). A source that loads a
 * final value has that value cached in the finalizer; a source that returns a
 * getter re-runs that getter on every `getComponent()` call. Any throw or
 * rejection inside the source becomes `{ error, duration }`.
 */
export function loadSource<TOptions, TValue>(
  source: Source<TOptions, TValue>,
  sourceOptions: TOptions
): () => Promise<Component<TValue>> {
  const sourceLoadPromise = suppressUnhandledRejectionWarning(
    new Promise<() => MaybePromise<Component<TValue>>>((resolveLoad) => {
      const loadStartTime = Date.now();

      awaitIfAsync(source.bind(null, sourceOptions), (...loadArgs) => {
        const loadDuration = Date.now() - loadStartTime;

        // Source loading failed.
        if (!loadArgs[0]) {
          return resolveLoad(() => ({ error: loadArgs[1], duration: loadDuration }));
        }

        const loadResult = loadArgs[1];

        // Source loaded with the final value.
        if (isFinalResultLoaded(loadResult)) {
          return resolveLoad(() => ({ value: loadResult, duration: loadDuration }));
        }

        // Source loaded with a second-stage getter.
        resolveLoad(
          () =>
            new Promise<Component<TValue>>((resolveGet) => {
              const getStartTime = Date.now();

              awaitIfAsync(loadResult, (...getArgs) => {
                const duration = loadDuration + Date.now() - getStartTime;

                // Source getting failed.
                if (!getArgs[0]) {
                  return resolveGet({ error: getArgs[1], duration });
                }

                // Source getting succeeded.
                resolveGet({ value: getArgs[1], duration });
              });
            })
        );
      });
    })
  );

  return function getComponent() {
    return sourceLoadPromise.then((finalizeSource) => finalizeSource());
  };
}

/**
 * Loads a registry of sources and returns `getComponents()`. Loading and
 * collection both run through `mapWithBreaks`, so long runs of synchronous
 * sources yield the event loop and already-started async sources can finish.
 * Component keys are assembled in exactly the source declaration order.
 */
export function loadSources<
  TSourceOptions,
  TSources extends UnknownSources<TSourceOptions>,
  TExclude extends string
>(
  sources: TSources,
  sourceOptions: TSourceOptions,
  excludeSources: readonly TExclude[],
  loopReleaseInterval?: number
): () => Promise<Omit<SourcesToComponents<TSources>, TExclude>> {
  const includedSources = Object.keys(sources).filter((sourceKey) =>
    excludes(excludeSources as readonly string[], sourceKey)
  ) as Exclude<keyof TSources, TExclude>[];

  // load() starts here; the getters are only awaited when getComponents() runs.
  const sourceGettersPromise = suppressUnhandledRejectionWarning(
    mapWithBreaks(includedSources, (sourceKey) => loadSource(sources[sourceKey], sourceOptions), loopReleaseInterval)
  );

  return async function getComponents() {
    const sourceGetters = await sourceGettersPromise;

    const componentPromises = await mapWithBreaks(
      sourceGetters,
      (sourceGetter) => suppressUnhandledRejectionWarning(sourceGetter()),
      loopReleaseInterval
    );

    const componentArray = await Promise.all(componentPromises);
    const components = {} as Omit<SourcesToComponents<TSources>, TExclude>;
    for (let index = 0; index < includedSources.length; ++index) {
      components[includedSources[index]] = componentArray[index] as Component<any>;
    }
    return components;
  };
}

/**
 * Wraps a source so its produced value is passed through `transformValue`.
 * Sync/async and 1-stage/2-stage properties of the source are preserved.
 */
export function transformSource<TOptions, TValueBefore, TValueAfter>(
  source: Source<TOptions, TValueBefore>,
  transformValue: (value: TValueBefore) => TValueAfter
): Source<TOptions, TValueAfter> {
  const transformLoadResult = (
    loadResult: TValueBefore | (() => MaybePromise<TValueBefore>)
  ): TValueAfter | (() => MaybePromise<TValueAfter>) => {
    if (isFinalResultLoaded(loadResult)) {
      return transformValue(loadResult);
    }

    return () => {
      const getResult = loadResult();

      if (isPromise(getResult)) {
        return getResult.then(transformValue);
      }

      return transformValue(getResult);
    };
  };

  return (options) => {
    const loadResult = source(options);

    if (isPromise(loadResult)) {
      return loadResult.then(transformLoadResult);
    }

    return transformLoadResult(loadResult);
  };
}
