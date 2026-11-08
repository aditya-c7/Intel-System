import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Play, Square, ExternalLink, RefreshCw } from 'lucide-react';

export type RawPressureState = 'nominal' | 'fair' | 'serious' | 'critical';
export type DisplayPressureLevel = 'Normal' | 'Moderate' | 'High' | 'Heavy';

export type CpuMonitorStatus =
  | 'Initializing'
  | 'Monitoring'
  | 'Live'
  | 'Paused'
  | 'Unsupported'
  | 'Blocked'
  | 'Error';

interface PressureObservationSample {
  id: number;
  timestampMs: number;
  rawRecordTime: number;
  rawState: RawPressureState;
  displayLevel: DisplayPressureLevel;
}

interface NativePressureRecord {
  source: string;
  state: RawPressureState;
  time: number;
  toJSON?: () => Record<string, unknown>;
}

interface NativePressureObserver {
  observe: (source: string, options?: { sampleInterval?: number }) => Promise<void>;
  unobserve?: (source: string) => void;
  disconnect: () => void;
  takeRecords?: () => NativePressureRecord[];
}

interface NativePressureObserverConstructor {
  new (callback: (records: NativePressureRecord[]) => void): NativePressureObserver;
  knownSources?: readonly string[];
}

const FIVE_MINUTES_MS = 5 * 60 * 1000; // 300,000 ms rolling five-minute timeline
const STALE_THRESHOLD_MS = 15 * 1000; // 15s threshold to indicate held/unchanged state

const PRESSURE_MAP: Record<RawPressureState, DisplayPressureLevel> = {
  nominal: 'Normal',
  fair: 'Moderate',
  serious: 'High',
  critical: 'Heavy',
};

const DISPLAY_LEVELS: DisplayPressureLevel[] = ['Normal', 'Moderate', 'High', 'Heavy'];

function SystemLoadBadge({ level }: { level: DisplayPressureLevel }) {
  // Smooth needle rotation angle:
  // Normal -> towards left (-48deg, green)
  // Moderate -> slightly left (-16deg, amber)
  // High -> slightly right (+18deg, orange)
  // Heavy -> towards right (+48deg, red)
  const needleAngleDeg =
    level === 'Heavy'
      ? 48
      : level === 'High'
      ? 18
      : level === 'Moderate'
      ? -16
      : -48;

  const badgeColors =
    level === 'Heavy'
      ? 'bg-[#FAD2CF] text-[#C5221F] dark:bg-rose-950/70 dark:text-rose-400'
      : level === 'High'
      ? 'bg-[#FCE8E6] text-[#D93025] dark:bg-orange-950/70 dark:text-orange-400'
      : level === 'Moderate'
      ? 'bg-[#FEF7E0] text-[#B06000] dark:bg-amber-950/70 dark:text-amber-400'
      : 'bg-[#E6F4EA] text-[#137333] dark:bg-emerald-950/70 dark:text-emerald-400';

  return (
    <div className="flex items-center gap-3 min-w-0">
      <div
        className={`w-9 h-9 rounded-full flex items-center justify-center shrink-0 transition-colors duration-500 ${badgeColors}`}
        aria-hidden="true"
      >
        <svg
          viewBox="0 0 24 24"
          className="w-6 h-6 overflow-visible"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Speedometer arch with flat bottom baseline */}
          <path
            d="M 3.6 17.4 A 9.1 9.1 0 1 1 20.4 17.4 Z"
            stroke="currentColor"
            strokeWidth="2.05"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          {/* Smoothly shifting gauge pointer needle */}
          <g
            style={{
              transform: `rotate(${needleAngleDeg}deg)`,
              transformOrigin: '12px 14.4px',
              transition: 'transform 550ms cubic-bezier(0.22, 1, 0.36, 1)',
            }}
          >
            <circle cx="12" cy="14.4" r="1.7" fill="currentColor" />
            <path
              d="M 10.65 14.4 L 12 6.7 L 13.35 14.4 Z"
              fill="currentColor"
              stroke="currentColor"
              strokeWidth="0.6"
              strokeLinejoin="round"
            />
          </g>
        </svg>
      </div>

      <div className="min-w-0">
        <span className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 block truncate">
          System load
        </span>
        <span className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5 block truncate">
          {level}
        </span>
      </div>
    </div>
  );
}

function formatClockTimestamp(ms: number): string {
  const d = new Date(ms);
  return d.toLocaleTimeString([], {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/**
 * Converts a W3C PressureRecord.time (DOMHighResTimeStamp relative to performance.timeOrigin)
 * into a Unix epoch millisecond timestamp for display and timeline placement.
 */
function convertRecordTimeToEpochMs(recordTime: unknown): number {
  const nowEpoch = Date.now();
  if (typeof recordTime !== 'number' || !Number.isFinite(recordTime) || recordTime <= 0) {
    return nowEpoch;
  }

  if (recordTime > 1_000_000_000_000) {
    return Math.round(recordTime);
  }

  const timeOrigin =
    typeof performance !== 'undefined' &&
    typeof performance.timeOrigin === 'number' &&
    Number.isFinite(performance.timeOrigin)
      ? performance.timeOrigin
      : nowEpoch - (typeof performance !== 'undefined' ? performance.now() : 0);

  const converted = Math.round(timeOrigin + recordTime);
  if (Math.abs(nowEpoch - converted) <= 10 * 60 * 1000) {
    return converted;
  }
  return nowEpoch;
}

function detectInsideIframe(): boolean {
  try {
    return typeof window !== 'undefined' && window.self !== window.top;
  } catch {
    return true;
  }
}

export function CpuActivityPanel() {
  const [userEnabled, setUserEnabled] = useState<boolean>(true);
  const [status, setStatus] = useState<CpuMonitorStatus>('Initializing');
  const [errorDetail, setErrorDetail] = useState<string | null>(null);
  const [samples, setSamples] = useState<PressureObservationSample[]>([]);
  const [windowEndMs, setWindowEndMs] = useState<number>(() => Date.now());
  const [pinnedSampleId, setPinnedSampleId] = useState<number | null>(null);
  const [httpPolicyHeader, setHttpPolicyHeader] = useState<string | null>(null);
  const [insideIframe] = useState<boolean>(() => detectInsideIframe());
  // Responsive SVG width measured from actual container so mobile graphs are never squeezed
  const [chartWidth, setChartWidth] = useState<number>(560);

  // Stable refs to prevent duplicate observers or disconnects across React re-renders
  const observerRef = useRef<NativePressureObserver | null>(null);
  const isObservingRef = useRef<boolean>(false);
  const hasReceivedObservationRef = useRef<boolean>(false);
  const terminalStateRef = useRef<'Unsupported' | 'Blocked' | null>(null);
  const isPageVisibleRef = useRef<boolean>(
    typeof document !== 'undefined' ? document.visibilityState !== 'hidden' : true
  );
  const userEnabledRef = useRef<boolean>(true);
  const sampleCounterRef = useRef<number>(0);
  const chartWrapperRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  userEnabledRef.current = userEnabled;

  // Measure actual chart container width via ResizeObserver so mobile renders 1:1 without shrinking
  useEffect(() => {
    const el = chartWrapperRef.current;
    if (!el) return;

    const updateSize = () => {
      const w = el.clientWidth;
      if (w > 0) {
        setChartWidth(Math.max(280, Math.round(w - 16)));
      }
    };

    updateSize();

    if (typeof ResizeObserver !== 'undefined') {
      const ro = new ResizeObserver(updateSize);
      ro.observe(el);
      return () => ro.disconnect();
    } else {
      window.addEventListener('resize', updateSize);
      return () => window.removeEventListener('resize', updateSize);
    }
  }, []);

  // Dismiss pinned tooltip when clicking outside the chart wrapper
  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent | TouchEvent) => {
      if (
        chartWrapperRef.current &&
        e.target instanceof Node &&
        !chartWrapperRef.current.contains(e.target)
      ) {
        setPinnedSampleId(null);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    document.addEventListener('touchstart', handleOutsideClick, { passive: true });
    return () => {
      document.removeEventListener('mousedown', handleOutsideClick);
      document.removeEventListener('touchstart', handleOutsideClick);
    };
  }, []);

  // Inspect HTTP Permissions-Policy header from same-origin server for diagnostic logging
  useEffect(() => {
    let active = true;
    fetch('/api/network/ping', { method: 'GET', cache: 'no-store' })
      .then((res) => {
        if (!active) return;
        const headerVal = res.headers.get('permissions-policy');
        setHttpPolicyHeader(headerVal);
        console.log('[CPU Pressure Diagnostics] HTTP Permissions-Policy header:', headerVal || '(none)');
      })
      .catch(() => {
        // Ignore network check error
      });
    return () => {
      active = false;
    };
  }, []);

  // Explicitly disconnect and clean up active observer
  const disconnectObserver = useCallback((reason: string) => {
    if (observerRef.current) {
      try {
        console.log(`[CPU Pressure] Disconnecting observer (${reason})`);
        observerRef.current.disconnect();
      } catch {
        // Ignore disconnect error
      }
      observerRef.current = null;
    }
    isObservingRef.current = false;
  }, []);

  // Start native W3C PressureObserver (guarded so duplicate observers are never created)
  const startCpuObservation = useCallback(
    async (forceRetry = false) => {
      if (forceRetry) {
        terminalStateRef.current = null;
      }

      if (terminalStateRef.current) {
        setStatus(terminalStateRef.current);
        return;
      }

      if (isObservingRef.current && observerRef.current) {
        setStatus(hasReceivedObservationRef.current ? 'Live' : 'Monitoring');
        return;
      }

      const g = globalThis as unknown as {
        PressureObserver?: NativePressureObserverConstructor;
      };

      const isHttps =
        typeof window !== 'undefined'
          ? window.location.protocol === 'https:' || window.isSecureContext
          : false;

      const hasPressureObserverFn = typeof g.PressureObserver === 'function';
      const knownSources =
        hasPressureObserverFn && Array.isArray(g.PressureObserver?.knownSources)
          ? g.PressureObserver.knownSources
          : [];
      const supportsCpuSource = knownSources.includes('cpu');

      console.log('[CPU Pressure] Initializing observer:', {
        HTTPS: isHttps,
        InsideIframe: insideIframe,
        PressureObserver: typeof g.PressureObserver,
        knownSources,
        supportsCpuSource,
      });

      if (!hasPressureObserverFn || !g.PressureObserver) {
        console.log('[CPU Pressure] globalThis.PressureObserver is not a function');
        terminalStateRef.current = 'Unsupported';
        setStatus('Unsupported');
        setErrorDetail('PressureObserver API is not available in this browser.');
        return;
      }

      if (!supportsCpuSource) {
        console.log('[CPU Pressure] PressureObserver.knownSources does not include "cpu":', knownSources);
        terminalStateRef.current = 'Unsupported';
        setStatus('Unsupported');
        setErrorDetail('CPU source is not listed in PressureObserver.knownSources.');
        return;
      }

      setStatus('Initializing');
      setErrorDetail(null);

      try {
        const observer = new g.PressureObserver((records: NativePressureRecord[]) => {
          console.log('[CPU Pressure] Callback invoked. Received records:', records?.length ?? 0);

          if (!Array.isArray(records) || records.length === 0) return;

          const validCpuRecords = records.filter(
            (rec) => rec && rec.source === 'cpu' && rec.state in PRESSURE_MAP
          );

          if (validCpuRecords.length === 0) {
            console.log('[CPU Pressure] No valid "cpu" records in callback batch');
            return;
          }

          const newSamples: PressureObservationSample[] = validCpuRecords.map((rec) => {
            const epochMs = convertRecordTimeToEpochMs(rec.time);
            const displayLevel = PRESSURE_MAP[rec.state];
            console.log(
              `[CPU Pressure] Record: source=${rec.source}, state=${rec.state} (${displayLevel}), rawTime=${rec.time}, timestamp=${new Date(epochMs).toISOString()}`
            );
            return {
              id: ++sampleCounterRef.current,
              timestampMs: epochMs,
              rawRecordTime: rec.time,
              rawState: rec.state,
              displayLevel,
            };
          });

          hasReceivedObservationRef.current = true;
          const latestEpochMs = Math.max(
            Date.now(),
            newSamples[newSamples.length - 1].timestampMs
          );

          setWindowEndMs(latestEpochMs);
          setSamples((prev) => {
            const cutoff = latestEpochMs - FIVE_MINUTES_MS - 15000;
            return [...prev.filter((s) => s.timestampMs >= cutoff), ...newSamples];
          });

          if (isPageVisibleRef.current && userEnabledRef.current) {
            setStatus('Live');
          }
        });

        observerRef.current = observer;
        isObservingRef.current = true;

        await observer.observe('cpu', { sampleInterval: 1000 });
        console.log('CPU monitoring started');

        if (!isObservingRef.current || observerRef.current !== observer) {
          return;
        }

        if (!isPageVisibleRef.current) {
          setStatus('Paused');
        } else if (hasReceivedObservationRef.current) {
          setStatus('Live');
        } else {
          setStatus('Monitoring');
        }
      } catch (err: unknown) {
        const errName = err instanceof Error ? err.name : '';
        const errMsg = err instanceof Error ? err.message : String(err);

        console.log(`[CPU Pressure] observe("cpu") rejected (${errName}): ${errMsg}`);
        disconnectObserver('observe rejected');

        if (
          errName === 'NotAllowedError' ||
          errName === 'SecurityError' ||
          /permission|policy|not allowed|disallowed/i.test(errMsg)
        ) {
          terminalStateRef.current = 'Blocked';
          setStatus('Blocked');
          setErrorDetail(
            insideIframe
              ? 'Blocked by parent iframe Permissions-Policy. Open the deployed URL in a top-level browser tab to enable CPU pressure monitoring.'
              : 'Permissions Policy rejected access to compute-pressure.'
          );
        } else if (errName === 'NotSupportedError' || /not supported/i.test(errMsg)) {
          terminalStateRef.current = 'Unsupported';
          setStatus('Unsupported');
          setErrorDetail(errMsg || 'Hardware or platform CPU pressure telemetry is not supported.');
        } else {
          setStatus('Error');
          setErrorDetail(errMsg || 'Unexpected error initializing CPU pressure observer.');
        }
      }
    },
    [disconnectObserver, insideIframe]
  );

  // Manage lifecycle when user starts/stops monitoring
  useEffect(() => {
    if (!userEnabled) {
      disconnectObserver('user stopped monitoring');
      setStatus('Paused');
      return;
    }

    if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
      isPageVisibleRef.current = false;
      setStatus('Paused');
      return;
    }

    isPageVisibleRef.current = true;
    startCpuObservation(false);
  }, [userEnabled, startCpuObservation, disconnectObserver]);

  // Handle browser tab visibility changes without creating duplicate observers
  useEffect(() => {
    const handleVisibilityChange = () => {
      const isVisible = document.visibilityState !== 'hidden';
      isPageVisibleRef.current = isVisible;

      if (terminalStateRef.current) {
        return;
      }

      if (!isVisible) {
        console.log('[CPU Pressure] Tab hidden -> Paused');
        setStatus((prev) =>
          prev === 'Unsupported' || prev === 'Blocked' || prev === 'Error' ? prev : 'Paused'
        );
      } else if (userEnabledRef.current) {
        console.log('[CPU Pressure] Tab visible -> Resuming');
        if (isObservingRef.current && observerRef.current) {
          setWindowEndMs(Date.now());
          setStatus(hasReceivedObservationRef.current ? 'Live' : 'Monitoring');
        } else {
          startCpuObservation(false);
        }
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [startCpuObservation]);

  // Cleanup observer on component unmount
  useEffect(() => {
    return () => {
      disconnectObserver('component unmount');
    };
  }, [disconnectObserver]);

  // Advance the rolling 5-minute timeline clock smoothly while active (does NOT create fake samples)
  useEffect(() => {
    if (!userEnabled || (status !== 'Monitoring' && status !== 'Live')) return;

    const clockTimer = setInterval(() => {
      if (typeof document === 'undefined' || document.visibilityState !== 'hidden') {
        setWindowEndMs(Date.now());
      }
    }, 1000);

    return () => clearInterval(clockTimer);
  }, [userEnabled, status]);

  // Rolling 5-minute window bounds
  const windowStartMs = windowEndMs - FIVE_MINUTES_MS;
  const visibleSamples = samples.filter(
    (s) => s.timestampMs >= windowStartMs - 60000 && s.timestampMs <= windowEndMs + 2000
  );

  const latestSample = samples[samples.length - 1] ?? null;
  const timeSinceLastObservationMs = latestSample
    ? Math.max(0, windowEndMs - latestSample.timestampMs)
    : null;
  const isStale =
    status === 'Live' &&
    timeSinceLastObservationMs !== null &&
    timeSinceLastObservationMs > STALE_THRESHOLD_MS;

  // Responsive 1:1 SVG Chart Geometry (never shrinks or squeezes on mobile screens)
  const isCompactMobile = chartWidth < 420;
  const svgWidth = chartWidth;
  const svgHeight = 236;
  const padLeft = isCompactMobile ? 58 : 66;
  const padRight = 12;
  const padTop = 18;
  const padBottom = 30;
  const plotWidth = Math.max(170, svgWidth - padLeft - padRight);
  const plotHeight = svgHeight - padTop - padBottom;

  const getXForTimestamp = (tsMs: number): number => {
    const ratio = (tsMs - windowStartMs) / FIVE_MINUTES_MS;
    return padLeft + ratio * plotWidth;
  };

  const getYForLevel = (level: DisplayPressureLevel): number => {
    const index = DISPLAY_LEVELS.indexOf(level); // 0 = Light (bottom), 3 = Heavy (top)
    const normalizedIdx = Math.max(0, Math.min(3, index));
    return padTop + plotHeight - (normalizedIdx / 3) * plotHeight;
  };

  // Build SVG step-line path strictly from actual recorded observations,
  // retaining the previous state horizontally until the next actual observation
  let stepPath = '';
  if (visibleSamples.length > 0) {
    const parts: string[] = [];
    visibleSamples.forEach((s, idx) => {
      const x = getXForTimestamp(s.timestampMs).toFixed(2);
      const y = getYForLevel(s.displayLevel).toFixed(2);
      if (idx === 0) {
        parts.push(`M ${x} ${y}`);
      } else {
        const prevY = getYForLevel(visibleSamples[idx - 1].displayLevel).toFixed(2);
        parts.push(`L ${x} ${prevY} L ${x} ${y}`);
      }
    });

    // Retain the latest actual state horizontally up to the current right edge while live
    const lastSample = visibleSamples[visibleSamples.length - 1];
    if (lastSample && status === 'Live' && windowEndMs > lastSample.timestampMs) {
      const rightEdgeX = getXForTimestamp(windowEndMs).toFixed(2);
      const lastY = getYForLevel(lastSample.displayLevel).toFixed(2);
      parts.push(`L ${rightEdgeX} ${lastY}`);
    }

    stepPath = parts.join(' ');
  }

  // Generate moving X-axis timestamp ticks (90s spacing on compact mobile so labels never crowd, 60s on tablet/desktop)
  const tickIntervalMs = (isCompactMobile ? 90 : 60) * 1000;
  const firstTickMs = Math.ceil(windowStartMs / tickIntervalMs) * tickIntervalMs;
  const xTicks: number[] = [];
  for (let t = firstTickMs; t <= windowEndMs; t += tickIntervalMs) {
    xTicks.push(t);
  }

  // Find nearest actual recorded observation for click / tap interaction
  const findNearestSample = (clientX: number): PressureObservationSample | null => {
    if (!svgRef.current || visibleSamples.length === 0) return null;
    const rect = svgRef.current.getBoundingClientRect();
    if (rect.width <= 0) return null;

    const svgX = ((clientX - rect.left) / rect.width) * svgWidth;
    if (svgX < padLeft - 10 || svgX > padLeft + plotWidth + 10) return null;

    let closest: PressureObservationSample | null = null;
    let minDistancePx = Infinity;

    for (const s of visibleSamples) {
      const sampleX = getXForTimestamp(s.timestampMs);
      if (sampleX < padLeft || sampleX > padLeft + plotWidth) continue;
      const dist = Math.abs(sampleX - svgX);
      if (dist < minDistancePx) {
        minDistancePx = dist;
        closest = s;
      }
    }

    return minDistancePx <= 48 ? closest : null;
  };

  const handlePointerClick = (e: React.MouseEvent<SVGSVGElement>) => {
    const nearest = findNearestSample(e.clientX);
    if (nearest) {
      setPinnedSampleId((prev) => (prev === nearest.id ? null : nearest.id));
    } else {
      setPinnedSampleId(null);
    }
  };

  const handleTouchSelect = (e: React.TouchEvent<SVGSVGElement>) => {
    if (e.touches.length > 0) {
      const nearest = findNearestSample(e.touches[0].clientX);
      if (nearest) {
        setPinnedSampleId(nearest.id);
      } else {
        setPinnedSampleId(null);
      }
    }
  };

  // Click-only tooltip sample (does not pop up on hover)
  const activeTooltipSample =
    pinnedSampleId !== null
      ? visibleSamples.find(
          (s) => s.id === pinnedSampleId && getXForTimestamp(s.timestampMs) >= padLeft
        ) ?? null
      : null;

  const activeTooltipX = activeTooltipSample
    ? getXForTimestamp(activeTooltipSample.timestampMs)
    : null;
  const activeTooltipY = activeTooltipSample
    ? getYForLevel(activeTooltipSample.displayLevel)
    : padTop + plotHeight / 2;

  const tooltipLeftPercent =
    activeTooltipX !== null
      ? Math.max(22, Math.min(78, (activeTooltipX / svgWidth) * 100))
      : 50;

  // Format distinct status badge text
  const renderStatusText = () => {
    switch (status) {
      case 'Initializing':
        return 'Initializing';
      case 'Monitoring':
        return 'Monitoring';
      case 'Live':
        return 'Live';
      case 'Paused':
        return 'Paused';
      case 'Unsupported':
        return 'Unsupported';
      case 'Blocked':
        return 'Blocked';
      case 'Error':
        return 'Error';
    }
  };

  // Format main current load description concisely
  const renderCurrentLoadValue = () => {
    if (status === 'Initializing') {
      return 'Initializing...';
    }
    if (status === 'Monitoring' && !latestSample) {
      return 'Awaiting sample';
    }
    if ((status === 'Live' || status === 'Paused' || status === 'Monitoring') && latestSample) {
      return `${latestSample.displayLevel} (${latestSample.rawState})`;
    }
    if (status === 'Paused') {
      return 'Paused';
    }
    if (status === 'Blocked') {
      return insideIframe ? 'Blocked in iframe' : 'Policy blocked';
    }
    if (status === 'Unsupported') {
      return 'Unsupported';
    }
    return 'Error';
  };

  const currentBadgeLevel: DisplayPressureLevel = latestSample
    ? latestSample.displayLevel
    : 'Normal';

  return (
    <div className="bg-white dark:bg-[#0A0D14] border border-zinc-200 dark:border-zinc-800/90 rounded-md flex flex-col justify-between overflow-hidden">
      <div>
        {/* Header */}
        <div className="px-4 sm:px-5 py-3 border-b border-zinc-200/70 dark:border-zinc-800/70 flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-xs sm:text-sm font-medium text-zinc-900 dark:text-zinc-100">
            CPU Activity
          </h2>

          <div className="flex items-center gap-3">
            <span className="inline-flex items-center gap-1.5 text-xs font-mono tabular-nums text-zinc-900 dark:text-zinc-100">
              <span
                className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                  status === 'Live' || status === 'Monitoring'
                    ? 'bg-emerald-500'
                    : status === 'Paused' || status === 'Initializing'
                    ? 'bg-amber-500'
                    : 'bg-rose-500'
                }`}
              />
              <span>{renderStatusText()}</span>
            </span>

            {status === 'Blocked' || status === 'Error' ? (
              <button
                type="button"
                onClick={() => startCpuObservation(true)}
                className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-zinc-700 dark:text-zinc-200 bg-white dark:bg-[#0A0D14] hover:bg-zinc-50 dark:hover:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded whitespace-nowrap shrink-0 cursor-pointer transition-colors"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Retry</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setUserEnabled((prev) => !prev)}
                disabled={status === 'Unsupported'}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-zinc-700 dark:text-zinc-200 bg-white dark:bg-[#0A0D14] hover:bg-zinc-50 dark:hover:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer transition-colors"
              >
                {userEnabled ? (
                  <>
                    <Square className="w-3 h-3 fill-current" />
                    <span>Stop</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3 h-3 fill-current" />
                    <span>Start</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>

        {/* Hairline 4-Column Summary Metrics Row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 border-b border-zinc-200/70 dark:border-zinc-800/70 divide-y sm:divide-y-0 divide-x divide-zinc-200/70 dark:divide-zinc-800/70 text-xs">
          <div className="px-4 py-3 min-w-0">
            <SystemLoadBadge level={currentBadgeLevel} />
          </div>

          <div className="px-4 py-3 min-w-0">
            <span className="text-xs text-zinc-500 dark:text-zinc-400 font-normal block truncate">
              CPU State
            </span>
            <span
              className="text-xs sm:text-sm font-mono tabular-nums font-medium text-zinc-900 dark:text-zinc-100 mt-0.5 block truncate"
              title={errorDetail || renderCurrentLoadValue()}
            >
              {renderCurrentLoadValue()}
            </span>
          </div>

          <div className="px-4 py-3 min-w-0">
            <span className="text-xs text-zinc-500 dark:text-zinc-400 font-normal block truncate">
              Last Sample
            </span>
            <span className="text-xs sm:text-sm font-mono tabular-nums font-medium text-zinc-900 dark:text-zinc-100 mt-0.5 block truncate">
              {latestSample ? formatClockTimestamp(latestSample.timestampMs) : 'Waiting...'}
            </span>
          </div>

          <div className="px-4 py-3 min-w-0">
            <span className="text-xs text-zinc-500 dark:text-zinc-400 font-normal block truncate">
              Samples
            </span>
            <span className="text-xs sm:text-sm font-mono tabular-nums font-medium text-zinc-900 dark:text-zinc-100 mt-0.5 block truncate">
              {samples.length}
            </span>
          </div>
        </div>

        {/* Notice if blocked specifically by embedded preview iframe */}
        {status === 'Blocked' && insideIframe && (
          <div className="px-4 sm:px-5 py-2.5 border-b border-zinc-200/70 dark:border-zinc-800/70 text-xs text-zinc-600 dark:text-zinc-400 flex items-center justify-between gap-3">
            <span className="truncate">
              Open in a direct browser tab to enable W3C Compute Pressure telemetry.
            </span>
            <a
              href={typeof window !== 'undefined' ? window.location.href : '#'}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-zinc-800 dark:text-zinc-200 border border-zinc-200 dark:border-zinc-800 rounded hover:bg-zinc-50 dark:hover:bg-zinc-900 shrink-0"
            >
              <span>Open Tab</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        )}

        {/* Step-Line Time-Series Graph */}
        <div className="p-4 sm:p-5" ref={chartWrapperRef}>
          <div className="flex items-center justify-between text-xs text-zinc-500 dark:text-zinc-400 mb-2">
            <span>CPU Pressure (Normal to Heavy) · Click line to inspect</span>
            <span className="font-mono tabular-nums">
              {status === 'Live'
                ? 'Live 5m'
                : status === 'Monitoring'
                ? 'Awaiting sample'
                : status}
            </span>
          </div>

          <div className="relative w-full bg-white dark:bg-[#0A0D14] border border-zinc-200/70 dark:border-zinc-800/70 rounded p-2 select-none">
            <svg
              ref={svgRef}
              width={svgWidth}
              height={svgHeight}
              viewBox={`0 0 ${svgWidth} ${svgHeight}`}
              className="w-full h-[236px] block overflow-hidden cursor-pointer touch-pan-y"
              role="img"
              aria-label="System CPU Pressure Step-Line Time-Series Graph"
              onClick={handlePointerClick}
              onTouchStart={handleTouchSelect}
            >
              <defs>
                <clipPath id="cpu-pressure-plot-clip">
                  <rect x={padLeft} y={padTop - 2} width={plotWidth} height={plotHeight + 4} />
                </clipPath>
              </defs>

              {DISPLAY_LEVELS.map((level) => {
                const y = getYForLevel(level);
                return (
                  <g key={level}>
                    <line
                      x1={padLeft}
                      y1={y}
                      x2={svgWidth - padRight}
                      y2={y}
                      stroke="#E2E8F0"
                      strokeWidth="1"
                    />
                    <text
                      x={padLeft - 6}
                      y={y + 3.5}
                      textAnchor="end"
                      className="fill-zinc-400 font-mono text-[10px]"
                    >
                      {level}
                    </text>
                  </g>
                );
              })}

              <line
                x1={padLeft}
                y1={padTop}
                x2={padLeft}
                y2={padTop + plotHeight}
                stroke="#CBD5E1"
                strokeWidth="1"
              />
              <line
                x1={padLeft}
                y1={padTop + plotHeight}
                x2={svgWidth - padRight}
                y2={padTop + plotHeight}
                stroke="#CBD5E1"
                strokeWidth="1"
              />

              {xTicks.map((tickMs) => {
                const x = getXForTimestamp(tickMs);
                if (x < padLeft + 26 || x > svgWidth - padRight - 26) return null;
                return (
                  <g key={tickMs}>
                    <line
                      x1={x}
                      y1={padTop}
                      x2={x}
                      y2={padTop + plotHeight}
                      stroke="#F8FAFC"
                      strokeWidth="1"
                    />
                    <line
                      x1={x}
                      y1={padTop + plotHeight}
                      x2={x}
                      y2={padTop + plotHeight + 4}
                      stroke="#CBD5E1"
                      strokeWidth="1"
                    />
                    <text
                      x={x}
                      y={svgHeight - 7}
                      textAnchor="middle"
                      className="fill-zinc-400 font-mono text-[10px]"
                    >
                      {formatClockTimestamp(tickMs)}
                    </text>
                  </g>
                );
              })}

              <g clipPath="url(#cpu-pressure-plot-clip)">
                {stepPath && (
                  <path
                    d={stepPath}
                    fill="none"
                    stroke="#2563EB"
                    strokeWidth="1.75"
                    strokeLinejoin="miter"
                    strokeLinecap="butt"
                  />
                )}

                {activeTooltipSample && activeTooltipX !== null && (
                  <line
                    x1={activeTooltipX}
                    y1={padTop}
                    x2={activeTooltipX}
                    y2={padTop + plotHeight}
                    stroke="#64748B"
                    strokeWidth="1"
                    strokeDasharray="3 3"
                  />
                )}
              </g>

              {visibleSamples.length === 0 && (
                <text
                  x={padLeft + plotWidth / 2}
                  y={padTop + plotHeight / 2}
                  textAnchor="middle"
                  className="fill-zinc-400 font-sans text-[11px] font-normal"
                >
                  {status === 'Monitoring'
                    ? 'Waiting for first CPU pressure observation'
                    : status === 'Initializing'
                    ? 'Initializing PressureObserver...'
                    : status === 'Paused'
                    ? 'Paused (Browser tab inactive or stopped)'
                    : status === 'Blocked'
                    ? insideIframe
                      ? 'Blocked in iframe (open URL in direct tab)'
                      : 'Blocked: Permissions Policy rejected access'
                    : status === 'Unsupported'
                    ? 'Unsupported: CPU pressure source unavailable'
                    : errorDetail || 'Error initializing CPU telemetry'}
                </text>
              )}
            </svg>

            {activeTooltipSample && activeTooltipX !== null && (
              <div
                style={{
                  left: `${tooltipLeftPercent}%`,
                  top: `${Math.max(8, Math.min(115, (activeTooltipY / svgHeight) * 140))}px`,
                  transform: 'translateX(-50%)',
                }}
                className="absolute z-20 bg-white dark:bg-[#0A0D14] border border-zinc-200 dark:border-zinc-800 rounded px-3 py-2 text-xs pointer-events-none min-w-[175px]"
              >
                <div className="font-mono tabular-nums font-medium text-zinc-900 dark:text-zinc-100 pb-1 border-b border-zinc-200/70 dark:border-zinc-800/70">
                  {formatClockTimestamp(activeTooltipSample.timestampMs)}
                </div>
                <div className="flex items-center justify-between gap-4 mt-1.5">
                  <span className="text-zinc-500 dark:text-zinc-400">CPU state</span>
                  <span className="font-mono tabular-nums font-semibold text-zinc-900 dark:text-zinc-100">
                    {activeTooltipSample.displayLevel} ({activeTooltipSample.rawState})
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Concise Status Footer */}
      <div
        className="px-4 sm:px-5 py-3 border-t border-zinc-200/70 dark:border-zinc-800/70 flex flex-wrap items-center justify-between gap-2 text-xs text-zinc-500 dark:text-zinc-400"
        title={httpPolicyHeader ? `Permissions-Policy: ${httpPolicyHeader}` : undefined}
      >
        <span>Scale: Normal · Moderate · High · Heavy</span>
        <span className="font-mono tabular-nums shrink-0">W3C Compute Pressure (1s)</span>
      </div>
    </div>
  );
}
