/**
 * Intel System — client identity storage waterfall (browser only).
 *
 * Self-contained: no imports, no Node APIs. Every storage access is wrapped in
 * try/catch so private-mode restrictions degrade silently (nulls, empty
 * sources, storage_healed: false).
 *
 * Waterfall: localStorage → IndexedDB (800ms timeout race) → cookie mirror.
 * As soon as one slot yields a valid identity, ALL writable slots are healed
 * (best-effort, idempotent) and `storage_healed` is true.
 */

/* -------------------------------------------------------------------------- */
/* Constants                                                                   */
/* -------------------------------------------------------------------------- */

/** HttpOnly, server-set first-party cookie. The client only sends it back. */
export const COOKIE_NAME = '_intel_vid';

/**
 * Non-HttpOnly client mirror the server may set so the waterfall can recover
 * the visitor id when localStorage and IndexedDB are both unavailable.
 */
export const CLIENT_COOKIE_NAME = '_intel_vid_client';

export const LOCAL_KEY = '_intel_identity_v4';
export const IDB_NAME = 'intel_system_db';
export const IDB_STORE = 'identities';
export const IDB_KEY = 'primary_visitor';
export const SESSION_KEY = '_intel_sid_v4';
export const SESSION_TTL_MS = 30 * 60 * 1000;

/** IndexedDB waterfall race budget. */
const IDB_TIMEOUT_MS = 800;

/* -------------------------------------------------------------------------- */
/* Types                                                                       */
/* -------------------------------------------------------------------------- */

export interface StoredIdentity {
  visitor_id: string;
  hardware_fingerprint: string;
  browser_fingerprint: string;
  created_at: string;
}

export interface StoredIdentityLoad {
  identity: StoredIdentity | null;
  /** Slot names that yielded a valid identity ('localStorage', 'indexedDB', 'cookie'). */
  sources: string[];
  storage_healed: boolean;
}

interface SessionRecord {
  session_id: string;
  tab_opened_at: number;
}

/* -------------------------------------------------------------------------- */
/* Validation helpers                                                          */
/* -------------------------------------------------------------------------- */

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/** Structural validation: all four fields are strings, visitor_id non-empty. */
function isValidStoredIdentity(value: unknown): value is StoredIdentity {
  if (!isPlainObject(value)) return false;
  if (!isNonEmptyString(value.visitor_id)) return false;
  if (typeof value.hardware_fingerprint !== 'string') return false;
  if (typeof value.browser_fingerprint !== 'string') return false;
  if (typeof value.created_at !== 'string') return false;
  return true;
}

function parseJson(raw: string | null): unknown {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* localStorage                                                                */
/* -------------------------------------------------------------------------- */

function readLocalStorage(): StoredIdentity | null {
  try {
    const storage = window.localStorage;
    if (!storage) return null;
    const candidate = parseJson(storage.getItem(LOCAL_KEY));
    return isValidStoredIdentity(candidate) ? candidate : null;
  } catch {
    return null;
  }
}

function writeLocalStorage(record: StoredIdentity): boolean {
  try {
    window.localStorage.setItem(LOCAL_KEY, JSON.stringify(record));
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* IndexedDB (promise-wrapped, timeout race, never throws)                     */
/* -------------------------------------------------------------------------- */

function idbOpen(): Promise<IDBDatabase> {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(IDB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        /* Out-of-line keys: values stored under IDB_KEY. */
        db.createObjectStore(IDB_STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('idb_open_failed'));
    request.onblocked = () => reject(new Error('idb_blocked'));
  });
}

function idbGet(): Promise<StoredIdentity | null> {
  return new Promise<StoredIdentity | null>((resolve) => {
    let settled = false;
    const finish = (value: StoredIdentity | null): void => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    try {
      if (typeof indexedDB === 'undefined' || !indexedDB) {
        finish(null);
        return;
      }
      idbOpen()
        .then((db) => {
          try {
            const tx = db.transaction(IDB_STORE, 'readonly');
            const store = tx.objectStore(IDB_STORE);
            const get = store.get(IDB_KEY);
            get.onsuccess = () => {
              const candidate = get.result;
              finish(isValidStoredIdentity(candidate) ? candidate : null);
            };
            get.onerror = () => finish(null);
            tx.oncomplete = () => {
              try {
                db.close();
              } catch {
                /* ignore */
              }
            };
            tx.onerror = () => finish(null);
          } catch {
            finish(null);
          }
        })
        .catch(() => finish(null));
    } catch {
      finish(null);
    }

    /* Hard 800ms budget: a hung open must never stall the waterfall. */
    setTimeout(() => finish(null), IDB_TIMEOUT_MS);
  });
}

function idbPut(record: StoredIdentity): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    let settled = false;
    const finish = (value: boolean): void => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    try {
      if (typeof indexedDB === 'undefined' || !indexedDB) {
        finish(false);
        return;
      }
      idbOpen()
        .then((db) => {
          try {
            const tx = db.transaction(IDB_STORE, 'readwrite');
            const store = tx.objectStore(IDB_STORE);
            store.put(record, IDB_KEY);
            tx.oncomplete = () => {
              try {
                db.close();
              } catch {
                /* ignore */
              }
              finish(true);
            };
            tx.onerror = () => {
              finish(false);
              try {
                db.close();
              } catch {
                /* ignore */
              }
            };
            tx.onabort = () => finish(false);
          } catch {
            finish(false);
          }
        })
        .catch(() => finish(false));
    } catch {
      finish(false);
    }

    setTimeout(() => finish(false), IDB_TIMEOUT_MS);
  });
}

/* -------------------------------------------------------------------------- */
/* Cookie mirror (non-HttpOnly, defensive)                                     */
/* -------------------------------------------------------------------------- */

function readClientCookie(): StoredIdentity | null {
  try {
    if (typeof document === 'undefined' || !document.cookie) return null;
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const eq = cookie.indexOf('=');
      if (eq === -1) continue;
      const name = cookie.slice(0, eq).trim();
      if (name !== CLIENT_COOKIE_NAME) continue;
      const raw = cookie.slice(eq + 1).trim();
      if (!raw) return null;
      let value = raw;
      try {
        value = decodeURIComponent(raw);
      } catch {
        /* keep raw value when malformed escaping */
      }
      /* The mirror carries only the visitor id — synthesize a partial record.
       * Hardware/browser layers stay empty; the server re-derives them. */
      const partial: StoredIdentity = {
        visitor_id: value,
        hardware_fingerprint: '',
        browser_fingerprint: '',
        created_at: '',
      };
      return isNonEmptyString(partial.visitor_id) ? partial : null;
    }
    return null;
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Waterfall + healing                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Waterfall load: localStorage → IndexedDB → cookie mirror. The first slot
 * with a structurally valid identity wins; every later slot is still probed so
 * `sources` reports all slots that held a valid identity, and all writable
 * slots are then healed with the winning record. storage_healed is true only
 * when at least one heal write actually landed. Never throws.
 */
export async function loadStoredIdentity(): Promise<StoredIdentityLoad> {
  try {
    if (typeof window === 'undefined') {
      return { identity: null, sources: [], storage_healed: false };
    }

    const candidates: Array<{ slot: string; identity: StoredIdentity }> = [];

    const fromLocal = readLocalStorage();
    if (fromLocal) candidates.push({ slot: 'localStorage', identity: fromLocal });

    const fromIdb = await idbGet();
    if (fromIdb) candidates.push({ slot: 'indexedDB', identity: fromIdb });

    const fromCookie = readClientCookie();
    if (fromCookie) candidates.push({ slot: 'cookie', identity: fromCookie });

    if (candidates.length === 0) {
      return { identity: null, sources: [], storage_healed: false };
    }

    const winning = candidates[0];
    const healed = await persistIdentity(winning.identity);

    return {
      identity: winning.identity,
      sources: candidates.map((c) => c.slot),
      storage_healed: healed,
    };
  } catch {
    return { identity: null, sources: [], storage_healed: false };
  }
}

/**
 * Writes the record to localStorage and IndexedDB idempotently (same record →
 * same stored bytes). Resolves true when at least one write succeeded; never
 * throws.
 */
export async function persistIdentity(record: StoredIdentity): Promise<boolean> {
  if (!isValidStoredIdentity(record)) return false;
  let wrote = false;
  const localOk = writeLocalStorage(record);
  if (localOk) wrote = true;
  try {
    const idbOk = await idbPut(record);
    if (idbOk) wrote = true;
  } catch {
    /* treated as a failed slot */
  }
  return wrote;
}

/* -------------------------------------------------------------------------- */
/* Session id                                                                  */
/* -------------------------------------------------------------------------- */

/** 32-char lowercase hex id from crypto.getRandomValues, Math.random fallback. */
function generateSessionId(): string {
  try {
    const cryptoRef: Crypto | undefined =
      typeof crypto !== 'undefined' ? crypto : undefined;
    if (cryptoRef && typeof cryptoRef.getRandomValues === 'function') {
      const bytes = new Uint8Array(16);
      cryptoRef.getRandomValues(bytes);
      let hex = '';
      for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
      return hex;
    }
  } catch {
    /* fall through to the weak fallback */
  }
  let fallback = '';
  while (fallback.length < 32) {
    fallback += Math.floor(Math.random() * 0x10000)
      .toString(16)
      .padStart(4, '0');
  }
  return fallback.slice(0, 32);
}

function isValidSessionRecord(value: unknown): value is SessionRecord {
  return (
    isPlainObject(value) &&
    isNonEmptyString(value.session_id) &&
    typeof value.tab_opened_at === 'number' &&
    isFinite(value.tab_opened_at)
  );
}

function readSessionStorage(): SessionRecord | null {
  try {
    const storage = window.sessionStorage;
    if (!storage) return null;
    const candidate = parseJson(storage.getItem(SESSION_KEY));
    return isValidSessionRecord(candidate) ? candidate : null;
  } catch {
    return null;
  }
}

function writeSessionStorage(record: SessionRecord): boolean {
  try {
    window.sessionStorage.setItem(SESSION_KEY, JSON.stringify(record));
    return true;
  } catch {
    return false;
  }
}

let memorySessionId: string | null = null;

/**
 * Resolves the session id with a sliding 30-minute TTL:
 * in-memory var → sessionStorage (tab_opened_at inside TTL, refreshed on every
 * access) → freshly generated 32-char hex. `isNew` is true when a new session
 * id was created. Private-mode sessionStorage failures degrade to the
 * in-memory value only.
 */
export function getSessionId(): { sessionId: string; isNew: boolean } {
  try {
    const now = Date.now();

    if (memorySessionId) {
      /* Sliding window: touch the timestamp on every access. */
      const existing = readSessionStorage();
      if (existing && existing.session_id === memorySessionId) {
        writeSessionStorage({ session_id: existing.session_id, tab_opened_at: now });
      }
      return { sessionId: memorySessionId, isNew: false };
    }

    const stored = readSessionStorage();
    if (stored && now - stored.tab_opened_at < SESSION_TTL_MS) {
      memorySessionId = stored.session_id;
      writeSessionStorage({ session_id: stored.session_id, tab_opened_at: now });
      return { sessionId: memorySessionId, isNew: false };
    }

    memorySessionId = generateSessionId();
    writeSessionStorage({ session_id: memorySessionId, tab_opened_at: now });
    return { sessionId: memorySessionId, isNew: true };
  } catch {
    /* Storage completely unavailable (aggressive private mode). */
    if (!memorySessionId) memorySessionId = generateSessionId();
    return { sessionId: memorySessionId, isNew: memorySessionId !== null };
  }
}
