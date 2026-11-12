import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Activity, Wifi, Play, Square, Gauge, ArrowDown, ArrowUp } from 'lucide-react';
import { getFirstPartyStorage } from '../lib/collector';

interface PingSample {
  id: number;
  timestampMs: number;
  latencyMs: number | null; // null indicates a failed request (produces a gap in the continuous line)
  failed: boolean;
}

type SpeedTestPhase = 'idle' | 'downloading' | 'uploading' | 'cooldown' | 'cancelled' | 'error';

interface SpeedTestState {
  phase: SpeedTestPhase;
  downloadMbps: number | null;
  uploadMbps: number | null;
  testedAtLabel: string | null;
  error: string | null;
}

// Fetch/XHR rejection carrying the HTTP status so callers can special-case payload-limit (413) errors
type HttpErrorWithStatus = Error & { status?: number };

const Y_LEVELS = [0, 150, 300, 450, 600] as const;
const MAX_Y_MS = 600;
const FIVE_MINUTES_MS = 5 * 60 * 1000; // 300,000 ms rolling five-minute timeline
const SAMPLE_INTERVAL_MS = 5000; // 5s visible RTT measurement interval (serialized, configurable)

// One-shot, bounded speed analysis. ONE explicit Start = ONE download phase + ONE upload phase.
// No automatic repeat, no hidden-tab transfers, no uncapped fallback.
const DOWNLOAD_PHASE_DURATION_MS = 8000; // 8s maximum download phase
const UPLOAD_PHASE_DURATION_MS = 6000; // 6s maximum upload phase
const RUN_COOLDOWN_MS = 60000; // 60s minimum interval between starts (server enforces durably)
const MAX_MONITOR_DURATION_MS = 15 * 60 * 1000; // auto-pause live monitoring after 15 minutes
const FALLBACK_MAX_DOWNLOAD_BYTES = 16 * 1024 * 1024; // 16 MiB aggregate download budget per run
const FALLBACK_MAX_UPLOAD_BYTES = 8 * 1024 * 1024; // 8 MiB aggregate upload budget per run
const ODOMETER_UPDATE_INTERVAL_MS = 250; // Smooth 250ms live odometer updates
const CONCURRENT_STREAMS = 2; // Policy maximum: 2 parallel transfer requests per run

// Stateless-serverless (Vercel) hardening: every speed-test request stays far below the 4.5 MB
// body cap, and every failure path keeps the test running instead of stalling at 0.00 Mbps.
const SPEED_TEST_CHUNK_BYTES_MAX = 262144; // hard 256 KiB cap per download/upload request chunk
const SPEED_TEST_413_FALLBACK_BYTES = 262144; // 256 KiB one-shot retry payload after an HTTP 413
const SPEED_TEST_INIT_TIMEOUT_MS = 4000; // speed-test/init call must never stall the test loop
const LAST_RUN_STORAGE_KEY = 'intel_speedtest_last_v1'; // display-only restore across remounts

function readPersistedSpeedTest(): SpeedTestState | null {
  try {
    const raw = window.sessionStorage.getItem(LAST_RUN_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<SpeedTestState>;
    const downloadMbps = typeof parsed.downloadMbps === 'number' ? parsed.downloadMbps : null;
    const uploadMbps = typeof parsed.uploadMbps === 'number' ? parsed.uploadMbps : null;
    if (downloadMbps === null && uploadMbps === null) return null;
    return {
      phase: 'cooldown',
      downloadMbps,
      uploadMbps,
      testedAtLabel: typeof parsed.testedAtLabel === 'string' ? parsed.testedAtLabel : null,
      error: null,
    };
  } catch {
    return null;
  }
}

function persistSpeedTestResult(result: SpeedTestState): void {
  try {
    window.sessionStorage.setItem(LAST_RUN_STORAGE_KEY, JSON.stringify(result));
  } catch {
    // Storage unavailable (private mode / quota) - results remain in memory.
  }
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
 * Odometer-Style Rolling Number Animation component.
 * Animates each digit independently in the same monospace font, rolling upwards when
 * the value increases and downwards when the value decreases without flickering.
 */
function OdometerNumber({
  value,
  decimals = 2,
  suffix = '',
  fallback = '0.00',
}: {
  value: number | null;
  decimals?: number;
  suffix?: string;
  fallback?: string;
}) {
  const formatted =
    value !== null && Number.isFinite(value) ? Math.max(0, value).toFixed(decimals) : fallback;
  const chars = formatted.split('');

  return (
    <span
      className="inline-flex items-baseline font-mono tabular-nums font-bold text-slate-900 select-none"
      aria-label={`${formatted}${suffix}`}
    >
      <span className="inline-flex items-center overflow-hidden h-[1.25em] leading-[1.25em]">
        {chars.map((char, idx) => {
          const placeKey = chars.length - idx;
          const digit = parseInt(char, 10);
          if (!Number.isNaN(digit)) {
            return (
              <span
                key={`digit-${placeKey}`}
                className="relative inline-block w-[0.62em] h-[1.25em] overflow-hidden align-bottom"
              >
                <span
                  className="flex flex-col transition-transform duration-300 ease-out will-change-transform"
                  style={{
                    transform: `translateY(-${digit * 10}%)`,
                  }}
                >
                  {[0, 1, 2, 3, 4, 5, 6, 7, 8, 9].map((d) => (
                    <span
                      key={d}
                      className="h-[1.25em] leading-[1.25em] flex items-center justify-center"
                    >
                      {d}
                    </span>
                  ))}
                </span>
              </span>
            );
          }

          return (
            <span
              key={`sep-${placeKey}`}
              className="inline-flex items-center justify-center w-[0.38em] h-[1.25em] leading-[1.25em]"
            >
              {char}
            </span>
          );
        })}
      </span>
      {suffix ? (
        <span className="ml-1.5 text-xs sm:text-sm font-semibold text-slate-600 font-mono tabular-nums">
          {suffix}
        </span>
      ) : null}
    </span>
  );
}

// Reusable high-entropy 3 MB binary payload in browser memory for multi-stream upload saturation
const UPLOAD_TEMPLATE_3MB = (() => {
  const buf = new Uint8Array(3 * 1024 * 1024);
  for (let i = 0; i < buf.length; i++) {
    buf[i] = (i * 73 + 19) & 0xff;
  }
  return buf;
})();

function getUploadPayloadSlice(byteLength: number): Uint8Array {
  const clamped = Math.max(65536, Math.min(UPLOAD_TEMPLATE_3MB.byteLength, byteLength));
  return UPLOAD_TEMPLATE_3MB.subarray(0, clamped);
}

/**
 * Ookla Speedtest.net Trimmed-Mean Throughput Algorithm:
 * Sorts throughput samples ascending, discards the bottom 30% (TCP slow-start ramp-up and
 * inter-request handshakes) and the top 8% (socket buffer bursts), and averages the
 * middle 62% steady-state saturation samples.
 */
function computeOoklaTrimmedMbps(samples: number[]): number | null {
  const valid = samples.filter((v) => Number.isFinite(v) && v > 0);
  if (valid.length === 0) return null;
  if (valid.length < 4) {
    const avg = valid.reduce((a, b) => a + b, 0) / valid.length;
    return Number(avg.toFixed(2));
  }
  const sorted = [...valid].sort((a, b) => a - b);
  const lowIndex = Math.floor(sorted.length * 0.3);
  const highIndex = Math.max(lowIndex + 1, Math.ceil(sorted.length * 0.92));
  const slice = sorted.slice(lowIndex, highIndex);
  const sum = slice.reduce((acc, v) => acc + v, 0);
  return Number((sum / slice.length).toFixed(2));
}

export function NetworkStabilityPanel() {
  const [isOnline, setIsOnline] = useState<boolean>(
    typeof navigator !== 'undefined' ? navigator.onLine : true
  );
  const [isRunning, setIsRunning] = useState<boolean>(true);
  const [samples, setSamples] = useState<PingSample[]>([]);
  const [windowEndMs, setWindowEndMs] = useState<number>(() => Date.now());
  // Click-only pinned sample ID (hover does NOT trigger the popup)
  const [pinnedSampleId, setPinnedSampleId] = useState<number | null>(null);
  // Responsive SVG width measured from actual container so mobile graphs are never squeezed
  const [chartWidth, setChartWidth] = useState<number>(560);

  const [speedTest, setSpeedTest] = useState<SpeedTestState>(
    () =>
      readPersistedSpeedTest() ?? {
        phase: 'idle',
        downloadMbps: null,
        uploadMbps: null,
        testedAtLabel: null,
        error: null,
      }
  );
  const [cooldownUntilMs, setCooldownUntilMs] = useState<number | null>(null);
  const [cooldownNowMs, setCooldownNowMs] = useState<number>(() => Date.now());
  const [monitorAutoPaused, setMonitorAutoPaused] = useState<boolean>(false);

  const sampleCounterRef = useRef<number>(0);
  const latestRttMsRef = useRef<number>(180);
  const recentRttsRef = useRef<number[]>([]);
  const pingInFlightRef = useRef<boolean>(false);
  // Ref mirrors isOnline so the speed-test loop can consult measured connectivity synchronously
  // (a falsely-offline navigator.onLine must never strand the panel at 'Starting...' / 0.00 Mbps)
  const isOnlineRef = useRef<boolean>(typeof navigator !== 'undefined' ? navigator.onLine : true);
  const chartWrapperRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const activeXhrsRef = useRef<Set<XMLHttpRequest>>(new Set());
  // One-shot speed-test control: single in-flight guard + abort handle for hard cancellation.
  const testAbortRef = useRef<AbortController | null>(null);
  const isTestStartingRef = useRef<boolean>(false);
  const lastProbeFailedRef = useRef<boolean>(false);
  const monitorStartedAtRef = useRef<number>(Date.now());

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

  // Track online/offline browser events
  useEffect(() => {
    const handleOnline = () => {
      isOnlineRef.current = true;
      setIsOnline(true);
    };
    const handleOffline = () => {
      isOnlineRef.current = false;
      setIsOnline(false);
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  // Measure pure HTTP socket RTT to /api/network/ping (serialized with instant retry)
  const executePingProbe = useCallback(async () => {
    if (pingInFlightRef.current) {
      return;
    }
    if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
      return;
    }

    pingInFlightRef.current = true;
    const reqId = ++sampleCounterRef.current;

    try {
      // NOTE: navigator.onLine is deliberately NOT trusted as a gate here. The measured HTTP
      // probe is the single source of truth: any 2xx response => successful sample => panel
      // Online; any other status or network error => typical-loss sample. A falsely-offline
      // navigator flag resolves itself on the first successful probe instead of showing a
      // false "Offline / 100% packet loss" forever.

      const attemptSinglePing = async (_attemptIdx: number): Promise<number> => {
        const url = `/api/network/ping?t=${Date.now()}`;
        const startTime = performance.now();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        try {
          const res = await fetch(url, {
            method: 'GET',
            cache: 'no-store',
            headers: { Accept: 'application/json' },
            signal: controller.signal,
          });
          clearTimeout(timeoutId);

          // Any 2xx (200-299) is a successful sample and flips the panel Online. Every other
          // status or a network error falls through to the caller as a typical-loss sample.
          if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
          }

          // Base RTT straight from performance.now(); refined below with the pure socket RTT
          // when Resource Timing is available for this request.
          let rtt = Math.max(1, Math.round(performance.now() - startTime));

          try {
            const fullUrl = window.location.origin + url;
            const entries = performance.getEntriesByName(fullUrl);
            const lastEntry = entries[entries.length - 1] as PerformanceResourceTiming | undefined;
            if (lastEntry) {
              // Pure socket RTT: time from first request byte sent on socket to first response header byte received.
              // Excludes browser connection-pool queueing (requestStart - startTime) and cold TLS setup.
              if (lastEntry.responseStart > lastEntry.requestStart) {
                rtt = Math.max(1, Math.round(lastEntry.responseStart - lastEntry.requestStart));
              } else if (lastEntry.responseEnd > lastEntry.requestStart) {
                rtt = Math.max(1, Math.round(lastEntry.responseEnd - lastEntry.requestStart));
              } else if (lastEntry.duration > 0) {
                rtt = Math.max(1, Math.round(lastEntry.duration));
              }
            }
            if (performance.getEntriesByType('resource').length > 180) {
              performance.clearResourceTimings();
            }
          } catch {
            // Fallback to the performance.now() delta computed above
          }

          // Drain (never parse) the body AFTER measuring so the connection stays reusable
          try {
            await res.text();
          } catch {
            // A failed body drain does not invalidate the sample
          }

          return rtt;
        } catch (err) {
          clearTimeout(timeoutId);
          throw err;
        }
      };

      let rawRttMs: number;
      try {
        rawRttMs = await attemptSinglePing(0);
      } catch {
        // If primary probe hit a transient serverless container recycle or socket reset, retry once immediately
        if (typeof navigator !== 'undefined' && !navigator.onLine) {
          throw new Error('Offline');
        }
        rawRttMs = await attemptSinglePing(1);
      }

      // Filter one-off serverless cold-start or upload-bufferbloat spikes using rolling median of recent probes
      let stabilizedRttMs = rawRttMs;
      const history = recentRttsRef.current;
      if (history.length >= 3) {
        const sortedHist = [...history].sort((a, b) => a - b);
        const medianRtt = sortedHist[Math.floor(sortedHist.length / 2)];
        if (rawRttMs > medianRtt * 1.65 && rawRttMs - medianRtt > 75) {
          stabilizedRttMs = Math.round(medianRtt + (rawRttMs - medianRtt) * 0.22);
        }
      }

      const nextHist = [...history, stabilizedRttMs];
      if (nextHist.length > 7) {
        nextHist.shift();
      }
      recentRttsRef.current = nextHist;

      const clampedRtt = Math.max(1, Math.min(MAX_Y_MS, stabilizedRttMs));
      latestRttMsRef.current = Math.round(latestRttMsRef.current * 0.6 + clampedRtt * 0.4);

      const recordedAtMs = Date.now();
      lastProbeFailedRef.current = false;
      isOnlineRef.current = true;
      setIsOnline(true);
      setWindowEndMs(recordedAtMs);
      setSamples((prev) => {
        const cutoff = recordedAtMs - FIVE_MINUTES_MS - 15000;
        return [
          ...prev.filter((s) => s.timestampMs >= cutoff),
          {
            id: reqId,
            timestampMs: recordedAtMs,
            latencyMs: clampedRtt,
            failed: false,
          },
        ];
      });
    } catch {
      const recordedAtMs = Date.now();
      lastProbeFailedRef.current = true;
      if (typeof navigator !== 'undefined' && !navigator.onLine) {
        isOnlineRef.current = false;
        setIsOnline(false);
      }
      setWindowEndMs(recordedAtMs);
      setSamples((prev) => {
        const cutoff = recordedAtMs - FIVE_MINUTES_MS - 15000;
        return [
          ...prev.filter((s) => s.timestampMs >= cutoff),
          {
            id: reqId,
            timestampMs: recordedAtMs,
            latencyMs: null,
            failed: true,
          },
        ];
      });
    } finally {
      pingInFlightRef.current = false;
    }
  }, []);

  /**
   * Runs a full 15.0-second Ookla-grade multi-stream Download analysis using 6 parallel
   * Fetch Streams. Excludes HTTP TTFB / serverless invocation wait time from payload
   * transfer rate calculation and computes an Ookla Trimmed Mean every 250ms.
   */
  const runSustainedDownload15s = useCallback(
    async (
      token: string,
      maxDownloadBytes: number,
      masterSignal: AbortSignal
    ): Promise<number> => {
      let totalReceivedBytes = 0;
      let totalRequestedBytes = 0;
      let purePayloadBytes = 0;
      let purePayloadTransferMs = 0;
      let firstBytePerf: number | null = null;
      const phaseStartPerf = performance.now();

      // Sliding window buckets and Ookla sample accumulator
      const byteBuckets: Array<{ t: number; bytes: number }> = [];
      const throughputSamplesMbps: number[] = [];

      // Fixed 1 MiB request chunks: enough to saturate the link across 3 streams while every
      // request stays far under the 4.5 MB stateless-serverless cap (never oversized, no 413s)
      const DOWNLOAD_CHUNK_BYTES = SPEED_TEST_CHUNK_BYTES_MAX;

      const phaseAbort = new AbortController();
      const onMasterAbort = () => phaseAbort.abort();
      masterSignal.addEventListener('abort', onMasterAbort);

      // End the download phase cleanly at 15.0 seconds
      const phaseEndTimer = setTimeout(() => {
        phaseAbort.abort();
      }, DOWNLOAD_PHASE_DURATION_MS);

      const evaluateLiveDownloadMbps = (): number | null => {
        if (firstBytePerf === null || totalReceivedBytes <= 0) return null;
        const nowPerf = performance.now();

        // 1. Sliding window rate over the last 1,250 ms across all 6 streams
        const windowCutoff = nowPerf - 1250;
        while (byteBuckets.length > 0 && byteBuckets[0].t < windowCutoff - 500) {
          byteBuckets.shift();
        }
        const recentWindow = byteBuckets.filter((b) => b.t >= windowCutoff);
        let windowMbps = 0;
        if (recentWindow.length >= 2) {
          const spanSec = Math.max(
            0.18,
            (nowPerf - recentWindow[0].t) / 1000
          );
          const windowBytes = recentWindow.reduce((acc, b) => acc + b.bytes, 0);
          windowMbps = (windowBytes * 8) / (spanSec * 1_000_000);
        }

        // 2. Pure payload reception rate across all 6 concurrent streams (excluding TTFB wait)
        let pureStreamParallelMbps = 0;
        if (purePayloadBytes > 0 && purePayloadTransferMs > 15) {
          const effectiveParallelSec = Math.max(
            0.05,
            purePayloadTransferMs / CONCURRENT_STREAMS / 1000
          );
          pureStreamParallelMbps = (purePayloadBytes * 8) / (effectiveParallelSec * 1_000_000);
        }

        // 3. Wall-clock fallback
        const wallSec = Math.max(0.12, (nowPerf - firstBytePerf) / 1000);
        const wallMbps = (totalReceivedBytes * 8) / (wallSec * 1_000_000);

        const bestInstantMbps = Math.max(pureStreamParallelMbps, windowMbps, wallMbps);
        if (bestInstantMbps > 0 && Number.isFinite(bestInstantMbps)) {
          throughputSamplesMbps.push(bestInstantMbps);
        }

        return computeOoklaTrimmedMbps(throughputSamplesMbps) ?? Number(bestInstantMbps.toFixed(2));
      };

      const uiInterval = setInterval(() => {
        const liveMbps = evaluateLiveDownloadMbps();
        if (liveMbps !== null && liveMbps > 0) {
          setSpeedTest((prev) => ({
            ...prev,
            downloadMbps: liveMbps,
          }));
        }
      }, ODOMETER_UPDATE_INTERVAL_MS);

      const creditReceivedPurePayload = (
        chunkUrl: string,
        chunkReqStartPerf: number,
        chunkFirstBytePerf: number | null,
        chunkLastBytePerf: number | null,
        chunkBytesReceived: number
      ): void => {
        if (chunkBytesReceived <= 0 || chunkFirstBytePerf === null) return;
        const chunkReqEndPerf = performance.now();
        const chunkTotalMs = Math.max(1, chunkReqEndPerf - chunkReqStartPerf);

        // Measure pure payload download time excluding HTTP TTFB / serverless cold wait
        let payloadDurationMs =
          chunkLastBytePerf !== null && chunkLastBytePerf - chunkFirstBytePerf >= 12
            ? chunkLastBytePerf - chunkFirstBytePerf
            : 0;

        try {
          const entries = performance.getEntriesByName(window.location.origin + chunkUrl);
          const entry = entries[entries.length - 1] as PerformanceResourceTiming | undefined;
          if (entry && entry.responseEnd > entry.responseStart + 5) {
            payloadDurationMs = Math.max(
              payloadDurationMs,
              entry.responseEnd - entry.responseStart
            );
          }
        } catch {
          // Ignore ResourceTiming error
        }

        if (payloadDurationMs < 12) {
          // Fallback when serverless runtime flushes the buffered payload in one burst after TTFB:
          // subtract estimated 1-way TTFB overhead from total request duration
          const estimatedTtfbMs = Math.min(chunkTotalMs * 0.68, latestRttMsRef.current * 0.88);
          payloadDurationMs = Math.max(15, chunkTotalMs - estimatedTtfbMs);
        }

        purePayloadBytes += chunkBytesReceived;
        purePayloadTransferMs += payloadDurationMs;
      };

      const streamWorker = async (workerIdx: number) => {
        let chunkSeq = 0;
        while (
          !phaseAbort.signal.aborted &&
          !masterSignal.aborted &&
          performance.now() - phaseStartPerf < DOWNLOAD_PHASE_DURATION_MS
        ) {
          const remainingBudget = maxDownloadBytes - totalRequestedBytes;
          if (remainingBudget < 65536) {
            break;
          }

          const reqBytes = Math.min(DOWNLOAD_CHUNK_BYTES, remainingBudget);
          totalRequestedBytes += reqBytes;
          chunkSeq += 1;

          // Token rides in BOTH the query string (token + bytes) and the x-speed-test-token
          // header so stateless serverless handlers can validate it either way.
          const url = `/api/network/download?token=${encodeURIComponent(
            token
          )}&bytes=${reqBytes}&s=${workerIdx}_${chunkSeq}_${Date.now()}`;

          const reqStartPerf = performance.now();
          let streamFirstBytePerf: number | null = null;
          let streamLastBytePerf: number | null = null;
          let streamBytesReceived = 0;

          try {
            const res = await fetch(url, {
              method: 'GET',
              cache: 'no-store',
              headers: {
                // Token rides in BOTH the query string and the header (stateless serverless
                // handlers may validate either); bytes mirrors the query param
                'x-speed-test-token': token,
                'x-speed-test-bytes': String(reqBytes),
              },
              signal: phaseAbort.signal,
            });

            if (!res.ok) {
              await new Promise((r) => setTimeout(r, 80));
              continue;
            }

            if (res.body && typeof res.body.getReader === 'function') {
              const reader = res.body.getReader();
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                if (value && value.byteLength > 0) {
                  const nowPerf = performance.now();
                  if (firstBytePerf === null) {
                    firstBytePerf = nowPerf;
                  }
                  if (streamFirstBytePerf === null) {
                    streamFirstBytePerf = nowPerf;
                  }
                  streamLastBytePerf = nowPerf;
                  streamBytesReceived += value.byteLength;
                  totalReceivedBytes += value.byteLength;
                  byteBuckets.push({ t: nowPerf, bytes: value.byteLength });
                }
                if (performance.now() - phaseStartPerf >= DOWNLOAD_PHASE_DURATION_MS) {
                  await reader.cancel().catch(() => {});
                  break;
                }
              }
            } else {
              const buf = await res.arrayBuffer();
              if (buf.byteLength > 0) {
                const nowPerf = performance.now();
                if (firstBytePerf === null) {
                  firstBytePerf = nowPerf;
                }
                streamFirstBytePerf = nowPerf;
                streamLastBytePerf = nowPerf;
                streamBytesReceived += buf.byteLength;
                totalReceivedBytes += buf.byteLength;
                byteBuckets.push({ t: nowPerf, bytes: buf.byteLength });
              }
            }

            // Chunk read to completion: credit its pure-payload transfer
            creditReceivedPurePayload(
              url,
              reqStartPerf,
              streamFirstBytePerf,
              streamLastBytePerf,
              streamBytesReceived
            );
          } catch {
            // Mid-chunk stream failure (network drop, abort, reset): treat the chunk as done
            // with whatever bytes actually arrived — credit them and keep looping, never hang.
            creditReceivedPurePayload(
              url,
              reqStartPerf,
              streamFirstBytePerf,
              streamLastBytePerf,
              streamBytesReceived
            );

            if (phaseAbort.signal.aborted || masterSignal.aborted) {
              break;
            }
            await new Promise((r) => setTimeout(r, 80));
          }

          // Brief 25ms yield between chunks so RTT probes and UI events are serviced with zero lag
          if (!phaseAbort.signal.aborted && !masterSignal.aborted) {
            await new Promise((r) => setTimeout(r, 25));
          }
        }
      };

      try {
        await Promise.all(
          Array.from({ length: CONCURRENT_STREAMS }, (_, idx) => streamWorker(idx))
        );
        const elapsedMs = performance.now() - phaseStartPerf;
        if (elapsedMs < DOWNLOAD_PHASE_DURATION_MS && !masterSignal.aborted) {
          await new Promise((r) =>
            setTimeout(r, Math.max(0, DOWNLOAD_PHASE_DURATION_MS - elapsedMs))
          );
        }
      } finally {
        clearInterval(uiInterval);
        clearTimeout(phaseEndTimer);
        masterSignal.removeEventListener('abort', onMasterAbort);
      }

      if (masterSignal.aborted) {
        throw new Error('Cancelled');
      }

      const finalMbps = evaluateLiveDownloadMbps() ?? 0;
      return finalMbps;
    },
    []
  );

  /**
   * Sends a single binary upload chunk via XMLHttpRequest and measures pure socket upload
   * transmission duration (from first upload progress byte to upload completion, excluding
   * post-upload serverless response wait time).
   */
  const sendUploadChunkXhr = useCallback(
    (
      url: string,
      payload: Uint8Array,
      signal: AbortSignal,
      onProgressDelta: (deltaBytes: number, nowPerf: number) => void
    ): Promise<{ confirmedBytes: number; pureUploadDurationMs: number }> => {
      return new Promise((resolve, reject) => {
        if (signal.aborted) {
          reject(new Error('Aborted'));
          return;
        }

        const xhr = new XMLHttpRequest();
        activeXhrsRef.current.add(xhr);
        let lastLoaded = 0;
        const sendStartPerf = performance.now();
        let firstUploadTickPerf: number | null = null;
        let lastUploadTickPerf: number | null = null;

        const cleanup = () => {
          activeXhrsRef.current.delete(xhr);
          signal.removeEventListener('abort', handleAbort);
        };

        const handleAbort = () => {
          try {
            xhr.abort();
          } catch {
            // Ignore
          }
          cleanup();
          reject(new Error('Aborted'));
        };

        signal.addEventListener('abort', handleAbort);

        xhr.open('POST', url, true);
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');
        // Token rides in BOTH the query string and the x-speed-test-token header so stateless
        // serverless handlers can validate it either way
        if (url.includes('token=')) {
          try {
            const token = new URL(url, window.location.origin).searchParams.get('token');
            if (token) xhr.setRequestHeader('x-speed-test-token', token);
          } catch {
            // Ignore header fallback failures
          }
        }
        xhr.timeout = 12000;

        xhr.upload.onprogress = (event) => {
          const nowPerf = performance.now();
          if (firstUploadTickPerf === null) {
            firstUploadTickPerf = nowPerf;
          }
          lastUploadTickPerf = nowPerf;

          if (event.lengthComputable && event.loaded > lastLoaded) {
            const delta = event.loaded - lastLoaded;
            lastLoaded = event.loaded;
            onProgressDelta(delta, nowPerf);
          }
        };

        xhr.upload.onload = () => {
          lastUploadTickPerf = performance.now();
        };

        xhr.onload = () => {
          cleanup();
          if (xhr.status >= 200 && xhr.status < 300) {
            const totalXhrMs = Math.max(1, performance.now() - sendStartPerf);
            let pureUploadDurationMs =
              firstUploadTickPerf !== null &&
              lastUploadTickPerf !== null &&
              lastUploadTickPerf - firstUploadTickPerf >= 12
                ? lastUploadTickPerf - firstUploadTickPerf
                : Math.max(
                    15,
                    totalXhrMs - Math.min(totalXhrMs * 0.65, latestRttMsRef.current * 0.85)
                  );

            try {
              const parsed = JSON.parse(xhr.responseText) as {
                ok?: boolean;
                receivedBytes?: number;
                elapsedServerMs?: number;
              };
              const confirmed =
                typeof parsed.receivedBytes === 'number' && parsed.receivedBytes > 0
                  ? parsed.receivedBytes
                  : payload.byteLength;
              if (
                typeof parsed.elapsedServerMs === 'number' &&
                parsed.elapsedServerMs > 12 &&
                parsed.elapsedServerMs < pureUploadDurationMs
              ) {
                pureUploadDurationMs = parsed.elapsedServerMs;
              }
              resolve({ confirmedBytes: confirmed, pureUploadDurationMs });
            } catch {
              resolve({
                confirmedBytes: payload.byteLength,
                pureUploadDurationMs,
              });
            }
          } else {
            const httpErr = new Error(`Upload HTTP ${xhr.status}`) as HttpErrorWithStatus;
            httpErr.status = xhr.status;
            reject(httpErr);
          }
        };

        xhr.onerror = () => {
          cleanup();
          reject(new Error('Upload network error'));
        };

        xhr.ontimeout = () => {
          cleanup();
          reject(new Error('Upload timed out'));
        };

        xhr.onabort = () => {
          cleanup();
          reject(new Error('Aborted'));
        };

        xhr.send(payload as unknown as XMLHttpRequestBodyInit);
      });
    },
    []
  );

  /**
   * Runs a full 15.0-second Ookla-grade multi-stream Upload analysis sequentially after
   * Download completes. Uses 6 concurrent streams, excludes post-upload HTTP response wait,
   * and updates the odometer smoothly every 250ms using the Ookla Trimmed Mean.
   */
  const runSustainedUpload15s = useCallback(
    async (
      token: string,
      maxUploadBytes: number,
      masterSignal: AbortSignal
    ): Promise<number> => {
      let serverConfirmedBytes = 0;
      let inFlightProgressBytes = 0;
      let totalAllocatedBytes = 0;
      let pureUploadBytes = 0;
      let pureUploadTransferMs = 0;
      let firstProgressPerf: number | null = null;
      const phaseStartPerf = performance.now();

      const uploadBuckets: Array<{ t: number; bytes: number }> = [];
      const throughputSamplesMbps: number[] = [];

      let calibratedUploadChunkBytes = SPEED_TEST_CHUNK_BYTES_MAX; // 1 MiB bodies, hard-capped at 1 MiB

      const phaseAbort = new AbortController();
      const onMasterAbort = () => phaseAbort.abort();
      masterSignal.addEventListener('abort', onMasterAbort);

      // End the upload phase cleanly at 15.0 seconds
      const phaseEndTimer = setTimeout(() => {
        phaseAbort.abort();
      }, UPLOAD_PHASE_DURATION_MS);

      const evaluateLiveUploadMbps = (): number | null => {
        const bytesToCount = Math.max(serverConfirmedBytes, inFlightProgressBytes);
        if (firstProgressPerf === null || bytesToCount <= 0) return null;
        const nowPerf = performance.now();

        // 1. Sliding window upload rate over the last 1,250 ms across all 6 streams
        const windowCutoff = nowPerf - 1250;
        while (uploadBuckets.length > 0 && uploadBuckets[0].t < windowCutoff - 500) {
          uploadBuckets.shift();
        }
        const recentWindow = uploadBuckets.filter((b) => b.t >= windowCutoff);
        let windowMbps = 0;
        if (recentWindow.length >= 2) {
          const spanSec = Math.max(0.18, (nowPerf - recentWindow[0].t) / 1000);
          const windowBytes = recentWindow.reduce((acc, b) => acc + b.bytes, 0);
          windowMbps = (windowBytes * 8) / (spanSec * 1_000_000);
        }

        // 2. Pure upload transmission rate across all 6 concurrent streams (excluding response wait)
        let pureParallelUploadMbps = 0;
        if (pureUploadBytes > 0 && pureUploadTransferMs > 15) {
          const effectiveParallelSec = Math.max(
            0.05,
            pureUploadTransferMs / CONCURRENT_STREAMS / 1000
          );
          pureParallelUploadMbps = (pureUploadBytes * 8) / (effectiveParallelSec * 1_000_000);
        }

        // 3. Wall-clock fallback
        const wallSec = Math.max(0.12, (nowPerf - firstProgressPerf) / 1000);
        const wallMbps = (bytesToCount * 8) / (wallSec * 1_000_000);

        const bestInstantMbps = Math.max(pureParallelUploadMbps, windowMbps, wallMbps);
        if (bestInstantMbps > 0 && Number.isFinite(bestInstantMbps)) {
          throughputSamplesMbps.push(bestInstantMbps);
        }

        return computeOoklaTrimmedMbps(throughputSamplesMbps) ?? Number(bestInstantMbps.toFixed(2));
      };

      const uiInterval = setInterval(() => {
        const liveMbps = evaluateLiveUploadMbps();
        if (liveMbps !== null && liveMbps > 0) {
          setSpeedTest((prev) => ({
            ...prev,
            uploadMbps: liveMbps,
          }));

          if (liveMbps > 12) {
            calibratedUploadChunkBytes = SPEED_TEST_CHUNK_BYTES_MAX; // 1.0 MiB — hard serverless-safe cap
          } else {
            calibratedUploadChunkBytes = 512 * 1024; // 512 KB floor keeps slow links saturated
          }
        }
      }, ODOMETER_UPDATE_INTERVAL_MS);

      const uploadWorker = async (workerIdx: number) => {
        let seq = 0;
        while (
          !phaseAbort.signal.aborted &&
          !masterSignal.aborted &&
          performance.now() - phaseStartPerf < UPLOAD_PHASE_DURATION_MS
        ) {
          const remainingBudget = maxUploadBytes - totalAllocatedBytes;
          if (remainingBudget < 65536) {
            break;
          }

          const chunkBytes = Math.min(calibratedUploadChunkBytes, remainingBudget);
          totalAllocatedBytes += chunkBytes;
          seq += 1;

          // Token rides in BOTH the query string (added here) and the x-speed-test-token header
          // (added inside sendUploadChunkXhr) so stateless serverless handlers can validate either
          const url = `/api/network/upload?token=${encodeURIComponent(
            token
          )}&s=${workerIdx}_${seq}_${Date.now()}`;

          let chunkProgressCounted = 0;
          let payloadBytes = chunkBytes;

          const attemptSend = () =>
            sendUploadChunkXhr(
              url,
              getUploadPayloadSlice(payloadBytes),
              phaseAbort.signal,
              (delta, nowPerf) => {
                chunkProgressCounted += delta;
                inFlightProgressBytes += delta;
                uploadBuckets.push({ t: nowPerf, bytes: delta });
              }
            );

          try {
            if (firstProgressPerf === null) {
              firstProgressPerf = performance.now();
            }

            let sent: { confirmedBytes: number; pureUploadDurationMs: number };
            try {
              sent = await attemptSend();
            } catch (err) {
              // HTTP 413 (payload over the stateless serverless limit): roll back progress
              // counted for this oversized attempt, shrink to 256 KiB, retry the chunk once.
              if (
                (err as HttpErrorWithStatus).status !== 413 ||
                phaseAbort.signal.aborted ||
                masterSignal.aborted
              ) {
                throw err;
              }
              inFlightProgressBytes = Math.max(0, inFlightProgressBytes - chunkProgressCounted);
              chunkProgressCounted = 0;
              payloadBytes = Math.min(payloadBytes, SPEED_TEST_413_FALLBACK_BYTES);
              calibratedUploadChunkBytes = Math.min(calibratedUploadChunkBytes, payloadBytes);
              sent = await attemptSend();
            }

            const { confirmedBytes, pureUploadDurationMs } = sent;

            pureUploadBytes += confirmedBytes;
            pureUploadTransferMs += pureUploadDurationMs;

            inFlightProgressBytes = Math.max(
              0,
              inFlightProgressBytes - chunkProgressCounted + confirmedBytes
            );
            serverConfirmedBytes += confirmedBytes;

            // Brief 25ms yield between upload chunks so RTT probes are never delayed
            if (!phaseAbort.signal.aborted && !masterSignal.aborted) {
              await new Promise((r) => setTimeout(r, 25));
            }
          } catch {
            inFlightProgressBytes = Math.max(0, inFlightProgressBytes - chunkProgressCounted);
            if (phaseAbort.signal.aborted || masterSignal.aborted) {
              break;
            }
            await new Promise((r) => setTimeout(r, 80));
          }
        }
      };

      try {
        await Promise.all(
          Array.from({ length: CONCURRENT_STREAMS }, (_, idx) => uploadWorker(idx))
        );
        const elapsedMs = performance.now() - phaseStartPerf;
        if (elapsedMs < UPLOAD_PHASE_DURATION_MS && !masterSignal.aborted) {
          await new Promise((r) =>
            setTimeout(r, Math.max(0, UPLOAD_PHASE_DURATION_MS - elapsedMs))
          );
        }
      } finally {
        clearInterval(uiInterval);
        clearTimeout(phaseEndTimer);
        masterSignal.removeEventListener('abort', onMasterAbort);
      }

      if (masterSignal.aborted) {
        throw new Error('Cancelled');
      }

      const finalMbps = evaluateLiveUploadMbps() ?? 0;
      return finalMbps;
    },
    [sendUploadChunkXhr]
  );

  // One-shot speed test: ONE Start -> ONE download phase -> ONE upload phase -> terminal result.
  // Abort in-flight work on unmount/hidden/offline. Cancelled or interrupted runs never restart.
  useEffect(() => {
    const abortTest = () => {
      testAbortRef.current?.abort();
      for (const xhr of activeXhrsRef.current) {
        try {
          xhr.abort();
        } catch {
          // Ignore
        }
      }
      activeXhrsRef.current.clear();
    };
    const onVisibility = () => {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
        abortTest();
      }
    };
    const onOffline = () => {
      isOnlineRef.current = false;
      setIsOnline(false);
      abortTest();
    };
    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('offline', onOffline);
    return () => {
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('offline', onOffline);
      abortTest();
    };
  }, []);

  // Cooldown countdown (display only; the control re-enables but never auto-starts a test).
  useEffect(() => {
    if (cooldownUntilMs === null) return;
    const id = setInterval(() => {
      if (Date.now() >= cooldownUntilMs) {
        setCooldownUntilMs(null);
      } else {
        setCooldownNowMs(Date.now());
      }
    }, 1000);
    return () => clearInterval(id);
  }, [cooldownUntilMs]);

  const runSpeedTestOnce = useCallback(async () => {
    const controller = new AbortController();
    testAbortRef.current = controller;

    let maxDlBytes = FALLBACK_MAX_DOWNLOAD_BYTES;
    let maxUlBytes = FALLBACK_MAX_UPLOAD_BYTES;
    let runCooldownMs = RUN_COOLDOWN_MS;
    let testToken = '';

    setSpeedTest((prev) => ({ ...prev, phase: 'downloading', error: null }));

    const initController = new AbortController();
    const abortInitOnTestAbort = () => initController.abort();
    controller.signal.addEventListener('abort', abortInitOnTestAbort);
    const initTimeoutId = setTimeout(() => initController.abort(), SPEED_TEST_INIT_TIMEOUT_MS);

    try {
      const stored = getFirstPartyStorage();
      const initResp = await fetch('/api/network/speed-test/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ visitorId: stored.visitorId, sessionId: stored.sessionId }),
        signal: initController.signal,
      });
      const initData = (await initResp.json().catch(() => ({}))) as {
        ok?: boolean;
        token?: string;
        maxDownloadBytes?: number;
        maxUploadBytes?: number;
        cooldownSeconds?: number;
      };
      if (initResp.ok && typeof initData.token === 'string' && initData.token.length > 0) {
        testToken = initData.token;
        // Honor the effective server policy; never exceed the built-in fallback ceilings.
        if (typeof initData.maxDownloadBytes === 'number' && initData.maxDownloadBytes > 0) {
          maxDlBytes = Math.min(initData.maxDownloadBytes, FALLBACK_MAX_DOWNLOAD_BYTES);
        }
        if (typeof initData.maxUploadBytes === 'number' && initData.maxUploadBytes > 0) {
          maxUlBytes = Math.min(initData.maxUploadBytes, FALLBACK_MAX_UPLOAD_BYTES);
        }
        if (typeof initData.cooldownSeconds === 'number' && Number.isFinite(initData.cooldownSeconds)) {
          runCooldownMs = Math.max(0, Math.min(initData.cooldownSeconds * 1000, 10 * 60 * 1000));
        }
      }
    } catch {
      // Init/admission failure must never fall back to an uncapped test.
    } finally {
      clearTimeout(initTimeoutId);
      controller.signal.removeEventListener('abort', abortInitOnTestAbort);
    }

    if (controller.signal.aborted) {
      isTestStartingRef.current = false;
      testAbortRef.current = null;
      setSpeedTest((prev) => ({ ...prev, phase: 'cancelled', error: 'Speed test cancelled.' }));
      return;
    }

    if (!testToken) {
      isTestStartingRef.current = false;
      testAbortRef.current = null;
      setSpeedTest((prev) => ({
        ...prev,
        phase: 'error',
        error: 'Speed test could not start (server admission unavailable). Try again shortly.',
      }));
      setCooldownUntilMs(Date.now() + RUN_COOLDOWN_MS);
      return;
    }

    let dlMbps: number | null = null;
    let ulMbps: number | null = null;

    try {
      dlMbps = await runSustainedDownload15s(testToken, maxDlBytes, controller.signal);
      if (controller.signal.aborted) throw new DOMException('Cancelled', 'AbortError');

      setSpeedTest((prev) => ({
        ...prev,
        downloadMbps: dlMbps ?? prev.downloadMbps,
        phase: 'uploading',
      }));

      try {
        ulMbps = await runSustainedUpload15s(testToken, maxUlBytes, controller.signal);
      } catch (uploadErr) {
        if (controller.signal.aborted) throw uploadErr;
        // Retain the completed download and label the upload honestly.
        const partial: SpeedTestState = {
          phase: 'cooldown',
          downloadMbps: dlMbps,
          uploadMbps: null,
          testedAtLabel: formatClockTimestamp(Date.now()),
          error: 'Upload interrupted; download result retained.',
        };
        setSpeedTest(partial);
        persistSpeedTestResult(partial);
        return;
      }

      if (controller.signal.aborted) throw new DOMException('Cancelled', 'AbortError');

      const finished: SpeedTestState = {
        phase: 'cooldown',
        downloadMbps: dlMbps,
        uploadMbps: ulMbps,
        testedAtLabel: formatClockTimestamp(Date.now()),
        error: null,
      };
      setSpeedTest(finished);
      persistSpeedTestResult(finished);
    } catch (err) {
      if (controller.signal.aborted) {
        setSpeedTest((prev) => ({
          ...prev,
          phase: 'cancelled',
          downloadMbps: dlMbps ?? prev.downloadMbps,
          error: 'Speed test cancelled.',
        }));
      } else {
        setSpeedTest((prev) => ({
          ...prev,
          phase: 'error',
          downloadMbps: dlMbps ?? prev.downloadMbps,
          error: err instanceof Error && err.message ? err.message : 'Speed test interrupted.',
        }));
      }
    } finally {
      if (testToken) {
        fetch('/api/network/speed-test/complete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: testToken }),
        }).catch(() => {});
      }
      testAbortRef.current = null;
      isTestStartingRef.current = false;
      if (!controller.signal.aborted) {
        setCooldownUntilMs(Date.now() + runCooldownMs);
        setCooldownNowMs(Date.now());
      }
    }
  }, [runSustainedDownload15s, runSustainedUpload15s]);

  const startSpeedTest = useCallback(() => {
    // Immediate in-flight guard before awaiting anything: a fast double click starts only one run.
    if (isTestStartingRef.current) return;
    if (speedTest.phase === 'downloading' || speedTest.phase === 'uploading') return;
    if (cooldownUntilMs !== null && Date.now() < cooldownUntilMs) return;
    isTestStartingRef.current = true;
    void runSpeedTestOnce();
  }, [cooldownUntilMs, runSpeedTestOnce, speedTest.phase]);

  const cancelSpeedTest = useCallback(() => {
    testAbortRef.current?.abort();
    for (const xhr of activeXhrsRef.current) {
      try {
        xhr.abort();
      } catch {
        // Ignore
      }
    }
    activeXhrsRef.current.clear();
  }, []);

  const toggleMonitor = useCallback(() => {
    setIsRunning((prev) => {
      if (!prev) {
        setMonitorAutoPaused(false);
        monitorStartedAtRef.current = Date.now();
      }
      return !prev;
    });
  }, []);

  // Serialized, visibility-aware live polling (5s visible cadence) with capped exponential
  // backoff on persistent failures and a hard 15-minute continuous-monitoring cap.
  useEffect(() => {
    if (!isRunning) return;

    let active = true;
    let nextProbeTimer: ReturnType<typeof setTimeout> | null = null;
    let consecutiveFailures = 0;
    monitorStartedAtRef.current = Date.now();

    const runProbeLoop = async () => {
      while (active) {
        if (Date.now() - monitorStartedAtRef.current >= MAX_MONITOR_DURATION_MS) {
          setMonitorAutoPaused(true);
          setIsRunning(false);
          break;
        }

        if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
          await new Promise<void>((resolve) => {
            nextProbeTimer = setTimeout(resolve, 1000);
          });
          continue;
        }

        const startedAt = Date.now();
        await executePingProbe();
        if (!active) break;

        consecutiveFailures = lastProbeFailedRef.current
          ? Math.min(consecutiveFailures + 1, 4)
          : 0;

        const delay = Math.min(30000, SAMPLE_INTERVAL_MS * Math.pow(2, consecutiveFailures));
        const elapsed = Date.now() - startedAt;
        const waitMs = Math.max(350, delay - elapsed);
        await new Promise<void>((resolve) => {
          nextProbeTimer = setTimeout(resolve, waitMs);
        });
      }
    };

    runProbeLoop();

    const clockTimer = setInterval(() => {
      if (typeof document === 'undefined' || document.visibilityState !== 'hidden') {
        setWindowEndMs(Date.now());
      }
    }, 500);

    return () => {
      active = false;
      if (nextProbeTimer) {
        clearTimeout(nextProbeTimer);
      }
      clearInterval(clockTimer);
    };
  }, [isRunning, executePingProbe]);

  // Rolling 5-minute window bounds
  const windowStartMs = windowEndMs - FIVE_MINUTES_MS;
  const visibleSamples = samples.filter(
    (s) => s.timestampMs >= windowStartMs - 5000 && s.timestampMs <= windowEndMs + 1000
  );

  // Calculate metrics from actual measurements in the rolling 5-minute buffer
  const validSamples = visibleSamples.filter(
    (s): s is PingSample & { latencyMs: number } => !s.failed && typeof s.latencyMs === 'number'
  );
  const failedCount = visibleSamples.filter((s) => s.failed).length;
  const totalCount = visibleSamples.length;

  const latestSample = visibleSamples[visibleSamples.length - 1];
  const currentLatencyMs =
    latestSample && !latestSample.failed && typeof latestSample.latencyMs === 'number'
      ? latestSample.latencyMs
      : null;

  const averageLatencyMs =
    validSamples.length > 0
      ? Math.round(validSamples.reduce((acc, s) => acc + s.latencyMs, 0) / validSamples.length)
      : null;

  // Jitter from consecutive successful measurements
  let jitterMs: number | null = null;
  if (validSamples.length >= 2) {
    let diffSum = 0;
    for (let i = 1; i < validSamples.length; i++) {
      diffSum += Math.abs(validSamples[i].latencyMs - validSamples[i - 1].latencyMs);
    }
    jitterMs = Number((diffSum / (validSamples.length - 1)).toFixed(1));
  }

  const failureRatePercent =
    totalCount > 0 ? Number(((failedCount / totalCount) * 100).toFixed(1)) : 0;

  // Responsive 1:1 SVG Chart Geometry (never shrinks or squeezes on mobile screens)
  const isCompactMobile = chartWidth < 420;
  const svgWidth = chartWidth;
  const svgHeight = 236;
  const padLeft = isCompactMobile ? 42 : 48;
  const padRight = 12;
  const padTop = 14;
  const padBottom = 30;
  const plotWidth = Math.max(180, svgWidth - padLeft - padRight);
  const plotHeight = svgHeight - padTop - padBottom;

  const getXForTimestamp = (tsMs: number): number => {
    const ratio = (tsMs - windowStartMs) / FIVE_MINUTES_MS;
    return padLeft + ratio * plotWidth;
  };

  const getYForLatency = (ms: number): number => {
    const clamped = Math.max(0, Math.min(MAX_Y_MS, ms));
    return padTop + plotHeight - (clamped / MAX_Y_MS) * plotHeight;
  };

  // Build continuous SVG path segments (gaps whenever a request fails)
  const pathSegments: string[] = [];
  let activeSeg: string[] = [];

  visibleSamples.forEach((s) => {
    if (s.failed || s.latencyMs === null) {
      if (activeSeg.length > 0) {
        pathSegments.push(activeSeg.join(' '));
        activeSeg = [];
      }
    } else {
      const x = getXForTimestamp(s.timestampMs).toFixed(2);
      const y = getYForLatency(s.latencyMs).toFixed(2);
      activeSeg.push(`${activeSeg.length === 0 ? 'M' : 'L'} ${x} ${y}`);
    }
  });
  if (activeSeg.length > 0) {
    pathSegments.push(activeSeg.join(' '));
  }

  // Generate moving X-axis timestamp ticks (90s spacing on compact mobile so labels never crowd, 60s on tablet/desktop)
  const tickIntervalMs = (isCompactMobile ? 90 : 60) * 1000;
  const firstTickMs = Math.ceil(windowStartMs / tickIntervalMs) * tickIntervalMs;
  const xTicks: number[] = [];
  for (let t = firstTickMs; t <= windowEndMs; t += tickIntervalMs) {
    xTicks.push(t);
  }

  // Find nearest actual recorded measurement ONLY when clicked/tapped
  const findNearestSample = (clientX: number): PingSample | null => {
    if (!svgRef.current || visibleSamples.length === 0) return null;
    const rect = svgRef.current.getBoundingClientRect();
    if (rect.width <= 0) return null;

    const svgX = ((clientX - rect.left) / rect.width) * svgWidth;
    if (svgX < padLeft - 10 || svgX > padLeft + plotWidth + 10) return null;

    let closest: PingSample | null = null;
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

    return minDistancePx <= 36 ? closest : null;
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

  // Resolve the clicked sample for the crosshair & popup (click-only, never hover)
  const activeTooltipSample =
    pinnedSampleId !== null
      ? visibleSamples.find(
          (s) => s.id === pinnedSampleId && getXForTimestamp(s.timestampMs) >= padLeft
        ) ?? null
      : null;

  const activeTooltipX = activeTooltipSample
    ? getXForTimestamp(activeTooltipSample.timestampMs)
    : null;
  const activeTooltipY =
    activeTooltipSample && activeTooltipSample.latencyMs !== null
      ? getYForLatency(activeTooltipSample.latencyMs)
      : padTop + plotHeight / 2;

  const tooltipLeftPercent =
    activeTooltipX !== null
      ? Math.max(22, Math.min(78, (activeTooltipX / svgWidth) * 100))
      : 50;

  // Cooldown remaining (display only; Start re-enables but never auto-runs).
  const cooldownRemainingMs =
    cooldownUntilMs !== null ? Math.max(0, cooldownUntilMs - cooldownNowMs) : 0;

  return (
    <div className="bg-white border border-[#E5E7EB] rounded-2xl p-4 sm:p-6 flex flex-col justify-between">
      <div>
        {/* Panel Header */}
        <div className="flex flex-wrap items-center justify-between gap-3 pb-3.5 border-b border-[#E5E7EB]">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-[#2563EB] shrink-0" />
            <h2 className="text-sm font-semibold text-slate-900">
              Network Stability
            </h2>
          </div>

          <div className="flex items-center gap-3">
            <span className="inline-flex items-center gap-1.5 text-xs font-mono tabular-nums text-slate-600">
              <Wifi className={`w-3.5 h-3.5 ${isOnline ? 'text-emerald-600' : 'text-red-600'}`} />
              <strong className={isOnline ? 'text-emerald-700' : 'text-red-600'}>
                {isOnline ? 'Online' : 'Offline'}
              </strong>
            </span>

            <button
              type="button"
              onClick={toggleMonitor}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 rounded whitespace-nowrap shrink-0 cursor-pointer"
              title={
                isRunning
                  ? 'Stop live RTT monitoring (does not affect speed-test state)'
                  : monitorAutoPaused
                  ? 'Resume live monitoring (paused after 15 minutes)'
                  : 'Start live RTT monitoring'
              }
            >
              {isRunning ? (
                <>
                  <Square className="w-3 h-3 fill-current" />
                  <span>Stop</span>
                </>
              ) : (
                <>
                  <Play className="w-3 h-3 fill-current" />
                  <span>{monitorAutoPaused ? 'Resume' : 'Start'}</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Metrics Strip: Current Latency, Average Latency, Jitter, Failure Rate */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 sm:gap-3 py-3.5 border-b border-slate-100 text-xs">
          <div className="p-2.5 rounded-xl bg-slate-50/70 border border-[#E5E7EB] min-w-0">
            <span className="text-[11px] text-slate-500 block truncate">Current RTT</span>
            <span className="text-sm sm:text-base font-bold font-mono tabular-nums text-slate-900 mt-0.5 block truncate">
              {currentLatencyMs !== null
                ? `${currentLatencyMs} ms`
                : latestSample?.failed
                ? 'Failed'
                : 'N/A'}
            </span>
          </div>
          <div className="p-2.5 rounded-xl bg-slate-50/70 border border-[#E5E7EB] min-w-0">
            <span className="text-[11px] text-slate-500 block truncate">Average RTT</span>
            <span className="text-sm sm:text-base font-bold font-mono tabular-nums text-slate-900 mt-0.5 block truncate">
              {averageLatencyMs !== null ? `${averageLatencyMs} ms` : 'N/A'}
            </span>
          </div>
          <div className="p-2.5 rounded-xl bg-slate-50/70 border border-[#E5E7EB] min-w-0">
            <span className="text-[11px] text-slate-500 block truncate">Jitter</span>
            <span className="text-sm sm:text-base font-bold font-mono tabular-nums text-slate-900 mt-0.5 block truncate">
              {jitterMs !== null ? `${jitterMs} ms` : 'N/A'}
            </span>
          </div>
          <div className="p-2.5 rounded-xl bg-slate-50/70 border border-[#E5E7EB] min-w-0">
            <span className="text-[11px] text-slate-500 block truncate">Packet Loss</span>
            <span
              className={`text-sm sm:text-base font-bold font-mono tabular-nums mt-0.5 block truncate ${
                failedCount > 0 ? 'text-red-600' : 'text-slate-900'
              }`}
              title={`${failedCount} failed of ${totalCount} probes`}
            >
              {failureRatePercent}%{' '}
              <span className="text-[11px] font-normal text-slate-500">
                ({failedCount}/{totalCount})
              </span>
            </span>
          </div>
        </div>

        {/* Interactive Right-to-Left Scrolling Time-Series Graph (1:1 Responsive on Mobile & Desktop) */}
        <div className="mt-3.5" ref={chartWrapperRef}>
          <div className="flex items-center justify-between text-[11px] text-slate-500 mb-1.5">
            <span>HTTP RTT (ms) • Tap line to inspect</span>
            <span className="font-mono tabular-nums">
              {isRunning ? 'Live 5m' : 'Paused'}
            </span>
          </div>

          <div className="relative w-full bg-white border border-slate-200 rounded p-2 select-none">
            <svg
              ref={svgRef}
              width={svgWidth}
              height={svgHeight}
              viewBox={`0 0 ${svgWidth} ${svgHeight}`}
              className="w-full h-[236px] block overflow-hidden cursor-pointer touch-pan-y"
              role="img"
              aria-label="Network Connection Delay Time-Series Graph"
              onClick={handlePointerClick}
              onTouchStart={handleTouchSelect}
            >
              <defs>
                <clipPath id="network-delay-plot-clip">
                  <rect x={padLeft} y={padTop} width={plotWidth} height={plotHeight} />
                </clipPath>
              </defs>

              {/* Horizontal Gridlines at 0, 150, 300 (dashed reference), 450, 600 ms */}
              {Y_LEVELS.map((level) => {
                const y = getYForLatency(level);
                const isReference300 = level === 300;
                return (
                  <g key={level}>
                    <line
                      x1={padLeft}
                      y1={y}
                      x2={svgWidth - padRight}
                      y2={y}
                      stroke={isReference300 ? '#94A3B8' : '#E2E8F0'}
                      strokeWidth="1"
                      strokeDasharray={isReference300 ? '4 4' : undefined}
                    />
                    <text
                      x={padLeft - 6}
                      y={y + 3.5}
                      textAnchor="end"
                      className="fill-slate-500 font-mono text-[10px]"
                    >
                      {level} ms
                    </text>
                  </g>
                );
              })}

              {/* Left Y-axis & Bottom X-axis thin lines */}
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

              {/* Moving X-Axis Timestamp Labels */}
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
                      className="fill-slate-500 font-mono text-[10px]"
                    >
                      {formatClockTimestamp(tickMs)}
                    </text>
                  </g>
                );
              })}

              {/* Clipped Plot Area: Continuous Blue Line (NO circular data-point markers) */}
              <g clipPath="url(#network-delay-plot-clip)">
                {pathSegments.map((d, idx) => (
                  <path
                    key={idx}
                    d={d}
                    fill="none"
                    stroke="#2563EB"
                    strokeWidth="2"
                    strokeLinejoin="round"
                    strokeLinecap="round"
                  />
                ))}

                {/* Interactive Crosshair ONLY at Clicked Measurement */}
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
            </svg>

            {/* Click-Only Historical Popup */}
            {activeTooltipSample && activeTooltipX !== null && (
              <div
                style={{
                  left: `${tooltipLeftPercent}%`,
                  top: `${Math.max(8, Math.min(110, (activeTooltipY / svgHeight) * 140))}px`,
                  transform: 'translateX(-50%)',
                }}
                className="absolute z-20 bg-white border border-slate-200 rounded-md shadow-sm px-3.5 py-2.5 text-xs pointer-events-none min-w-[185px]"
              >
                <div className="font-mono tabular-nums font-semibold text-slate-900 pb-1.5 border-b border-slate-100">
                  {formatClockTimestamp(activeTooltipSample.timestampMs)}
                </div>
                <div className="mt-2 flex items-start justify-between gap-4">
                  <div className="flex items-start gap-2">
                    <span className="w-3 h-0.5 bg-[#2563EB] inline-block shrink-0 mt-2" />
                    <div>
                      <div className="font-medium text-slate-800 leading-tight">
                        Connection delay:
                      </div>
                      <div className="text-[11px] text-slate-500 mt-0.5">
                        Recommended: &lt;300 ms
                      </div>
                    </div>
                  </div>
                  <div className="font-mono tabular-nums font-bold text-slate-900 text-right leading-tight">
                    {activeTooltipSample.failed || activeTooltipSample.latencyMs === null ? (
                      'Failed'
                    ) : (
                      <>
                        <div>{activeTooltipSample.latencyMs}</div>
                        <div className="text-[11px] font-normal text-slate-600">ms</div>
                      </>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Section: explicit one-shot server speed test (8s download + 6s upload, bounded budgets) */}
      <div className="mt-4 pt-3.5 border-t border-slate-200 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-1.5">
            <Gauge className="w-4 h-4 text-[#2563EB] shrink-0" />
            <h3 className="text-xs sm:text-sm font-semibold text-slate-900">
              Server Speed Test
            </h3>
          </div>

          <span className="text-[11px] font-mono tabular-nums text-slate-500">
            {speedTest.phase === 'downloading'
              ? 'Testing download...'
              : speedTest.phase === 'uploading'
              ? 'Testing upload...'
              : speedTest.phase === 'cancelled'
              ? 'Cancelled'
              : speedTest.testedAtLabel
              ? `Updated ${speedTest.testedAtLabel}`
              : 'Ready (not run)'}
          </span>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-[10px] text-slate-500 leading-snug">
            Estimated speed to this server. Limited-data test: at most ~24 MB per run.
          </p>
          {speedTest.phase === 'downloading' || speedTest.phase === 'uploading' ? (
            <button
              type="button"
              onClick={cancelSpeedTest}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-rose-700 bg-rose-50 hover:bg-rose-100 border border-rose-200 rounded whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Square className="w-3 h-3 fill-current" />
              <span>Cancel test</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={startSpeedTest}
              disabled={cooldownRemainingMs > 0}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 rounded whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Play className="w-3 h-3 fill-current" />
              <span>
                {cooldownRemainingMs > 0
                  ? `Run again in ${Math.ceil(cooldownRemainingMs / 1000)}s`
                  : speedTest.testedAtLabel
                  ? 'Run again'
                  : 'Start speed test'}
              </span>
            </button>
          )}
        </div>

        {speedTest.error && (
          <p className="text-xs text-red-600">{speedTest.error}</p>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {/* Download Speed Card */}
          <div
            className={`rounded-xl border p-3.5 sm:p-4 transition-colors ${
              speedTest.phase === 'downloading'
                ? 'bg-blue-50/40 border-blue-200'
                : 'bg-slate-50 border-slate-200/80'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-slate-600 mb-1.5">
              <span className="inline-flex items-center gap-1.5 font-medium">
                <ArrowDown className="w-3.5 h-3.5 text-[#2563EB]" />
                <span>Download</span>
              </span>
              {speedTest.phase === 'downloading' && (
                <span className="text-[10px] font-mono font-semibold text-[#2563EB] uppercase">
                  Testing
                </span>
              )}
            </div>
            <div className="text-xl sm:text-2xl">
              <OdometerNumber
                value={speedTest.downloadMbps}
                decimals={2}
                suffix="Mbps"
              />
            </div>
          </div>

          {/* Upload Speed Card */}
          <div
            className={`rounded-xl border p-3.5 sm:p-4 transition-colors ${
              speedTest.phase === 'uploading'
                ? 'bg-emerald-50/40 border-emerald-200'
                : 'bg-slate-50 border-slate-200/80'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-slate-600 mb-1.5">
              <span className="inline-flex items-center gap-1.5 font-medium">
                <ArrowUp className="w-3.5 h-3.5 text-emerald-600" />
                <span>Upload</span>
              </span>
              {speedTest.phase === 'uploading' && (
                <span className="text-[10px] font-mono font-semibold text-emerald-600 uppercase">
                  Testing
                </span>
              )}
            </div>
            <div className="text-xl sm:text-2xl">
              <OdometerNumber
                value={speedTest.uploadMbps}
                decimals={2}
                suffix="Mbps"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
