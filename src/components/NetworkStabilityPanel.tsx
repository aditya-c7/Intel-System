import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Activity, Wifi, Play, Square } from 'lucide-react';

interface PingSample {
  id: number;
  timestampMs: number;
  latencyMs: number | null; // null indicates a failed request (produces a gap in the continuous line)
  failed: boolean;
}

const Y_LEVELS = [0, 150, 300, 450, 600] as const;
const MAX_Y_MS = 600;
const FIVE_MINUTES_MS = 5 * 60 * 1000; // 300,000 ms rolling five-minute timeline
const SAMPLE_INTERVAL_MS = 5000; // 5s visible RTT measurement interval (serialized, configurable)
const MAX_MONITOR_DURATION_MS = 15 * 60 * 1000; // auto-pause live monitoring after 15 minutes
const MONITOR_LEADER_KEY = 'intel_rtt_leader_v1'; // same-origin tab lease (not a security boundary)
const MONITOR_LEADER_TTL_MS = 12000; // lease lifetime; renews on every probe (5s cadence)
const MONITOR_CHANNEL_NAME = 'intel_rtt_samples_v1'; // share measured samples with mirroring tabs

interface MonitorLease {
  id: string;
  expiresAtMs: number;
}

function readMonitorLease(): MonitorLease | null {
  try {
    const raw = window.localStorage.getItem(MONITOR_LEADER_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<MonitorLease>;
    if (typeof parsed.id !== 'string' || typeof parsed.expiresAtMs !== 'number') return null;
    return { id: parsed.id, expiresAtMs: parsed.expiresAtMs };
  } catch {
    return null;
  }
}

function writeMonitorLease(id: string): void {
  try {
    window.localStorage.setItem(
      MONITOR_LEADER_KEY,
      JSON.stringify({ id, expiresAtMs: Date.now() + MONITOR_LEADER_TTL_MS })
    );
  } catch {
    // Storage unavailable: polling continues without deduplication rather than deadlocking.
  }
}

function releaseMonitorLease(id: string): void {
  try {
    const lease = readMonitorLease();
    if (lease?.id === id) window.localStorage.removeItem(MONITOR_LEADER_KEY);
  } catch {
    // Ignore storage failures.
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
  const [monitorAutoPaused, setMonitorAutoPaused] = useState<boolean>(false);
  const [isMonitorLeader, setIsMonitorLeader] = useState<boolean>(true);
  const tabIdRef = useRef<string>(
    `tab_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`
  );

  const sampleCounterRef = useRef<number>(0);
  const latestRttMsRef = useRef<number>(180);
  const recentRttsRef = useRef<number[]>([]);
  const pingInFlightRef = useRef<boolean>(false);
  // Ref mirrors isOnline so the probe loop can consult measured connectivity synchronously
  // (a falsely-offline navigator.onLine must never pause monitoring forever)
  const isOnlineRef = useRef<boolean>(typeof navigator !== 'undefined' ? navigator.onLine : true);
  const chartWrapperRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
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
        if (!isOnlineRef.current) {
          // Explicitly offline: pause probing (and release the tab lease) until connectivity returns.
          releaseMonitorLease(tabIdRef.current);
          await new Promise<void>((resolve) => {
            nextProbeTimer = setTimeout(resolve, 1000);
          });
          continue;
        }

        // One tab per origin performs the probes. The lease expires on its own, so closing a
        // leader recovers automatically; this is a quota safeguard, not a security boundary.
        const lease = readMonitorLease();
        if (lease && lease.id !== tabIdRef.current && lease.expiresAtMs > Date.now()) {
          setIsMonitorLeader(false);
          await new Promise<void>((resolve) => {
            nextProbeTimer = setTimeout(resolve, 1000);
          });
          continue;
        }
        writeMonitorLease(tabIdRef.current);
        setIsMonitorLeader(true);

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
      releaseMonitorLease(tabIdRef.current);
    };
  }, [isRunning, executePingProbe]);

  // Mirroring tabs append the leader's measured samples so every open tab shows the same graph
  // without issuing duplicate ping requests.
  useEffect(() => {
    if (!isRunning || typeof BroadcastChannel === 'undefined') return;
    const channel = new BroadcastChannel(MONITOR_CHANNEL_NAME);
    channel.onmessage = (event: MessageEvent) => {
      const payload = event.data as { owner?: string; sample?: PingSample } | null;
      if (!payload?.sample || payload.owner === tabIdRef.current) return;
      const incoming = payload.sample;
      setSamples((prev) =>
        prev.some((sample) => sample.id === incoming.id && sample.timestampMs === incoming.timestampMs)
          ? prev
          : [...prev, incoming].slice(-600)
      );
    };
    return () => channel.close();
  }, [isRunning]);

  const broadcastedSampleRef = useRef<string>('');
  useEffect(() => {
    if (!isRunning || typeof BroadcastChannel === 'undefined') return;
    const latest = samples[samples.length - 1];
    if (!latest) return;
    const lease = readMonitorLease();
    if (!lease || lease.id !== tabIdRef.current || lease.expiresAtMs < Date.now()) return;
    const signature = `${latest.id}:${latest.timestampMs}`;
    if (broadcastedSampleRef.current === signature) return;
    broadcastedSampleRef.current = signature;
    const channel = new BroadcastChannel(MONITOR_CHANNEL_NAME);
    channel.postMessage({ owner: tabIdRef.current, sample: latest });
    channel.close();
  }, [samples, isRunning]);

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

            {isRunning && (
              <span
                className="text-[10px] font-mono text-slate-500"
                title="Same-origin tabs share RTT polling through a leader lease; this is not a server security boundary."
              >
                {isMonitorLeader ? 'Probing this tab' : 'Mirroring another tab'}
              </span>
            )}

            <button
              type="button"
              onClick={toggleMonitor}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 rounded whitespace-nowrap shrink-0 cursor-pointer"
              title={
                isRunning
                  ? 'Stop live RTT monitoring'
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
    </div>
  );
}
