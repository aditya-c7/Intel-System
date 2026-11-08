import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Cpu, Play, Square, Clock, ExternalLink, RefreshCw } from 'lucide-react';

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

const SYSTEM_LOAD_THEME: Record<
  DisplayPressureLevel,
  {
    circleBg: string;
    iconColor: string;
    needleAngleDeg: number;
    rawLabel: RawPressureState;
  }
> = {
  Normal: {
    circleBg: '#DCFCE7',
    iconColor: '#15803D',
    needleAngleDeg: -38,
    rawLabel: 'nominal',
  },
  Moderate: {
    circleBg: '#FDECC8',
    iconColor: '#B45309',
    needleAngleDeg: -16,
    rawLabel: 'fair',
  },
  High: {
    circleBg: '#FCD9BD',
    iconColor: '#C2410C',
    needleAngleDeg: 18,
    rawLabel: 'serious',
  },
  Heavy: {
    circleBg: '#FAD1D1',
    iconColor: '#B91C1C',
    needleAngleDeg: 42,
    rawLabel: 'critical',
  },
};

function SystemLoadGaugeIcon({
  level,
  size = 22,
}: {
  level: DisplayPressureLevel;
  size?: number;
}) {
  const theme = SYSTEM_LOAD_THEME[level];
  const maskId = `gauge-needle-cutout-${level.toLowerCase()}`;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
      className="block shrink-0"
    >
      <defs>
        {/* Creates the authentic small gap in the speedometer arch right around the needle tip */}
        <mask id={maskId}>
          <rect x="0" y="0" width="24" height="24" fill="white" />
          <g transform={`rotate(${theme.needleAngleDeg} 12 14)`}>
            <polygon points="9.7,4.2 14.3,4.2 13.1,10.5 10.9,10.5" fill="black" />
          </g>
        </mask>
      </defs>

      {/* Speedometer D-shape arch + flat baseline */}
      <path
        d="M 5.35 16.5 A 7.6 7.6 0 1 1 18.65 16.5 C 18.95 15.95 18.55 17.2 17.6 17.2 L 6.4 17.2 C 5.45 17.2 5.05 15.95 5.35 16.5 Z"
        stroke={theme.iconColor}
        strokeWidth="1.95"
        strokeLinecap="round"
        strokeLinejoin="round"
        mask={`url(#${maskId})`}
      />

      {/* Tapered gauge needle + center pivot */}
      <g transform={`rotate(${theme.needleAngleDeg} 12 14)`}>
        <path
          d="M 10.45 14 L 11.65 5.4 C 11.75 4.85 12.25 4.85 12.35 5.4 L 13.55 14 Z"
          fill={theme.iconColor}
        />
        <circle cx="12" cy="14" r="1.75" fill={theme.iconColor} />
      </g>
    </svg>
  );
}

function SystemLoadBadge({ level }: { level: DisplayPressureLevel }) {
  const theme = SYSTEM_LOAD_THEME[level];

  return (
    <div className="inline-flex items-center gap-3.5 select-none">
      <div
        className="w-10 h-10 rounded-full flex items-center justify-center shrink-0 transition-colors duration-300"
        style={{ backgroundColor: theme.circleBg }}
      >
        <SystemLoadGaugeIcon level={level} size={22} />
      </div>
      <div className="flex flex-col justify-center">
        <span className="text-[15px] font-semibold text-slate-900 leading-tight tracking-[-0.01em]">
          System load
        </span>
        <span className="text-[13px] font-normal text-slate-600 leading-snug mt-0.5">
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

  // Format main current load description according to the 7 distinct states
  const renderCurrentLoadValue = () => {
    if (status === 'Initializing') {
      return 'Initializing observer...';
    }
    if (status === 'Monitoring' && !latestSample) {
      return 'Waiting for first CPU pressure observation';
    }
    if ((status === 'Live' || status === 'Paused' || status === 'Monitoring') && latestSample) {
      return `${latestSample.displayLevel} (${latestSample.rawState})`;
    }
    if (status === 'Paused') {
      return 'Paused (tab inactive or stopped)';
    }
    if (status === 'Blocked') {
      return insideIframe
        ? 'Blocked in preview iframe (open in direct tab)'
        : 'Permissions Policy rejected access';
    }
    if (status === 'Unsupported') {
      return 'CPU source unavailable';
    }
    return errorDetail || 'Initialization error';
  };

  const currentBadgeLevel: DisplayPressureLevel = latestSample
    ? latestSample.displayLevel
    : 'Normal';

  return (
    <div className="bg-white border border-[#E5E7EB] rounded-2xl p-4 sm:p-6 flex flex-col justify-between">
      <div>
        {/* Header */}
        <div className="flex flex-wrap items-center justify-between gap-3 pb-3.5 border-b border-[#E5E7EB]">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-[#2563EB] shrink-0" />
            <h2 className="text-sm font-semibold text-slate-900">
              CPU Activity
            </h2>
          </div>

          <div className="flex items-center gap-2.5">
            <span className="text-xs font-mono text-slate-600">
              Status:{' '}
              <strong
                className={
                  status === 'Live' || status === 'Monitoring'
                    ? 'text-emerald-700'
                    : status === 'Paused' || status === 'Initializing'
                    ? 'text-amber-700'
                    : 'text-red-600'
                }
              >
                {renderStatusText()}
              </strong>
            </span>

            {status === 'Blocked' || status === 'Error' ? (
              <button
                type="button"
                onClick={() => startCpuObservation(true)}
                className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 rounded whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Retry</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setUserEnabled((prev) => !prev)}
                disabled={status === 'Unsupported'}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 rounded disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
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

        {/* Summary Metrics Row with Single Active System Load Badge */}
        <div className="grid grid-cols-2 sm:grid-cols-4 items-center gap-3 sm:gap-4 py-3.5 border-b border-slate-100 text-xs">
          <div className="flex items-center">
            <SystemLoadBadge level={currentBadgeLevel} />
          </div>

          <div>
            <span className="text-slate-500 block">Current CPU State</span>
            <span className="text-sm sm:text-base font-bold text-slate-900 mt-0.5 block">
              {renderCurrentLoadValue()}
            </span>
          </div>

          <div>
            <span className="text-slate-500 inline-flex items-center gap-1">
              <Clock className="w-3 h-3 text-slate-400" /> Last Observation
            </span>
            <span className="text-sm sm:text-base font-bold font-mono tabular-nums text-slate-900 mt-0.5 block">
              {latestSample ? formatClockTimestamp(latestSample.timestampMs) : 'Waiting...'}
            </span>
            {isStale && timeSinceLastObservationMs !== null && (
              <span className="text-[11px] font-mono text-amber-700 block mt-0.5">
                {Math.round(timeSinceLastObservationMs / 1000)}s ago (state held)
              </span>
            )}
          </div>

          <div>
            <span className="text-slate-500 block">Recorded Observations</span>
            <span className="text-sm sm:text-base font-bold font-mono tabular-nums text-slate-900 mt-0.5 block">
              {samples.length} {samples.length === 1 ? 'record' : 'records'}
            </span>
          </div>
        </div>

        {/* Notice if blocked specifically by embedded preview iframe */}
        {status === 'Blocked' && insideIframe && (
          <div className="mt-3 px-3 py-2 bg-amber-50 border border-amber-200 rounded text-xs text-amber-900 flex items-center justify-between gap-2">
            <span>
              The outer preview iframe does not delegate <code className="font-mono">compute-pressure</code>. Open the app URL directly in a browser tab (<code className="font-mono">InsideIframe: false</code>) for live CPU observations.
            </span>
            <a
              href={typeof window !== 'undefined' ? window.location.href : '#'}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-amber-900 bg-white border border-amber-300 rounded hover:bg-amber-100 shrink-0"
            >
              <span>Open Tab</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        )}

        {/* Step-Line Time-Series Graph (1:1 Responsive on Mobile & Desktop) */}
        <div className="mt-3.5" ref={chartWrapperRef}>
          <div className="flex items-center justify-between text-[11px] text-slate-500 mb-1.5">
            <span>CPU Pressure (Normal to Heavy) / Click line to inspect time</span>
            <span className="font-mono tabular-nums">
              {status === 'Live'
                ? 'Live 5m'
                : status === 'Monitoring'
                ? 'Waiting for first observation'
                : status}
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
              aria-label="System CPU Pressure Step-Line Time-Series Graph"
              onClick={handlePointerClick}
              onTouchStart={handleTouchSelect}
            >
              <defs>
                <clipPath id="cpu-pressure-plot-clip">
                  <rect x={padLeft} y={padTop - 2} width={plotWidth} height={plotHeight + 4} />
                </clipPath>
              </defs>

              {/* Horizontal Gridlines & Labels for Normal, Moderate, High, Heavy */}
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
                      className="fill-slate-500 font-mono text-[10px]"
                    >
                      {level}
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

              {/* Clipped Plot Area: Blue Step-Line of Actual Observations */}
              <g clipPath="url(#cpu-pressure-plot-clip)">
                {stepPath && (
                  <path
                    d={stepPath}
                    fill="none"
                    stroke="#2563EB"
                    strokeWidth="2"
                    strokeLinejoin="miter"
                    strokeLinecap="butt"
                  />
                )}

                {/* Interactive Crosshair at Clicked Actual Observation */}
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

              {/* Status Overlay inside Chart when no observations have arrived yet or on error */}
              {visibleSamples.length === 0 && (
                <text
                  x={padLeft + plotWidth / 2}
                  y={padTop + plotHeight / 2}
                  textAnchor="middle"
                  className="fill-slate-500 font-sans text-[11px] font-medium"
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

            {/* Click-Only Historical Tooltip */}
            {activeTooltipSample && activeTooltipX !== null && (
              <div
                style={{
                  left: `${tooltipLeftPercent}%`,
                  top: `${Math.max(8, Math.min(115, (activeTooltipY / svgHeight) * 140))}px`,
                  transform: 'translateX(-50%)',
                }}
                className="absolute z-20 bg-white border border-slate-200 rounded shadow-sm px-3 py-2 text-xs pointer-events-none min-w-[175px]"
              >
                <div className="font-mono tabular-nums font-semibold text-slate-800 pb-1 border-b border-slate-100">
                  {formatClockTimestamp(activeTooltipSample.timestampMs)}
                </div>
                <div className="flex items-center gap-2 mt-1.5">
                  <span className="w-3 h-0.5 bg-[#2563EB] inline-block shrink-0" />
                  <span className="text-slate-600">CPU state:</span>
                  <span className="font-semibold text-slate-900 ml-auto">
                    {activeTooltipSample.displayLevel} ({activeTooltipSample.rawState})
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Concise Status Footer */}
      <div className="mt-4 pt-3.5 border-t border-slate-200 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
        <span>nominal: Normal / fair: Moderate / serious: High / critical: Heavy</span>
        <span className="font-mono shrink-0">
          {httpPolicyHeader
            ? `Policy: ${httpPolicyHeader}`
            : 'PressureObserver ("cpu", 1000ms)'}
        </span>
      </div>
    </div>
  );
}
