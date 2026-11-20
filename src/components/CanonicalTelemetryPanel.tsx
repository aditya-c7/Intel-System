/**
 * Phase 7 — canonical telemetry panels.
 *
 * Every value rendered here is read from the single `CanonicalView` resolved by
 * `resolveCanonical`, the same object the Event JSON inspector prints. Nothing in
 * this file derives a score, tier or verdict from raw signals. Until the Worker
 * supplies the canonical axes, each panel shows an explicit honest state.
 */

import {
  Globe2,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { CanonicalView } from './canonical';
import { networkAxes } from './canonical';

const CARD = 'bg-white border border-[#E5E7EB] rounded-2xl p-4 sm:p-6';
const TITLE = 'flex items-center gap-2 text-sm sm:text-base font-semibold text-slate-900';
const KEY = 'block text-[11px] text-slate-500';
const VALUE = 'block text-xs sm:text-sm font-semibold text-[#111827] break-words leading-snug mt-0.5';

function Scalar({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div className="p-3 rounded-xl bg-slate-50/70 border border-[#E5E7EB] min-w-0">
      <span className={KEY}>{label}</span>
      <span className={VALUE} title={detail ?? value}>
        {value}
      </span>
      {detail && <span className="block text-[10px] text-slate-400 mt-0.5">{detail}</span>}
    </div>
  );
}

/** Exact Verdict State Machine headline + human corroboration. */
export function VerdictBannerPanel({ view }: { view: CanonicalView }) {
  const tamperingDetected = view.tamperingReasons.length > 0;
  const headline = view.verdictTier ?? 'Awaiting canonical verdict from Worker';
  return (
    <section className={CARD} aria-label="Verdict state">
      <div className="flex items-center justify-between gap-3 pb-3.5 border-b border-[#E5E7EB] flex-wrap">
        <div className="flex items-center gap-2">
          {tamperingDetected ? (
            <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0" />
          ) : (
            <ShieldCheck className="w-4 h-4 text-[#2563EB] shrink-0" />
          )}
          <h2 className={TITLE}>Verdict State Machine</h2>
        </div>
        <span
          className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold ${
            tamperingDetected
              ? 'border-rose-200 bg-rose-50 text-rose-700'
              : 'border-slate-200 bg-slate-50 text-slate-600'
          }`}
        >
          {tamperingDetected ? 'Browser Tampering: Detected' : 'Browser Tampering: Not detected'}
        </span>
      </div>
      <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-3">
        <Scalar label="Verdict headline" value={headline} detail="Exact canonical verdict tier" />
        <Scalar
          label="Human corroboration"
          value={view.humanCorroboration === null ? '—' : String(view.humanCorroboration)}
          detail="0 or 1, from the canonical automation axis"
        />
        <Scalar
          label="Calibration"
          value={view.calibrationStatus === 'calibrated' ? 'Calibrated' : 'Uncalibrated'}
          detail="Identification confidence calibration gate"
        />
      </div>
    </section>
  );
}

/** Four orthogonal network axes plus the RDAP netblock comparison. */
export function NetworkAxesPanel({ view }: { view: CanonicalView }) {
  const axes = networkAxes(view);
  return (
    <section className={CARD} aria-label="Network provenance">
      <div className="flex items-center gap-2 pb-3.5 border-b border-[#E5E7EB]">
        <Globe2 className="w-4 h-4 text-indigo-600 shrink-0" />
        <h2 className={TITLE}>Network Provenance (orthogonal axes)</h2>
      </div>
      <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Scalar label="Hosting / datacenter ASN" value={axes.hosting} />
        <Scalar
          label="RDAP netblock org"
          value={axes.rdap}
          detail={axes.rdapDiffers ? 'Differs from BGP ASN org' : undefined}
        />
        <Scalar label="VPN status" value={axes.vpn} />
        <Scalar label="Proxy rotation" value={axes.proxy} />
        <Scalar label="Timezone discrepancy" value={axes.timezone} />
      </div>
    </section>
  );
}

