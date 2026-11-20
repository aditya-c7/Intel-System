import type { IntelVisitorResponse } from '../types/visitor';
import { isSwiftShader, SWIFTSHADER_LABEL } from './canonical';

/**
 * Smart Signals grid.
 *
 * Renders one deterministic row per signal instead of the legacy four broad risk cards.
 * Clean states use the soft mint treatment (#E6F4EA fill, #81C995 accent) and triggered
 * states use the red treatment (#FCE8E6 fill, #D93025 accent); the row label stays neutral.
 * Signals whose platform capability is absent are pruned from the DOM entirely.
 */

export interface SmartSignalRowData {
  key: string;
  label: string;
  status: string;
  triggered: boolean;
  /** Muted/amber state for informational verdicts that are not threats of their own. */
  tone?: 'clean' | 'trigger' | 'neutral';
  detail?: string;
  /** Row links to the raw event JSON inspector. */
  jsonAnchor?: boolean;
}

const CLEAN = {
  box: 'bg-[#E6F4EA] border-[#81C995]/60 text-[#137333]',
};
const TRIGGER = {
  box: 'bg-[#FCE8E6] border-[#D93025]/40 text-[#D93025]',
};
const NEUTRAL = {
  box: 'bg-[#F8FAFC] border-[#E5E7EB] text-[#475569]',
};

function toneClass(tone: SmartSignalRowData['tone']): string {
  if (tone === 'trigger') return TRIGGER.box;
  if (tone === 'neutral') return NEUTRAL.box;
  return CLEAN.box;
}

/** Short, human-readable bot verdict. Never leaks raw user-agent internals. */
function botStatus(data: IntelVisitorResponse): { status: string; triggered: boolean; detail?: string } {
  const signals = data.securitySignals;
  const subtype = signals.botSubtype;
  if (!signals.isBot && subtype !== 'bad_bot' && subtype !== 'good_bot' && subtype !== 'ai_agent') {
    return { status: 'Not detected', triggered: false };
  }
  if (subtype === 'good_bot') {
    return { status: 'Verified crawler', triggered: false, detail: signals.botProvider };
  }
  if (subtype === 'ai_agent') {
    return { status: 'AI agent', triggered: true, detail: signals.botProvider };
  }
  if (signals.botSubtype === 'bad_bot') {
    return {
      status: 'You are a bot',
      triggered: true,
      detail: signals.botReason || signals.botProvider,
    };
  }
  return { status: 'You are a bot', triggered: true, detail: signals.botReason };
}

export function buildSmartSignalRows(data: IntelVisitorResponse): SmartSignalRowData[] {
  const signals = data.securitySignals;
  const rows: SmartSignalRowData[] = [];

  const city = data.location.city && data.location.city !== 'Unavailable' ? data.location.city : '';
  const region =
    data.location.region && data.location.region !== 'Unavailable' ? data.location.region : '';
  const country =
    data.location.country && data.location.country !== 'Unavailable' ? data.location.country : '';
  const geoParts = [city, region, country].filter(Boolean);
  rows.push({
    key: 'geolocation',
    label: 'Geolocation',
    status: geoParts.length > 0 ? geoParts.join(', ') : 'Unavailable',
    triggered: false,
    tone: geoParts.length > 0 ? 'clean' : 'neutral',
    detail: 'IP Geolocation Estimate',
  });

  const incognito = Boolean(
    signals.isIncognito ?? signals.incognito ?? signals.privateMode ?? signals.incognitoLikely
  );
  rows.push({
    key: 'incognito',
    label: 'Incognito Mode',
    status: incognito ? 'You are incognito' : 'Not detected',
    triggered: incognito,
    detail: signals.incognitoMethod,
  });

  const bot = botStatus(data);
  rows.push({
    key: 'bot',
    label: 'Bot',
    status: bot.status,
    triggered: bot.triggered,
    detail: bot.detail,
  });

  // The server's `vpnMethods` object is the single source of truth for both the method count
  // and the status label — the same object the event JSON prints, so this tile can never claim
  // more methods (or a different verdict) than `#raw-json`. A plain datacenter / hosting ASN is
  // explicitly NOT a commercial VPN: only the server's `public_vpn` method earns that label.
  const methods = signals.vpnMethods;
  const vpnMethodCount = methods ? Object.values(methods).filter(Boolean).length : 0;
  const vpnDetected = Boolean(vpnMethodCount > 0 || signals.vpnSuspected);
  const datacenterHosting = Boolean(signals.datacenterAsn ?? signals.isDatacenterOrHosting);
  let vpnStatus = 'Not detected';
  if (vpnDetected) {
    if (methods?.public_vpn) vpnStatus = 'Commercial VPN';
    else if (methods?.relay) vpnStatus = 'Tor exit / relay';
    else if (datacenterHosting) vpnStatus = 'Datacenter / hosting';
    else if (methods?.timezone_mismatch) vpnStatus = 'Timezone mismatch';
  }
  rows.push({
    key: 'vpn',
    label: 'VPN',
    status: vpnStatus,
    triggered: vpnDetected,
    detail: vpnMethodCount > 1 ? `${vpnMethodCount} matching network methods` : signals.vpnReasons?.[0],
  });

  const tampering = Boolean(data.tampering ?? signals.tampering);
  rows.push({
    key: 'tampering',
    label: 'Browser Tampering',
    status: tampering ? 'Detected' : 'Not detected',
    triggered: tampering,
    detail: data.tamperingDetails?.devtools_device_emulation
      ? 'DevTools device emulation'
      : data.tamperingDetails?.anti_detect_browser
      ? 'Anti-detect browser'
      : data.tamperingDetails?.reasons?.[0],
  });

  // DevTools is reported only when the canonical inspector state verifies an actively docked
  // debugger. A bare CDP bridge (automation_protocol_attached) is informational, not proof.
  const envelopeAutomation = (
    data as unknown as {
      envelope?: { automation?: { inspector_state?: string } };
    }
  ).envelope?.automation;
  const developerTools = envelopeAutomation?.inspector_state === 'devtools_active_verified';
  rows.push({
    key: 'developerTools',
    label: 'Developer Tools',
    status: developerTools ? 'Yes' : 'Not detected',
    triggered: developerTools,
  });

  // A software rasterizer is not proof of a VM: SwiftShader is reported honestly as
  // software-rendered graphics instead of being stretched into a "Yes" VM verdict.
  const swiftShader = isSwiftShader(data.hardwareSignals?.gpuRenderer);
  const virtualMachine = Boolean(
    signals.isVirtualMachine || signals.cloudOrMaskedGpu || signals.emulatorDetected
  );
  rows.push({
    key: 'virtualMachine',
    label: 'Virtual Machine',
    status: swiftShader
      ? 'Software-rendered (not proven VM)'
      : virtualMachine
      ? 'Yes'
      : 'Not detected',
    triggered: !swiftShader && virtualMachine,
    tone: swiftShader ? 'neutral' : undefined,
    detail: swiftShader ? SWIFTSHADER_LABEL : signals.emulatorReason || signals.vmReason,
  });

  const privacySettings = Boolean(
    signals.privacySettings || signals.isTorBrowserClient || signals.privacyProtected
  );
  rows.push({
    key: 'privacySettings',
    label: 'Privacy Settings',
    status: privacySettings ? 'Yes' : 'Not detected',
    triggered: privacySettings,
    detail: signals.privacyDetail || (signals.isTorBrowserClient ? 'Tor Browser RFP' : undefined),
  });

  const torNode = Boolean(signals.torExitNode);
  const blocklisted = Boolean(signals.ipBlocklisted);
  rows.push({
    key: 'ipBlocklist',
    label: 'IP Blocklist',
    status: torNode
      ? 'Your IP is a Tor exit node'
      : blocklisted
      ? 'Your IP is blocklisted'
      : 'Not detected',
    triggered: torNode || blocklisted,
    detail: torNode ? signals.torOperator : blocklisted ? signals.ipBlocklistReasons?.[0] : undefined,
  });

  const proxy = Boolean(
    (signals as unknown as { proxyDetected?: boolean }).proxyDetected ||
      (signals.networkType === 'VPN / Proxy Relay' && !signals.vpnSuspected)
  );
  rows.push({
    key: 'proxy',
    label: 'Proxy Detection',
    status: proxy ? 'Yes' : 'Not detected',
    triggered: proxy,
    detail: proxy ? signals.proxyReasons?.[0] || signals.networkType : undefined,
  });

  const highActivity = Boolean(data.highActivityDevice ?? signals.highActivityDevice);
  rows.push({
    key: 'highActivityDevice',
    label: 'High-Activity Device',
    status: highActivity ? 'Yes' : 'Not detected',
    triggered: highActivity,
    detail: data.velocity
      ? `${data.velocity.events['24_hours']} events in 24 hours`
      : undefined,
  });

  const rare = Boolean(data.rareDevice ?? signals.rareDevice);
  rows.push({
    key: 'rareDevice',
    label: 'Rare Device',
    status: rare ? 'Yes' : 'Not detected',
    triggered: rare,
    detail: data.rareDevicePercentileBucket
      ? `Hardware rarity ${data.rareDevicePercentileBucket}`
      : undefined,
  });

  // Active call state is observable only in runtimes that expose it; otherwise the row is
  // pruned from the grid entirely instead of advertising an unmeasurable capability.
  const activeCallSupported = Boolean(data.activeCallSupported ?? signals.activeCallSupported);
  if (activeCallSupported) {
    const activeCall = Boolean(data.activeCall ?? signals.activeCall);
    rows.push({
      key: 'activeCall',
      label: 'Active Call Detection',
      status: activeCall ? 'Yes' : 'Not detected',
      triggered: activeCall,
      detail: signals.activeCallReasons?.[0],
    });
  }

  const velocity = data.velocity;
  const velocityStatus = velocity
    ? `${velocity.distinct_ip['24_hours']} IP${
        velocity.distinct_ip['24_hours'] === 1 ? '' : 's'
      }, ${velocity.distinct_linked_id['24_hours']} Linked ID${
        velocity.distinct_linked_id['24_hours'] === 1 ? '' : 's'
      } in the past 24 hours`
    : 'Collecting persistence windows';
  rows.push({
    key: 'velocity',
    label: 'Velocity Signals',
    status: velocityStatus,
    triggered: false,
    tone: 'clean',
  });

  const suspectScore = Math.max(
    0,
    Math.min(10, Number(data.suspectScore ?? data.securitySignals?.suspectScore ?? 0) || 0)
  );
  rows.push({
    key: 'suspectScore',
    label: 'Suspect Score',
    status: `${suspectScore}/10`,
    triggered: suspectScore >= 5,
    tone: suspectScore >= 5 ? 'trigger' : suspectScore > 0 ? 'neutral' : 'clean',
  });

  // Fix 5 — the server always computes the metro-zone geohash synchronously, so this tile
  // never waits on a browser geolocation callback. IP coordinates are never printed here;
  // the tile reports an IP-only zone estimate when no finer metro zone was resolved.
  const proximityResolved = Boolean(data.proximity?.resolved);
  const proximityStatus =
    data.proximity?.zone_label ||
    (data.location.isLocationVerified
      ? `${city || region || country || 'Verified zone'}`
      : 'Zone Unresolved (IP-only)');
  rows.push({
    key: 'proximity',
    label: 'Proximity Detection',
    status: proximityStatus,
    triggered: false,
    tone: proximityResolved ? 'clean' : 'neutral',
  });

  rows.push({
    key: 'rawDeviceAttributes',
    label: 'Raw Device Attributes',
    status: 'See the JSON below',
    triggered: false,
    tone: 'neutral',
    jsonAnchor: true,
  });

  return rows;
}

export function SmartSignalsGrid({ data }: { data: IntelVisitorResponse }) {
  const rows = buildSmartSignalRows(data);

  return (
    <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-2">
      {rows.map((row) => {
        const content = (
          <>
            <div className="min-w-0">
              <span className="block text-[11px] font-medium text-slate-500">{row.label}</span>
              {row.detail && (
                <span className="block text-[10px] text-slate-400 truncate" title={row.detail}>
                  {row.detail}
                </span>
              )}
            </div>
            <span
              className={`inline-flex items-center justify-end text-right max-w-[62%] text-[11px] font-mono font-semibold px-2 py-1 rounded-md border leading-snug shrink-0 ${toneClass(
                row.tone ?? (row.triggered ? 'trigger' : 'clean')
              )}`}
            >
              {row.status}
            </span>
          </>
        );

        return row.jsonAnchor ? (
          <a
            key={row.key}
            href="#raw-json"
            className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg border border-[#E5E7EB] bg-[#F8FAFC] hover:bg-slate-100 transition-colors"
          >
            {content}
          </a>
        ) : (
          <div
            key={row.key}
            className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg border border-[#E5E7EB] bg-[#F8FAFC]"
          >
            {content}
          </div>
        );
      })}
    </div>
  );
}
