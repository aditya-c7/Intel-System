import type { IntelVisitorResponse } from '../types/visitor';

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
    detail: data.location.isLocationVerified ? 'Verified geolocation' : 'IP derived location',
  });

  const incognito = Boolean(
    signals.isIncognito ?? signals.incognito ?? signals.privateMode ?? signals.incognitoLikely
  );
  rows.push({
    key: 'incognito',
    label: 'Incognito Mode',
    status: incognito ? 'You are incognito \u{1F576}' : 'Not detected',
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

  const vpn = Boolean(signals.vpnSuspected);
  const vpnMethodCount = Array.isArray(signals.vpnReasons) ? signals.vpnReasons.length : 0;
  rows.push({
    key: 'vpn',
    label: 'VPN',
    status: vpn ? 'You are using a VPN \u{1F310}' : 'Not detected',
    triggered: vpn,
    detail: vpnMethodCount > 1 ? `${vpnMethodCount} matching network methods` : signals.vpnReasons?.[0],
  });

  const tampering = Boolean(data.tampering ?? signals.tampering);
  rows.push({
    key: 'tampering',
    label: 'Browser Tampering',
    status: tampering ? 'Yes' : 'Not detected',
    triggered: tampering,
    detail: data.tamperingDetails?.devtools_device_emulation
      ? 'DevTools device emulation'
      : data.tamperingDetails?.anti_detect_browser
      ? 'Anti-detect browser'
      : data.tamperingDetails?.reasons?.[0],
  });

  const developerTools = Boolean(signals.developerTools);
  rows.push({
    key: 'developerTools',
    label: 'Developer Tools',
    status: developerTools ? 'Yes' : 'Not detected',
    triggered: developerTools,
  });

  const virtualMachine = Boolean(
    signals.isVirtualMachine || signals.cloudOrMaskedGpu || signals.emulatorDetected
  );
  rows.push({
    key: 'virtualMachine',
    label: 'Virtual Machine',
    status: virtualMachine ? 'Yes \u2601\uFE0F\u{1F4BB}' : 'Not detected',
    triggered: virtualMachine,
    detail: signals.emulatorReason || signals.vmReason,
  });

  const privacySettings = Boolean(
    signals.privacySettings || signals.isTorBrowserClient || signals.privacyProtected
  );
  rows.push({
    key: 'privacySettings',
    label: 'Privacy Settings',
    status: privacySettings ? 'Yes \u{1F648}\u{1F4BB}' : 'Not detected',
    triggered: privacySettings,
    detail: signals.privacyDetail || (signals.isTorBrowserClient ? 'Tor Browser RFP' : undefined),
  });

  const torNode = Boolean(signals.torExitNode);
  const blocklisted = Boolean(signals.ipBlocklisted);
  rows.push({
    key: 'ipBlocklist',
    label: 'IP Blocklist',
    status: torNode
      ? 'Your IP is a Tor exit node \u{1F9C5}'
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
    detail: proxy ? signals.networkType : undefined,
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

  // Active call: pruned unless the runtime can observe call state at all.
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

  const suspectScore = Number(data.suspectScore100 ?? 0);
  rows.push({
    key: 'suspectScore',
    label: 'Suspect Score',
    status: String(suspectScore),
    triggered: suspectScore >= 50,
    tone: suspectScore >= 50 ? 'trigger' : suspectScore > 0 ? 'neutral' : 'clean',
  });

  const proximityStatus = data.location.isLocationVerified
    ? `${city || region || country || 'Verified zone'} ${
        data.location.latitude !== null && data.location.longitude !== null
          ? `(${data.location.latitude.toFixed(2)}, ${data.location.longitude.toFixed(2)})`
          : ''
      }`.trim()
    : 'Collecting location...';
  rows.push({
    key: 'proximity',
    label: 'Proximity Detection',
    status: proximityStatus,
    triggered: false,
    tone: data.location.isLocationVerified ? 'clean' : 'neutral',
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
