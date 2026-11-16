import { useEffect, useMemo, useState, useTransition } from 'react';
import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  Database,
  FileText,
  Globe2,
  RefreshCw,
  Shield,
  ShieldCheck,
} from 'lucide-react';
import type { AgentVerdict } from '../lib/agent-probe';
import { startIntelAgentProbe } from '../lib/agent-probe';

/* -------------------------------------------------------------------------- */
/* Local analytics payload types (server response is treated as untrusted)     */
/* -------------------------------------------------------------------------- */

interface Summary {
  total_requests: number;
  allowed_requests: number;
  unsuccessful_requests: number;
  total_bytes: number;
  markdown_served_count: number;
  robots_violations_count: number;
}

interface CrawlerRow {
  bot_id: string;
  bot_display_name: string;
  operator: string;
  cf_detection_id: string;
  legacy_category: string;
  behavior: string;
  operator_label: string;
  verification_status: string;
  verification_method: string;
  total_requests: number;
  allowed_requests: number;
  unsuccessful_requests: number;
  data_transfer_bytes: number;
  robots_violations: number;
  last_seen_ms: number;
}

interface OperatorRow {
  operator: string;
  total_requests: number;
  allowed_requests: number;
  unsuccessful_requests: number;
  data_transfer_bytes: number;
  referrals: number;
}

interface StatusDistribution {
  status_2xx: number;
  status_3xx: number;
  status_4xx: number;
  status_403_blocked: number;
  status_402_charged: number;
  status_5xx: number;
}

interface UriPatternRow {
  uri?: string;
  pattern?: string;
  path?: string;
  requests?: number;
  count?: number;
  total_requests?: number;
  bytes?: number;
  data_transfer_bytes?: number;
  [key: string]: unknown;
}

interface ViolationRow {
  bot_id?: string;
  bot_display_name?: string;
  operator?: string;
  path?: string;
  uri?: string;
  user_agent?: string;
  details?: string;
  reason?: string;
  timestamp_ms?: number;
  [key: string]: unknown;
}

interface ZoneConfig {
  policy_search?: string;
  policy_agent?: string;
  policy_training?: string;
  [key: string]: unknown;
}

interface AnalyticsPayload {
  summary?: Partial<Summary>;
  crawlers?: CrawlerRow[];
  operators?: OperatorRow[];
  statusDistribution?: Partial<StatusDistribution>;
  status_distribution?: Partial<StatusDistribution>;
  uriPatterns?: UriPatternRow[];
  uri_patterns?: UriPatternRow[];
  violations?: ViolationRow[];
  zoneConfig?: ZoneConfig;
  zone_config?: ZoneConfig;
  liveRobotsTxt?: string;
  live_robots_txt?: string;
  [key: string]: unknown;
}

interface MarkdownPlaygroundResult {
  markdown?: string;
  content_signal?: string;
  contentSignal?: string;
  headers?: Record<string, string>;
  [key: string]: unknown;
}

type TabKey = 'overview' | 'crawlers' | 'metrics' | 'directives' | 'markdown';

const TABS: { key: TabKey; label: string }[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'crawlers', label: 'Crawlers' },
  { key: 'metrics', label: 'Metrics' },
  { key: 'directives', label: 'Directives' },
  { key: 'markdown', label: 'Markdown' },
];

const TH =
  'px-3 py-2 text-left text-[10px] font-medium uppercase tracking-wide text-zinc-500 dark:text-zinc-400 border-b border-zinc-200 dark:border-zinc-800 whitespace-nowrap';
const TD =
  'px-3 py-2 text-xs text-zinc-700 dark:text-zinc-300 border-b border-zinc-100 dark:border-zinc-900 whitespace-nowrap';
const SELECT =
  'px-2 py-1 text-xs bg-white dark:bg-[#0A0D14] border border-zinc-200 dark:border-zinc-800 rounded text-zinc-800 dark:text-zinc-200 outline-none cursor-pointer';

const DEFAULT_SAMPLE_HTML =
  '<article>\n  <h1>AI Crawl Control</h1>\n  <p>Verified crawlers may fetch the <a href="/docs">docs</a>.</p>\n</article>';

/* -------------------------------------------------------------------------- */
/* Formatting helpers — all defensive against missing / malformed fields        */
/* -------------------------------------------------------------------------- */

function num(value: unknown): number {
  const parsed = Number(value ?? 0);
  return Number.isFinite(parsed) ? parsed : 0;
}

function formatBytes(value: unknown): string {
  const bytes = Math.max(0, num(value));
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const scaled = bytes / Math.pow(1024, index);
  const text = index === 0 || scaled >= 100 ? Math.round(scaled).toString() : scaled.toFixed(1);
  return `${text} ${units[index]}`;
}

function formatCount(value: unknown): string {
  return new Intl.NumberFormat().format(num(value));
}

function formatLastSeen(ms: unknown): string {
  const value = num(ms);
  if (value <= 0) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString();
}

function text(value: unknown, fallback = '—'): string {
  if (value === null || value === undefined || value === '') return fallback;
  return String(value);
}

function uriLabel(row: UriPatternRow): string {
  return text(row.uri ?? row.pattern ?? row.path, 'Unlabeled pattern');
}

function uriRequests(row: UriPatternRow): number {
  return num(row.requests ?? row.total_requests ?? row.count);
}

function uriBytes(row: UriPatternRow): number {
  return num(row.bytes ?? row.data_transfer_bytes);
}

function violationText(row: ViolationRow): string {
  return text(
    row.bot_display_name ?? row.bot_id ?? row.operator ?? row.reason ?? row.details,
    'Unknown source'
  );
}

function violationPath(row: ViolationRow): string {
  return text(row.path ?? row.uri, '—');
}

/* -------------------------------------------------------------------------- */
/* Small presentational pieces                                                  */
/* -------------------------------------------------------------------------- */

function VerdictBadge({ verdict }: { verdict: AgentVerdict }) {
  const isAgent = verdict.type === 'agent';
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-1 rounded border font-mono text-[10px] whitespace-nowrap ${
        isAgent
          ? 'bg-rose-50 dark:bg-rose-950/30 border-rose-200 dark:border-rose-900 text-rose-700 dark:text-rose-300'
          : 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900 text-emerald-700 dark:text-emerald-300'
      }`}
      title={isAgent ? (verdict.reasons || []).join(', ') : 'No agent probes triggered'}
    >
      {isAgent ? <Bot className="w-3 h-3" /> : <ShieldCheck className="w-3 h-3" />}
      SELF VERDICT: {isAgent ? 'AGENT' : 'HUMAN'}
      {isAgent && verdict.agent_name ? ` · ${verdict.agent_name}` : ''}
    </span>
  );
}

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="px-4 py-3 min-w-0">
      <div className="text-[11px] text-zinc-500 dark:text-zinc-400 truncate" title={label}>
        {label}
      </div>
      <div
        className="text-sm sm:text-base font-semibold font-mono tabular-nums text-zinc-900 dark:text-zinc-100 mt-0.5 truncate"
        title={value}
      >
        {value}
      </div>
    </div>
  );
}

function EmptyRow({ colSpan }: { colSpan: number }) {
  return (
    <tr>
      <td
        colSpan={colSpan}
        className="px-3 py-6 text-center text-xs text-zinc-400 dark:text-zinc-500"
      >
        No data recorded for this window.
      </td>
    </tr>
  );
}

function VerificationBadge({ status, method }: { status: string; method: string }) {
  const normalized = (status || '').toLowerCase();
  const verified = /verified|passed|ok|true|yes/.test(normalized);
  const failed = /failed|false|unverified|invalid|blocked/.test(normalized);
  const tone = verified
    ? 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900 text-emerald-700 dark:text-emerald-300'
    : failed
    ? 'bg-rose-50 dark:bg-rose-950/30 border-rose-200 dark:border-rose-900 text-rose-700 dark:text-rose-300'
    : 'bg-zinc-50 dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800 text-zinc-600 dark:text-zinc-400';
  return (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] ${tone}`}
      title={method || status || 'Unknown verification method'}
    >
      {verified ? <Check className="w-3 h-3" /> : failed ? <AlertTriangle className="w-3 h-3" /> : null}
      {text(status, 'Unknown')}
    </span>
  );
}

/* -------------------------------------------------------------------------- */
/* Dashboard                                                                    */
/* -------------------------------------------------------------------------- */

export function AICrawlControlDashboard() {
  const [data, setData] = useState<AnalyticsPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [tab, setTab] = useState<TabKey>('overview');
  const [syncState, setSyncState] = useState<'idle' | 'busy' | 'done' | 'error'>('idle');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [behaviorFilter, setBehaviorFilter] = useState('all');
  const [policy, setPolicy] = useState({ search: 'allow', agent: 'block', training: 'block' });
  const [isPending, startTransition] = useTransition();
  const [sampleHtml, setSampleHtml] = useState(DEFAULT_SAMPLE_HTML);
  const [markdownResult, setMarkdownResult] = useState<MarkdownPlaygroundResult | null>(null);
  const [markdownBusy, setMarkdownBusy] = useState(false);
  const [verdict, setVerdict] = useState<AgentVerdict>(() =>
    startIntelAgentProbe().getVerdict()
  );

  // Refresh the local verdict while later asynchronous probes resolve.
  useEffect(() => {
    const controller = startIntelAgentProbe();
    setVerdict(controller.getVerdict());
    const timer = setInterval(() => setVerdict(controller.getVerdict()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    let active = true;
    setData(null);
    setError(null);
    fetch('/api/intel/ai-crawl-control/analytics?hours=168', {
      headers: { Accept: 'application/json' },
    })
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json() as Promise<AnalyticsPayload>;
      })
      .then((payload) => {
        if (active) setData(payload && typeof payload === 'object' ? payload : {});
      })
      .catch((cause: unknown) => {
        if (active) setError(cause instanceof Error ? cause.message : 'Request failed');
      });
    return () => {
      active = false;
    };
  }, [reloadKey]);

  // Seed policy selects from zone configuration when it arrives.
  useEffect(() => {
    const zone = data?.zoneConfig ?? data?.zone_config;
    if (!zone) return;
    setPolicy((previous) => ({
      search: typeof zone.policy_search === 'string' ? zone.policy_search : previous.search,
      agent: typeof zone.policy_agent === 'string' ? zone.policy_agent : previous.agent,
      training:
        typeof zone.policy_training === 'string' ? zone.policy_training : previous.training,
    }));
  }, [data]);

  const crawlers = data?.crawlers ?? [];
  const operators = data?.operators ?? [];
  const status = data?.statusDistribution ?? data?.status_distribution ?? {};
  const uriPatterns = data?.uriPatterns ?? data?.uri_patterns ?? [];
  const violations = data?.violations ?? [];
  const summary = data?.summary ?? {};
  const liveRobotsTxt = data?.liveRobotsTxt ?? data?.live_robots_txt ?? '';

  const categories = useMemo(
    () =>
      Array.from(
        new Set(crawlers.map((row) => text(row.legacy_category, 'Uncategorized')))
      ).sort(),
    [crawlers]
  );
  const behaviors = useMemo(
    () => Array.from(new Set(crawlers.map((row) => text(row.behavior, 'Unknown')))).sort(),
    [crawlers]
  );
  const filteredCrawlers = useMemo(
    () =>
      crawlers.filter((row) => {
        const category = text(row.legacy_category, 'Uncategorized');
        const behavior = text(row.behavior, 'Unknown');
        return (
          (categoryFilter === 'all' || category === categoryFilter) &&
          (behaviorFilter === 'all' || behavior === behaviorFilter)
        );
      }),
    [crawlers, categoryFilter, behaviorFilter]
  );

  const statusEntries: { label: string; value: number; color: string }[] = [
    { label: '2xx Success', value: num(status.status_2xx), color: 'bg-emerald-500' },
    { label: '3xx Redirect', value: num(status.status_3xx), color: 'bg-sky-500' },
    { label: '4xx Client Error', value: num(status.status_4xx), color: 'bg-amber-500' },
    { label: '403 Blocked', value: num(status.status_403_blocked), color: 'bg-rose-500' },
    { label: '402 Charged', value: num(status.status_402_charged), color: 'bg-violet-500' },
    { label: '5xx Server Error', value: num(status.status_5xx), color: 'bg-red-600' },
  ];
  const statusTotal = statusEntries.reduce((sum, entry) => sum + entry.value, 0);

  const handleSyncFeeds = async (): Promise<void> => {
    setSyncState('busy');
    try {
      const response = await fetch('/api/intel/ai-crawl-control/sync-feeds', {
        method: 'POST',
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setSyncState('done');
    } catch {
      setSyncState('error');
    }
  };

  const requestPolicyUpdate = async (key: 'search' | 'agent' | 'training', value: string) => {
    try {
      await fetch('/api/intel/ai-crawl-control/policy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [key]: value }),
      });
    } catch {
      // The select remains a local optimistic value; the next analytics load re-syncs it.
    }
  };

  const handlePolicyChange = (key: 'search' | 'agent' | 'training', value: string): void => {
    setPolicy((previous) => ({ ...previous, [key]: value }));
    startTransition(() => {
      void requestPolicyUpdate(key, value);
    });
  };

  const runMarkdownPlayground = async (): Promise<void> => {
    setMarkdownBusy(true);
    try {
      const response = await fetch('/api/intel/ai-crawl-control/markdown-playground', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ html: sampleHtml }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = (await response.json()) as MarkdownPlaygroundResult;
      setMarkdownResult(payload && typeof payload === 'object' ? payload : {});
    } catch {
      setMarkdownResult({ markdown: 'Playground request failed. Please retry.' });
    } finally {
      setMarkdownBusy(false);
    }
  };

  const markdownText = markdownResult
    ? text(
        markdownResult.markdown ??
          markdownResult.headers?.['markdown'] ??
          'No markdown returned.',
        'No markdown returned.'
      )
    : '';
  const contentSignal = markdownResult
    ? text(
        markdownResult.content_signal ??
          markdownResult.contentSignal ??
          markdownResult.headers?.['Content-Signal'] ??
          markdownResult.headers?.['content-signal'],
        ''
      )
    : '';

  /* ---------------------------- tab bodies --------------------------------- */

  const renderOverview = () => (
    <div className="overflow-x-auto border border-zinc-200 dark:border-zinc-800 rounded-md">
      <table className="w-full border-collapse">
        <thead>
          <tr>
            <th className={TH}>Operator</th>
            <th className={TH}>Requests</th>
            <th className={TH}>Allowed</th>
            <th className={TH}>Unsuccessful</th>
            <th className={TH}>Data Transfer</th>
            <th className={TH}>Referrals</th>
            <th className={TH}>Crawl : Referral</th>
          </tr>
        </thead>
        <tbody>
          {operators.length === 0 ? (
            <EmptyRow colSpan={7} />
          ) : (
            operators.map((row, index) => {
              const referrals = num(row.referrals);
              const requests = num(row.total_requests);
              const ratio = referrals > 0 ? (requests / referrals).toFixed(1) : '—';
              return (
                <tr key={`${row.operator ?? 'operator'}-${index}`} className="hover:bg-zinc-50 dark:hover:bg-zinc-900/40">
                  <td className={`${TD} font-medium`}>{text(row.operator, 'Unknown operator')}</td>
                  <td className={`${TD} font-mono tabular-nums`}>{formatCount(row.total_requests)}</td>
                  <td className={`${TD} font-mono tabular-nums`}>{formatCount(row.allowed_requests)}</td>
                  <td className={`${TD} font-mono tabular-nums`}>{formatCount(row.unsuccessful_requests)}</td>
                  <td className={`${TD} font-mono tabular-nums`}>{formatBytes(row.data_transfer_bytes)}</td>
                  <td className={`${TD} font-mono tabular-nums`}>{formatCount(row.referrals)}</td>
                  <td className={`${TD} font-mono tabular-nums`} title="Crawl requests per referral">
                    {ratio}
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );

  const renderCrawlers = () => (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <label className="text-[11px] text-zinc-500 dark:text-zinc-400">Category</label>
        <select
          className={SELECT}
          value={categoryFilter}
          onChange={(event) => setCategoryFilter(event.target.value)}
        >
          <option value="all">All categories</option>
          {categories.map((category) => (
            <option key={category} value={category}>
              {category}
            </option>
          ))}
        </select>
        <label className="text-[11px] text-zinc-500 dark:text-zinc-400">Behavior</label>
        <select
          className={SELECT}
          value={behaviorFilter}
          onChange={(event) => setBehaviorFilter(event.target.value)}
        >
          <option value="all">All behaviors</option>
          {behaviors.map((behavior) => (
            <option key={behavior} value={behavior}>
              {behavior}
            </option>
          ))}
        </select>
        <span className="text-[11px] text-zinc-400 dark:text-zinc-500 ml-auto">
          {filteredCrawlers.length} of {crawlers.length} crawlers
        </span>
      </div>
      <div className="overflow-x-auto border border-zinc-200 dark:border-zinc-800 rounded-md">
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className={TH}>Bot</th>
              <th className={TH}>Operator</th>
              <th className={TH}>Category</th>
              <th className={TH}>Behavior</th>
              <th className={TH}>CF Detection ID</th>
              <th className={TH}>Verification</th>
              <th className={TH}>Requests</th>
              <th className={TH}>Allowed</th>
              <th className={TH}>Violations</th>
              <th className={TH}>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {filteredCrawlers.length === 0 ? (
              <EmptyRow colSpan={10} />
            ) : (
              filteredCrawlers.map((row, index) => (
                <tr
                  key={`${row.bot_id ?? 'bot'}-${index}`}
                  className="hover:bg-zinc-50 dark:hover:bg-zinc-900/40"
                >
                  <td className={`${TD} font-medium`}>{text(row.bot_display_name ?? row.bot_id, 'Unknown bot')}</td>
                  <td className={TD}>{text(row.operator_label ?? row.operator)}</td>
                  <td className={TD}>{text(row.legacy_category, 'Uncategorized')}</td>
                  <td className={TD}>{text(row.behavior, 'Unknown')}</td>
                  <td className={`${TD} font-mono text-[11px]`}>{text(row.cf_detection_id)}</td>
                  <td className={TD}>
                    <VerificationBadge
                      status={text(row.verification_status, 'Unknown')}
                      method={text(row.verification_method, '')}
                    />
                  </td>
                  <td className={`${TD} font-mono tabular-nums`}>{formatCount(row.total_requests)}</td>
                  <td className={`${TD} font-mono tabular-nums`}>{formatCount(row.allowed_requests)}</td>
                  <td className={`${TD} font-mono tabular-nums`}>{formatCount(row.robots_violations)}</td>
                  <td className={`${TD} font-mono text-[11px]`}>{formatLastSeen(row.last_seen_ms)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );

  const renderMetrics = () => (
    <div className="space-y-5">
      <section>
        <h3 className="text-xs font-medium text-zinc-800 dark:text-zinc-200 mb-2">
          Status Code Distribution
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {statusEntries.map((entry) => {
            const percent = statusTotal > 0 ? (entry.value / statusTotal) * 100 : 0;
            return (
              <div
                key={entry.label}
                className="border border-zinc-200 dark:border-zinc-800 rounded-md px-3 py-2"
              >
                <div className="flex items-center justify-between gap-2 text-xs">
                  <span className="text-zinc-600 dark:text-zinc-400 truncate">{entry.label}</span>
                  <span className="font-mono tabular-nums text-zinc-900 dark:text-zinc-100">
                    {formatCount(entry.value)}
                  </span>
                </div>
                <div className="mt-2 h-1.5 w-full rounded-full bg-zinc-100 dark:bg-zinc-900 overflow-hidden">
                  <div
                    className={`h-full rounded-full ${entry.color}`}
                    style={{ width: `${Math.min(100, Math.max(0, percent))}%` }}
                  />
                </div>
                <div className="mt-1 text-[10px] text-zinc-400 dark:text-zinc-500 font-mono">
                  {percent.toFixed(1)}%
                </div>
              </div>
            );
          })}
        </div>
      </section>
      <section>
        <h3 className="text-xs font-medium text-zinc-800 dark:text-zinc-200 mb-2">URI Patterns</h3>
        <div className="overflow-x-auto border border-zinc-200 dark:border-zinc-800 rounded-md">
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className={TH}>URI Pattern</th>
                <th className={TH}>Requests</th>
                <th className={TH}>Data Transfer</th>
              </tr>
            </thead>
            <tbody>
              {uriPatterns.length === 0 ? (
                <EmptyRow colSpan={3} />
              ) : (
                uriPatterns.map((row, index) => (
                  <tr
                    key={`${uriLabel(row)}-${index}`}
                    className="hover:bg-zinc-50 dark:hover:bg-zinc-900/40"
                  >
                    <td className={`${TD} font-mono text-[11px]`}>{uriLabel(row)}</td>
                    <td className={`${TD} font-mono tabular-nums`}>{formatCount(uriRequests(row))}</td>
                    <td className={`${TD} font-mono tabular-nums`}>{formatBytes(uriBytes(row))}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );

  const renderDirectives = () => (
    <div className="space-y-5">
      <section className="border border-zinc-200 dark:border-zinc-800 rounded-md p-3 sm:p-4">
        <div className="flex items-center justify-between gap-2 mb-3">
          <h3 className="text-xs font-medium text-zinc-800 dark:text-zinc-200">Traffic Directives</h3>
          {isPending && (
            <span className="text-[10px] text-zinc-400 dark:text-zinc-500">Saving…</span>
          )}
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {(
            [
              ['search', 'Search engines', 'Lets verified search crawlers index content.'],
              ['agent', 'AI agents', 'Controls live AI assistant / agent fetchers.'],
              ['training', 'Training crawlers', 'Controls crawlers collecting training data.'],
            ] as const
          ).map(([key, label, help]) => (
            <label key={key} className="block">
              <span className="block text-[11px] font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                {label}
              </span>
              <select
                className={`${SELECT} w-full`}
                value={policy[key]}
                onChange={(event) => handlePolicyChange(key, event.target.value)}
              >
                <option value="allow">Allow</option>
                <option value="block">Block</option>
                <option value="charge">Charge</option>
              </select>
              <span className="block text-[10px] text-zinc-400 dark:text-zinc-500 mt-1">{help}</span>
            </label>
          ))}
        </div>
      </section>

      <section>
        <h3 className="text-xs font-medium text-zinc-800 dark:text-zinc-200 mb-2">live robots.txt</h3>
        <pre className="max-h-64 overflow-auto p-3 rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/50 text-[11px] font-mono leading-relaxed text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">
          {liveRobotsTxt || 'No robots.txt has been generated yet.'}
        </pre>
      </section>

      <section>
        <h3 className="text-xs font-medium text-zinc-800 dark:text-zinc-200 mb-2">
          robots.txt Violations
        </h3>
        <div className="overflow-x-auto border border-zinc-200 dark:border-zinc-800 rounded-md">
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className={TH}>Source</th>
                <th className={TH}>Operator</th>
                <th className={TH}>Path</th>
                <th className={TH}>Detail</th>
                <th className={TH}>Recorded</th>
              </tr>
            </thead>
            <tbody>
              {violations.length === 0 ? (
                <EmptyRow colSpan={5} />
              ) : (
                violations.map((row, index) => (
                  <tr
                    key={`${violationText(row)}-${index}`}
                    className="hover:bg-zinc-50 dark:hover:bg-zinc-900/40"
                  >
                    <td className={`${TD} font-medium`}>{violationText(row)}</td>
                    <td className={TD}>{text(row.operator)}</td>
                    <td className={`${TD} font-mono text-[11px]`}>{violationPath(row)}</td>
                    <td className={TD}>{text(row.details ?? row.reason ?? row.user_agent)}</td>
                    <td className={`${TD} font-mono text-[11px]`}>{formatLastSeen(row.timestamp_ms)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );

  const renderMarkdown = () => (
    <div className="space-y-4">
      <section>
        <label
          htmlFor="ai-crawl-markdown-sample"
          className="block text-xs font-medium text-zinc-800 dark:text-zinc-200 mb-2"
        >
          Sample HTML
        </label>
        <textarea
          id="ai-crawl-markdown-sample"
          value={sampleHtml}
          onChange={(event) => setSampleHtml(event.target.value)}
          rows={7}
          spellCheck={false}
          className="w-full rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0A0D14] px-3 py-2 font-mono text-[11px] leading-relaxed text-zinc-800 dark:text-zinc-200 outline-none focus:border-zinc-400 dark:focus:border-zinc-600"
        />
        <div className="mt-2 flex items-center gap-2">
          <button
            type="button"
            onClick={() => void runMarkdownPlayground()}
            disabled={markdownBusy}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-zinc-700 dark:text-zinc-200 bg-white dark:bg-[#0A0D14] hover:bg-zinc-50 dark:hover:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded disabled:opacity-50 cursor-pointer"
          >
            <FileText className="w-3 h-3" />
            {markdownBusy ? 'Converting…' : 'Convert to Markdown'}
          </button>
          {contentSignal && (
            <span
              className="inline-flex items-center gap-1.5 px-2 py-1 rounded border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/50 text-[10px] font-mono text-zinc-700 dark:text-zinc-300 truncate"
              title={contentSignal}
            >
              Content-Signal: {contentSignal}
            </span>
          )}
        </div>
      </section>
      <section>
        <h3 className="text-xs font-medium text-zinc-800 dark:text-zinc-200 mb-2">Markdown Preview</h3>
        <pre className="max-h-80 overflow-auto p-3 rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/50 text-[11px] font-mono leading-relaxed text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">
          {markdownResult ? markdownText : 'Run the playground to see the generated markdown.'}
        </pre>
      </section>
    </div>
  );

  const renderTab = (): React.ReactNode => {
    switch (tab) {
      case 'crawlers':
        return renderCrawlers();
      case 'metrics':
        return renderMetrics();
      case 'directives':
        return renderDirectives();
      case 'markdown':
        return renderMarkdown();
      case 'overview':
      default:
        return renderOverview();
    }
  };

  return (
    <div className="bg-white dark:bg-[#0A0D14] border border-zinc-200 dark:border-zinc-800 rounded-md text-zinc-900 dark:text-zinc-100">
      {/* Header */}
      <div className="px-4 sm:px-5 py-3 border-b border-zinc-200/70 dark:border-zinc-800/70 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <Shield className="w-4 h-4 text-zinc-800 dark:text-zinc-200 shrink-0" />
          <h2 className="text-xs sm:text-sm font-medium truncate">
            Intel System — AI Crawl Control &amp; Agent Defense
          </h2>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <VerdictBadge verdict={verdict} />
          <button
            type="button"
            onClick={() => void handleSyncFeeds()}
            disabled={syncState === 'busy'}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-zinc-700 dark:text-zinc-200 bg-white dark:bg-[#0A0D14] hover:bg-zinc-50 dark:hover:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer transition-colors"
          >
            <RefreshCw className={`w-3 h-3 ${syncState === 'busy' ? 'animate-spin' : ''}`} />
            <span>Sync Official IP &amp; JWK Feeds</span>
          </button>
        </div>
      </div>

      {(syncState === 'done' || syncState === 'error') && (
        <div
          className={`px-4 sm:px-5 py-1.5 text-[11px] border-b border-zinc-200/70 dark:border-zinc-800/70 ${
            syncState === 'done'
              ? 'text-emerald-700 dark:text-emerald-300'
              : 'text-rose-700 dark:text-rose-300'
          }`}
        >
          {syncState === 'done'
            ? 'Official IP & JWK feeds synced.'
            : 'Feed sync failed. Please retry.'}
        </div>
      )}

      {/* Hero metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 border-b border-zinc-200/70 dark:border-zinc-800/70 divide-x divide-zinc-200/70 dark:divide-zinc-800/70">
        <MetricCard label="Total AI Requests" value={data ? formatCount(summary.total_requests) : '—'} />
        <MetricCard label="Allowed" value={data ? formatCount(summary.allowed_requests) : '—'} />
        <MetricCard
          label="Unsuccessful"
          value={data ? formatCount(summary.unsuccessful_requests) : '—'}
        />
        <MetricCard label="Data Transfer" value={data ? formatBytes(summary.total_bytes) : '—'} />
        <MetricCard
          label="Markdown Served"
          value={data ? formatCount(summary.markdown_served_count) : '—'}
        />
        <MetricCard
          label="robots.txt Violations"
          value={data ? formatCount(summary.robots_violations_count) : '—'}
        />
      </div>

      {/* Tabs */}
      <div className="px-2 sm:px-4 border-b border-zinc-200/70 dark:border-zinc-800/70 flex items-center gap-1 overflow-x-auto">
        {TABS.map((item) => (
          <button
            key={item.key}
            type="button"
            onClick={() => setTab(item.key)}
            className={`px-3 py-2 text-xs font-medium whitespace-nowrap border-b-2 cursor-pointer transition-colors ${
              tab === item.key
                ? 'border-zinc-900 dark:border-zinc-100 text-zinc-900 dark:text-zinc-100'
                : 'border-transparent text-zinc-500 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200'
            }`}
          >
            {item.label}
          </button>
        ))}
        <button
          type="button"
          onClick={() => setReloadKey((value) => value + 1)}
          className="ml-auto inline-flex items-center gap-1 px-2 py-1 text-[11px] text-zinc-500 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200 cursor-pointer"
          title="Reload analytics"
        >
          <Activity className="w-3 h-3" />
          Refresh
        </button>
      </div>

      {/* Content */}
      <div className="p-4 sm:p-5">
        {data === null ? (
          <div className="flex items-center justify-center gap-2 py-12 text-xs text-zinc-500 dark:text-zinc-400">
            <Database className="w-4 h-4 animate-pulse" />
            {error ? `Failed to load analytics (${error}).` : 'Loading analytics…'}
          </div>
        ) : (
          <>
            {error && (
              <div className="mb-3 flex items-center gap-2 rounded-md border border-amber-200 dark:border-amber-900 bg-amber-50 dark:bg-amber-950/30 px-3 py-2 text-[11px] text-amber-800 dark:text-amber-300">
                <AlertTriangle className="w-3 h-3" />
                Showing last available data — refresh failed ({error}).
              </div>
            )}
            <div className="mb-3 flex items-center gap-2 text-[11px] text-zinc-400 dark:text-zinc-500">
              <Globe2 className="w-3 h-3" />
              Rolling 168-hour window · Cloudflare bot signals &amp; crawl directives
            </div>
            {renderTab()}
          </>
        )}
      </div>
    </div>
  );
}

export default AICrawlControlDashboard;
