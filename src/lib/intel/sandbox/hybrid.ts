// External sandbox API integrations (Hybrid Analysis, Joe Sandbox, ANY.RUN).
// Normalizes their responses into the internal SandboxResult schema.
// All require API keys via environment variables.

import type {
  ContentIndicator, ContentForm, HttpFingerprint, RedirectHop, ResourceProbe,
  SandboxResult, SandboxVerdict, StaticFlag, TlsInfo,
} from './types';

const HYBRID_ANALYSIS_API = 'https://www.hybrid-analysis.com/api/v2';
const JOE_SANDBOX_API = 'https://jbxcloud.joesecurity.org/api/v2';
const ANY_RUN_API = 'https://api.any.run/v1';

interface HybridConfig {
  hybridAnalysisKey?: string;
  joeSandboxKey?: string;
  anyRunKey?: string;
}

function getConfig(): HybridConfig {
  return {
    hybridAnalysisKey: process.env.HYBRID_ANALYSIS_API_KEY,
    joeSandboxKey: process.env.JOE_SANDBOX_API_KEY,
    anyRunKey: process.env.ANY_RUN_API_KEY,
  };
}

// ---- Common normalization helpers ----

function mapSeverity(label: string): ContentIndicator['severity'] {
  const l = label.toLowerCase();
  if (l.includes('critical') || l.includes('malicious') || l.includes('trojan') || l.includes('ransomware')) return 'CRITICAL';
  if (l.includes('high') || l.includes('suspicious') || l.includes('phishing') || l.includes('c2') || l.includes('exfil')) return 'HIGH';
  if (l.includes('medium') || l.includes('moderate') || l.includes('potentially')) return 'MEDIUM';
  if (l.includes('low') || l.includes('info')) return 'LOW';
  return 'MEDIUM';
}

function normalizeVerdict(verdict: string | undefined, score: number): SandboxVerdict {
  const level: SandboxVerdict['level'] = score >= 30 ? 'MALICIOUS' : score >= 12 ? 'SUSPICIOUS' : 'BENIGN';
  return {
    score: Math.min(score, 100),
    level,
    verdict:
      score >= 30
        ? 'External sandbox: strong malicious signals.'
        : score >= 12
          ? 'External sandbox: suspicious signals.'
          : 'External sandbox: no significant threats.',
    reasons: verdict ? [verdict] : [],
  };
}

// ---- Hybrid Analysis ----

interface HybridSubmitResponse {
  job_id: string;
  sha256: string;
}

interface HybridReportSummary {
  verdict: string;
  threat_score: number;
  av_detect: number;
  total_av: number;
  tags: string[];
  mitre_attacks: string[];
  network: { hosts: string[]; domains: string[]; ips: string[] };
  dropped_files: string[];
}

export async function submitToHybridAnalysis(url: string): Promise<{ jobId: string; sha256: string } | null> {
  const { hybridAnalysisKey } = getConfig();
  if (!hybridAnalysisKey) return null;

  try {
    const res = await fetch(`${HYBRID_ANALYSIS_API}/submit/url`, {
      method: 'POST',
      headers: {
        'api-key': hybridAnalysisKey,
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: new URLSearchParams({ url, environment_id: '120' }), // Win10 x64
    });
    if (!res.ok) return null;
    const data: HybridSubmitResponse = await res.json();
    return { jobId: data.job_id, sha256: data.sha256 };
  } catch {
    return null;
  }
}

export async function pollHybridAnalysis(jobId: string, maxAttempts = 12): Promise<HybridReportSummary | null> {
  const { hybridAnalysisKey } = getConfig();
  if (!hybridAnalysisKey) return null;

  for (let i = 0; i < maxAttempts; i++) {
    await new Promise((r) => setTimeout(r, 15000));
    try {
      const res = await fetch(`${HYBRID_ANALYSIS_API}/report/${jobId}/summary`, {
        headers: { 'api-key': hybridAnalysisKey, Accept: 'application/json' },
      });
      if (!res.ok) continue;
      const data: HybridReportSummary = await res.json();
      if (data.verdict !== 'in progress' && data.verdict !== 'no specific verdict') return data;
    } catch {
      /* continue polling */
    }
  }
  return null;
}

function hybridToSandboxResult(url: string, host: string, report: HybridReportSummary): SandboxResult {
  const indicators: ContentIndicator[] = [];
  for (const tag of report.tags) {
    indicators.push({
      label: tag,
      category: 'hybrid-analysis',
      severity: mapSeverity(tag),
      detail: `Hybrid Analysis tag: ${tag}`,
    });
  }
  for (const attack of report.mitre_attacks) {
    indicators.push({
      label: `MITRE: ${attack}`,
      category: 'attribution',
      severity: 'HIGH',
      detail: `Hybrid Analysis MITRE ATT&CK: ${attack}`,
    });
  }

  const staticFlags: StaticFlag[] = [];
  if (report.av_detect > 0) {
    staticFlags.push({ label: `AV detection ${report.av_detect}/${report.total_av}`, weight: 8, category: 'av' });
  }

  return {
    url,
    host,
    timestamp: new Date().toISOString(),
    source: 'Hybrid Analysis (dynamic detonation)',
    live: true,
    http: null,
    redirects: [],
    tls: null,
    content: {
      title: 'Hybrid Analysis Report',
      description: null,
      lang: null,
      favicon: null,
      forms: [],
      iframes: [],
      metaRefresh: false,
      obfuscatedJs: false,
      inlineJsBytes: 0,
      scripts: [],
      emails: [],
      telegramTokens: [],
      telegramChatIds: [],
      indicators,
      finalHost: host,
    },
    resources: [],
    reputation: {
      ip: null, geo: null, asn: null, isp: null,
      dnsblListed: 0, dnsblBlocked: 0, torExit: false, urlhausCount: 0,
      hosting: false, proxy: false,
      whoisCreated: null, domainAgeDays: null, domainExpires: null,
    },
    staticFlags,
    verdict: normalizeVerdict(report.verdict, report.threat_score),
    screenshotUrl: null,
  };
}

// ---- Joe Sandbox ----

interface JoeSubmitResponse {
  webid: string;
}

interface JoeAnalysisInfo {
  status: string;
  score: number;
  verdict: string;
  malware_names: string[];
  signatures: { name: string; severity: string; category: string }[];
  mitre_attacks: { technique: string; tactic: string }[];
  network: { domains: string[]; ips: string[] };
}

export async function submitToJoeSandbox(url: string): Promise<string | null> {
  const { joeSandboxKey } = getConfig();
  if (!joeSandboxKey) return null;

  try {
    const res = await fetch(`${JOE_SANDBOX_API}/analysis/submit`, {
      method: 'POST',
      headers: {
        'Joe-Security-API-Key': joeSandboxKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        url,
        system: 'win10_64',
        cookbook: 'default',
      }),
    });
    if (!res.ok) return null;
    const data: JoeSubmitResponse = await res.json();
    return data.webid;
  } catch {
    return null;
  }
}

export async function pollJoeSandbox(webid: string, maxAttempts = 12): Promise<JoeAnalysisInfo | null> {
  const { joeSandboxKey } = getConfig();
  if (!joeSandboxKey) return null;

  for (let i = 0; i < maxAttempts; i++) {
    await new Promise((r) => setTimeout(r, 20000));
    try {
      const res = await fetch(`${JOE_SANDBOX_API}/analysis/info/${webid}`, {
        headers: { 'Joe-Security-API-Key': joeSandboxKey },
      });
      if (!res.ok) continue;
      const data = await res.json();
      if (data.status === 'finished' || data.status === 'error') return data;
    } catch {
      /* continue */
    }
  }
  return null;
}

function joeToSandboxResult(url: string, host: string, report: JoeAnalysisInfo): SandboxResult {
  const indicators: ContentIndicator[] = [];
  for (const sig of report.signatures) {
    indicators.push({
      label: sig.name,
      category: sig.category || 'joe-sandbox',
      severity: sig.severity === 'critical' ? 'CRITICAL' : sig.severity === 'high' ? 'HIGH' : sig.severity === 'medium' ? 'MEDIUM' : 'LOW',
      detail: `Joe Sandbox signature: ${sig.name}`,
    });
  }
  for (const attack of report.mitre_attacks) {
    indicators.push({
      label: `MITRE ${attack.technique} (${attack.tactic})`,
      category: 'attribution',
      severity: 'HIGH',
      detail: `Joe Sandbox MITRE ATT&CK: ${attack.technique} — ${attack.tactic}`,
    });
  }

  const staticFlags: StaticFlag[] = [];
  for (const name of report.malware_names) {
    staticFlags.push({ label: `Malware family: ${name}`, weight: 10, category: 'malware-family' });
  }

  return {
    url,
    host,
    timestamp: new Date().toISOString(),
    source: 'Joe Sandbox (dynamic detonation)',
    live: true,
    http: null,
    redirects: [],
    tls: null,
    content: {
      title: 'Joe Sandbox Report',
      description: null,
      lang: null,
      favicon: null,
      forms: [],
      iframes: [],
      metaRefresh: false,
      obfuscatedJs: false,
      inlineJsBytes: 0,
      scripts: [],
      emails: [],
      telegramTokens: [],
      telegramChatIds: [],
      indicators,
      finalHost: host,
    },
    resources: [],
    reputation: {
      ip: null, geo: null, asn: null, isp: null,
      dnsblListed: 0, dnsblBlocked: 0, torExit: false, urlhausCount: 0,
      hosting: false, proxy: false,
      whoisCreated: null, domainAgeDays: null, domainExpires: null,
    },
    staticFlags,
    verdict: normalizeVerdict(report.verdict, report.score),
    screenshotUrl: null,
  };
}

// ---- ANY.RUN ----

interface AnyRunSubmitResponse {
  data: { taskid: string };
}

interface AnyRunReport {
  status: string;
  verdict: string;
  score: number;
  threats: { name: string; severity: string; category: string }[];
  mitre: { technique: string; tactic: string }[];
  network: { domains: string[]; ips: string[] };
  processes: { name: string; pid: number }[];
}

export async function submitToAnyRun(url: string): Promise<string | null> {
  const { anyRunKey } = getConfig();
  if (!anyRunKey) return null;

  try {
    const res = await fetch(`${ANY_RUN_API}/analysis/submit/url`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${anyRunKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        env_bitness: 64,
        env_type: 'windows',
        obj_type: 'url',
        obj_url: url,
      }),
    });
    if (!res.ok) return null;
    const data: AnyRunSubmitResponse = await res.json();
    return data.data.taskid;
  } catch {
    return null;
  }
}

export async function pollAnyRun(taskid: string, maxAttempts = 12): Promise<AnyRunReport | null> {
  const { anyRunKey } = getConfig();
  if (!anyRunKey) return null;

  for (let i = 0; i < maxAttempts; i++) {
    await new Promise((r) => setTimeout(r, 15000));
    try {
      const res = await fetch(`${ANY_RUN_API}/analysis/${taskid}`, {
        headers: { Authorization: `Bearer ${anyRunKey}` },
      });
      if (!res.ok) continue;
      const data: AnyRunReport = await res.json();
      if (data.status === 'completed' || data.status === 'failed') return data;
    } catch {
      /* continue */
    }
  }
  return null;
}

function anyRunToSandboxResult(url: string, host: string, report: AnyRunReport): SandboxResult {
  const indicators: ContentIndicator[] = [];
  for (const threat of report.threats) {
    indicators.push({
      label: threat.name,
      category: threat.category || 'anyrun',
      severity: threat.severity === 'critical' ? 'CRITICAL' : threat.severity === 'high' ? 'HIGH' : threat.severity === 'medium' ? 'MEDIUM' : 'LOW',
      detail: `ANY.RUN threat: ${threat.name}`,
    });
  }
  for (const attack of report.mitre) {
    indicators.push({
      label: `MITRE ${attack.technique} (${attack.tactic})`,
      category: 'attribution',
      severity: 'HIGH',
      detail: `ANY.RUN MITRE ATT&CK: ${attack.technique} — ${attack.tactic}`,
    });
  }

  const staticFlags: StaticFlag[] = [];

  return {
    url,
    host,
    timestamp: new Date().toISOString(),
    source: 'ANY.RUN (dynamic detonation)',
    live: true,
    http: null,
    redirects: [],
    tls: null,
    content: {
      title: 'ANY.RUN Report',
      description: null,
      lang: null,
      favicon: null,
      forms: [],
      iframes: [],
      metaRefresh: false,
      obfuscatedJs: false,
      inlineJsBytes: 0,
      scripts: [],
      emails: [],
      telegramTokens: [],
      telegramChatIds: [],
      indicators,
      finalHost: host,
    },
    resources: [],
    reputation: {
      ip: null, geo: null, asn: null, isp: null,
      dnsblListed: 0, dnsblBlocked: 0, torExit: false, urlhausCount: 0,
      hosting: false, proxy: false,
      whoisCreated: null, domainAgeDays: null, domainExpires: null,
    },
    staticFlags,
    verdict: normalizeVerdict(report.verdict, report.score),
    screenshotUrl: null,
  };
}

// ---- Unified orchestrator ----

export interface ExternalSandboxResult {
  source: 'hybrid-analysis' | 'joe-sandbox' | 'any-run';
  result: SandboxResult;
  error?: string;
}

export async function runExternalSandboxes(url: string): Promise<ExternalSandboxResult[]> {
  const host = new URL(url).hostname;
  const results: ExternalSandboxResult[] = [];

  // Submit to all available services in parallel
  const [hybridJob, joeWebid, anyRunTaskid] = await Promise.allSettled([
    submitToHybridAnalysis(url),
    submitToJoeSandbox(url),
    submitToAnyRun(url),
  ]);

  // Poll for results in parallel
  const polls = await Promise.allSettled([
    hybridJob.status === 'fulfilled' && hybridJob.value
      ? pollHybridAnalysis(hybridJob.value.jobId)
      : Promise.resolve(null),
    joeWebid.status === 'fulfilled' && joeWebid.value
      ? pollJoeSandbox(joeWebid.value)
      : Promise.resolve(null),
    anyRunTaskid.status === 'fulfilled' && anyRunTaskid.value
      ? pollAnyRun(anyRunTaskid.value)
      : Promise.resolve(null),
  ]);

  // Normalize Hybrid Analysis
  if (polls[0].status === 'fulfilled' && polls[0].value) {
    results.push({ source: 'hybrid-analysis', result: hybridToSandboxResult(url, host, polls[0].value) });
  } else if (polls[0].status === 'rejected') {
    results.push({ source: 'hybrid-analysis', result: null as any, error: polls[0].reason?.message });
  }

  // Normalize Joe Sandbox
  if (polls[1].status === 'fulfilled' && polls[1].value) {
    results.push({ source: 'joe-sandbox', result: joeToSandboxResult(url, host, polls[1].value) });
  } else if (polls[1].status === 'rejected') {
    results.push({ source: 'joe-sandbox', result: null as any, error: polls[1].reason?.message });
  }

  // Normalize ANY.RUN
  if (polls[2].status === 'fulfilled' && polls[2].value) {
    results.push({ source: 'any-run', result: anyRunToSandboxResult(url, host, polls[2].value) });
  } else if (polls[2].status === 'rejected') {
    results.push({ source: 'any-run', result: null as any, error: polls[2].reason?.message });
  }

  return results.filter((r) => r.result !== null);
}