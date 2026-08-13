// VirusTotal enrichment helper (shared by Domain Intel and URL Scanner).
// Looks up an indicator in VirusTotal and returns normalized current indicators
// (detection stats, reputation, categories, votes, verdict) or null.

const VT_BASE = 'https://www.virustotal.com/api/v3';

function vtAuth(headers: Record<string, string>): Record<string, string> {
  if (process.env.VIRUSTOTAL_API_KEY) {
    headers['x-apikey'] = process.env.VIRUSTOTAL_API_KEY;
  }
  return headers;
}

export function vtEnabled(): boolean {
  return Boolean(process.env.VIRUSTOTAL_API_KEY);
}

const EMPTY_STATS = { malicious: 0, suspicious: 0, undetected: 0, harmless: 0, timeout: 0 };

export async function lookupVirusTotalDomain(domain: string): Promise<null | {
  source: string;
  analyzed: boolean;
  url: string;
  reputation: number;
  lastAnalysisDate: string | null;
  lastAnalysisStats: { malicious: number; suspicious: number; undetected: number; harmless: number; timeout: number };
  totalEngines: number;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
  categories: string[];
  votes: { harmless: number; malicious: number };
  tags: string[];
  firstSeen: string | null;
  lastSeen: string | null;
}> {
  if (!vtEnabled()) return null;
  try {
    const res = await fetch(`${VT_BASE}/domains/${encodeURIComponent(domain)}`, {
      headers: vtAuth({}),
      signal: AbortSignal.timeout(12000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    const attrs = data.data?.attributes;
    if (!attrs) return null;
    const stats = attrs.last_analysis_stats || EMPTY_STATS;
    const vTtl = stats.malicious + stats.suspicious;
    return {
      source: 'VirusTotal',
      analyzed: true,
      url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}/detection`,
      reputation: attrs.reputation ?? 0,
      lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
      lastAnalysisStats: stats,
      totalEngines: stats.malicious + stats.suspicious + stats.undetected + stats.harmless + stats.timeout,
      verdict: stats.malicious > 0 ? 'MALICIOUS' : stats.suspicious > 0 ? 'SUSPICIOUS' : vTtl === 0 && stats.harmless > 0 ? 'CLEAN' : 'UNKNOWN',
      categories: Object.values(attrs.categories || {}),
      votes: attrs.total_votes || { harmless: 0, malicious: 0 },
      tags: (attrs.tags || []).slice(0, 12),
      firstSeen: attrs.first_seen ? new Date(attrs.first_seen * 1000).toISOString() : null,
      lastSeen: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
    };
  } catch (e) {
    console.log('[VT] domain lookup failed:', e);
    return null;
  }
}

export async function lookupVirusTotalUrl(url: string): Promise<null | {
  source: string;
  analyzed: boolean;
  url: string;
  reputation: number;
  lastAnalysisDate: string | null;
  lastAnalysisStats: { malicious: number; suspicious: number; undetected: number; harmless: number; timeout: number };
  totalEngines: number;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
  categories: string[];
  votes: { harmless: number; malicious: number };
  tags: string[];
  firstSeen: string | null;
  lastSeen: string | null;
}> {
  if (!vtEnabled()) return null;
  try {
    const res = await fetch(`${VT_BASE}/urls/${encodeURIComponent(url)}`, {
      headers: vtAuth({}),
      signal: AbortSignal.timeout(12000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    const attrs = data.data?.attributes;
    if (!attrs) return null;
    const stats = attrs.last_analysis_stats || EMPTY_STATS;
    const vTtl = stats.malicious + stats.suspicious;
    return {
      source: 'VirusTotal',
      analyzed: true,
      url: `https://www.virustotal.com/gui/url/${encodeURIComponent(url)}`,
      reputation: attrs.reputation ?? 0,
      lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
      lastAnalysisStats: stats,
      totalEngines: stats.malicious + stats.suspicious + stats.undetected + stats.harmless + stats.timeout,
      verdict: stats.malicious > 0 ? 'MALICIOUS' : stats.suspicious > 0 ? 'SUSPICIOUS' : vTtl === 0 && stats.harmless > 0 ? 'CLEAN' : 'UNKNOWN',
      categories: Object.values(attrs.categories || {}),
      votes: attrs.total_votes || { harmless: 0, malicious: 0 },
      tags: (attrs.tags || []).slice(0, 12),
      firstSeen: attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toISOString() : null,
      lastSeen: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
    };
  } catch (e) {
    console.log('[VT] URL lookup failed:', e);
    return null;
  }
}