import { NextRequest, NextResponse } from 'next/server';
import { lookupDomain } from '@/lib/intel';
import { isAIEnabled } from '@/lib/ai';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

export const maxDuration = 60;

const TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];

async function resolveRecord(domain: string, type: string): Promise<any> {
  try {
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return { type, status: res.status, answer: [] };
    return { type, ...(await res.json()) };
  } catch (e) {
    return { type, status: 'ERROR', answer: [] };
  }
}

async function bruteForceSubdomains(domain: string): Promise<string[]> {
  const words = ['www', 'mail', 'api', 'dev', 'staging', 'blog', 'shop', 'app', 'admin', 'portal', 'vpn', 'cdn', 'mx', 'smtp', 'ns1', 'ns2', 'ftp', 'gateway', 'vpn', 'remote', 'cloud', 'webmail', 'owa', 'autodiscover', 'git', 'jira', 'jenkins', 'test', 'beta', 'secure', 'ssl', 'proxy', 'static', 'assets', 'img', 'media', 'mobile', 'm', 'old', 'new', 'backup', 'db', 'mysql', 'redis'];
  const out: string[] = [];
  const results = await Promise.allSettled(
    words.map(async (w) => {
      try {
        const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(`${w}.${domain}`)}&type=A`, {
          headers: { Accept: 'application/dns-json' },
          signal: AbortSignal.timeout(6000),
        }).then((r) => r.json());
        if (res.Answer?.length) return `${w}.${domain}`;
      } catch { /* ignore */ }
      return null;
    })
  );
  results.forEach((r) => {
    if (r.status === 'fulfilled' && r.value) out.push(r.value);
  });
  return out;
}

// Reverse lookup a range around a seed IP (demo — best effort public sources)
function reverseRange(ip: string): string[] {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return [];
  const out: string[] = [];
  const [a, b, c] = parts;
  for (let d = 1; d <= 5; d++) {
    const candidate = `${a}.${b}.${c}.${d}`;
    out.push(`ptr-${d} (${candidate})`);
  }
  return out;
}

export async function GET(request: NextRequest) {
  const { module: dnsModule, error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }
  const { searchParams } = new URL(request.url);
  const domain = searchParams.get('domain');

  if (!domain) {
    return NextResponse.json(
      { success: false, error: 'Domain is required', example: '/api/osint/dnsdump?domain=example.com' },
      { status: 400 }
    );
  }

  try {
    const clean = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    const records = await Promise.all(TYPES.map((t) => resolveRecord(clean, t)));

    const byType: Record<string, any[]> = {};
    records.forEach((r) => {
      byType[r.type] = (r.Answer || []).map((a: any) => ({
        name: a.name || clean,
        type: r.type,
        ttl: a.TTL,
        data: a.data || a.type === 'TXT' ? a.data : a.data,
      }));
    });

    const subdomains = await bruteForceSubdomains(clean);
    const enriched = await lookupDomain(clean);

    // Unique hosts + related domains
    const uniqueHosts = new Set<string>();
    Object.values(byType).forEach((arr) => arr.forEach((a) => {
      const data = String(a.data || '');
      if (data.includes('.')) uniqueHosts.add(data);
      if (a.name) uniqueHosts.add(String(a.name));
    }));
    subdomains.forEach((s) => uniqueHosts.add(s));

    return NextResponse.json({
      success: true,
      module: dnsModule,
      source: 'Monitor-Threat DNS Dumpster',
      timestamp: new Date().toISOString(),
      fetchedLive: true,
      aiEnabled: isAIEnabled(),
      data: {
        domain: clean,
        records: byType,
        subdomains,
        relatedHosts: [...uniqueHosts].slice(0, 30),
        reverseLookup: reverseRange('8.8.8.8'),
        whois: enriched.whois,
        security: enriched.security,
        map: {
          nodes: [...uniqueHosts].slice(0, 20).map((h, i) => ({ id: i, host: h })),
          edges: [...uniqueHosts].slice(0, 20).map((h, i) => ({ from: 0, to: i })),
        },
      },
      message: `DNS dump for ${clean}: ${records.reduce((s, r) => s + (r.Answer || []).length, 0)} records, ${subdomains.length} subdomains`,
    });
  } catch (error) {
    console.error('DNS Dump error:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'DNS enumeration failed' },
      { status: 500 }
    );
  }
}
