import { NextRequest, NextResponse } from 'next/server';
import { runSandbox } from '@/lib/intel/sandbox';
import { upsertIOC, createAlert, generateId } from '@/lib/store';
import { kvPushList, kvGetList } from '@/lib/kv';

export const maxDuration = 60;

const JOBS_KEY = 'nexus:sandbox:jobs';

interface SandboxJob {
  id: string;
  url: string;
  status: 'COMPLETED';
  verdict: string;
  score: number;
  startedAt: string;
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { url, external } = body;
    if (!url) {
      return NextResponse.json({ success: false, error: 'URL is required' }, { status: 400 });
    }

    const result = await runSandbox(url, { external: Boolean(external) });

    const job: SandboxJob = {
      id: generateId(),
      url: result.url,
      status: 'COMPLETED',
      verdict: result.verdict.level,
      score: result.verdict.score,
      startedAt: result.timestamp,
    };
    await kvPushList(JOBS_KEY, job, 50).catch(() => {});

    try {
      await upsertIOC({
        type: 'URL',
        value: result.url,
        description: `Sandbox (${result.external ? 'hybrid' : 'real'}): ${result.verdict.level} (${result.verdict.score}/100) — ${result.verdict.reasons.slice(0, 3).join('; ')}`,
        severity: result.verdict.level === 'MALICIOUS' ? 'HIGH' : result.verdict.level === 'SUSPICIOUS' ? 'MEDIUM' : 'LOW',
        confidence: 85,
        status: result.verdict.level === 'MALICIOUS' ? 'MALICIOUS' : result.verdict.level === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'UNKNOWN',
        source: 'URL-Sandbox',
        rawResponse: JSON.stringify(result).substring(0, 8000),
        tags: ['sandbox', result.verdict.level.toLowerCase(), ...result.staticFlags.map((f) => f.category)],
      });
      if (result.verdict.level === 'MALICIOUS') {
        await createAlert({
          iocId: job.id,
          title: `Malicious URL detonated: ${result.url}`,
          description: `Sandbox score ${result.verdict.score}/100. ${result.verdict.reasons.slice(0, 4).join('; ')}`,
          severity: 'HIGH',
          type: 'SANDBOX_DETONATION',
        });
      }
    } catch (e) {
      console.error('Sandbox store error (non-critical):', e);
    }

    return NextResponse.json({
      success: true,
      source: result.source,
      timestamp: result.timestamp,
      fetchedLive: true,
      data: result,
      message: `Sandbox analysis complete: ${result.verdict.level} (${result.verdict.score}/100)`,
    });
  } catch (error) {
    console.error('Sandbox error:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'Sandbox analysis failed' },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action');
  if (action === 'jobs') {
    const jobs = await kvGetList<SandboxJob>(JOBS_KEY);
    return NextResponse.json({ success: true, data: jobs.slice(0, 20), message: `${jobs.length} sandbox job(s)` });
  }
  return NextResponse.json({
    success: true,
    source: 'NEXUS URL Sandbox',
    data: {
      capabilities: [
        'Real redirect chain capture',
        'HTTP fingerprint (headers / server / timing)',
        'TLS certificate inspection (issuer / SAN / expiry)',
        'HTML content analysis (forms, iframes, obfuscation, tokens)',
        'Referenced resource probing',
        'DNSBL / Tor / URLhaus reputation (via IP enrichment)',
        'RDAP WHOIS age & expiry',
        'Real screenshot (WordPress mshots)',
        'External dynamic detonation: Hybrid Analysis, Joe Sandbox, ANY.RUN (optional, API keys required)',
      ],
      engines: ['NEXUS Real Sandbox v1.0', 'Hybrid Analysis', 'Joe Sandbox', 'ANY.RUN'],
      note: 'Runs from the API runtime — no external API key required for base engine',
    },
  });
}
