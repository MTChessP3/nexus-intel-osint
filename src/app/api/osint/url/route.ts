import { NextRequest, NextResponse } from 'next/server';
import { scanUrl } from '@/lib/intel/scanner';
import { upsertIOC, createAlert, generateId } from '@/lib/store';
import { kvPushList, kvGetList } from '@/lib/kv';

export const maxDuration = 60;

const JOBS_KEY = 'nexus:url:jobs';

interface ScanJob {
  id: string;
  url: string;
  status: 'COMPLETED';
  verdict: string;
  score: number;
  startedAt: string;
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const action = searchParams.get('action');

  if (action === 'jobs') {
    const jobs = await kvGetList<ScanJob>(JOBS_KEY);
    return NextResponse.json({ success: true, data: jobs.slice(0, 20), message: `${jobs.length} scan job(s)` });
  }

  const url = searchParams.get('url');
  if (!url) {
    return NextResponse.json(
      { success: false, error: 'URL is required', suggestion: 'Enter a valid URL (e.g., https://example.com/page)' },
      { status: 400 }
    );
  }

  try {
    const result = await scanUrl(url);

    const job: ScanJob = {
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
        description: `URL Scanner: ${result.verdict.level} (${result.verdict.score}/100) — ${result.verdict.reasons.slice(0, 3).join('; ')}`,
        severity: result.verdict.level === 'MALICIOUS' ? 'HIGH' : result.verdict.level === 'SUSPICIOUS' ? 'MEDIUM' : 'LOW',
        confidence: 80,
        status: result.verdict.level === 'MALICIOUS' ? 'MALICIOUS' : result.verdict.level === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'UNKNOWN',
        source: 'URL-Scanner',
        rawResponse: JSON.stringify(result).substring(0, 8000),
        tags: ['url-scanner', result.verdict.level.toLowerCase(), ...result.kit.matches.map((m) => m.family.toLowerCase().replace(/\s+/g, '-'))],
      });
      if (result.verdict.level === 'MALICIOUS') {
        await createAlert({
          iocId: job.id,
          title: `Malicious URL scanned: ${result.url}`,
          description: `Attack-surface score ${result.verdict.score}/100. ${result.verdict.reasons.slice(0, 4).join('; ')}`,
          severity: 'HIGH',
          type: 'URL_SCAN',
        });
      }
    } catch (e) {
      console.error('Scanner store error (non-critical):', e);
    }

    return NextResponse.json({
      success: true,
      source: result.source,
      timestamp: result.timestamp,
      fetchedLive: true,
      url: result.url,
      domain: result.host,
      riskAssessment: {
        level: result.verdict.level,
        score: result.verdict.score,
        status: result.verdict.level === 'MALICIOUS' ? 'MALICIOUS' : result.verdict.level === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'BENIGN',
        findings: result.verdict.reasons,
        safeBrowsing: 'Attack-surface scan (real)',
      },
      data: result,
      message: `URL scan complete: ${result.verdict.level} (${result.verdict.score}/100)`,
    });
  } catch (error) {
    console.error('URL Scanner Error:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'URL scan failed' },
      { status: 500 }
    );
  }
}
