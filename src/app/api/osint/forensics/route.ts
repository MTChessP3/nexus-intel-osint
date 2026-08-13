import { NextRequest, NextResponse } from 'next/server';
import { upsertIOC, createAnalysis, generateId } from '@/lib/store';
import { kvGet, kvSet, kvListKeys, kvDel } from '@/lib/kv';
import { lookupVirusTotalDomain } from '@/lib/intel/virustotal';
import { runForensicAnalysis } from '@/lib/intel/forensics';

export const maxDuration = 120;

const ANALYSIS_KEY_PREFIX = 'nexus:forensics:';
const INDEX_KEY = 'nexus:forensics:index';

// Advanced Web Forensic Module — per-site resource containers:
// /analisis_[dominio]_[timestamp]/ -> fuzzing tree, artifacts, phishing kits,
// databases and attribution metadata, persisted in KV.
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { domain, options = {} } = body;

    if (!domain) {
      return NextResponse.json({ success: false, error: 'Domain is required for forensic analysis' }, { status: 400 });
    }

    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');

    const results = await runForensicAnalysis(cleanDomain);
    const vt = await lookupVirusTotalDomain(cleanDomain).catch(() => null);

    // Persist as a resource container in KV
    await kvSet(`${ANALYSIS_KEY_PREFIX}${results.id}`, results);

    // Maintain a lightweight index for the resource list
    try {
      const index = (await kvGet<string[]>(INDEX_KEY)) || [];
      index.push(results.id);
      await kvSet(INDEX_KEY, index.slice(-100));
    } catch { /* index best-effort */ }

    try {
      await upsertIOC({
        type: 'DOMAIN',
        value: cleanDomain,
        description: `Forensic Analysis: ${results.risk.level} risk - ${results.phishingKits.length} kit(s), ${results.databases.length} db file(s) exposed`,
        severity: results.risk.level === 'CRITICAL' || results.risk.level === 'HIGH' ? 'HIGH' : 'MEDIUM',
        confidence: 90,
        status: results.risk.level === 'CRITICAL' ? 'MALICIOUS' : results.risk.level === 'HIGH' ? 'SUSPICIOUS' : 'UNKNOWN',
        source: 'Forensic-Engine',
        rawResponse: JSON.stringify(results).substring(0, 5000),
        tags: ['forensics', 'full-analysis', 'fuzzing', 'phishing-kit', 'db-exposure', results.risk.level.toLowerCase(), ...(vt?.verdict ? [`vt:${vt.verdict.toLowerCase()}`] : [])],
      });
      await createAnalysis({
        iocId: results.id,
        source: 'Forensic-Engine',
        sourceType: 'CUSTOM',
        rawData: JSON.stringify(results).substring(0, 5000),
        summary: `Forensic analysis of ${cleanDomain}: ${results.risk.level} (${results.risk.score}/100), ${results.phishingKits.length} phishing kits, ${results.databases.length} databases`,
        verified: true,
      });
    } catch (storeError) {
      console.error('Store save error (non-critical):', storeError);
    }

    return NextResponse.json({
      success: true,
      source: 'Advanced Web Forensic Engine v4.0',
      fetchedLive: true,
      data: { ...results, virusTotal: vt },
      message: `Forensic analysis complete. Risk Level: ${results.risk.level}. Score: ${results.risk.score}/100`,
    });
  } catch (error) {
    console.error('Forensic analysis error:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'Analysis failed', suggestion: 'Verify domain name and try again' },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action');
  const idParam = searchParams.get('id') || searchParams.get('name') || '';

  if (action === 'list') {
    try {
      const index = (await kvGet<string[]>(INDEX_KEY)) || [];
      const keys = index.length > 0 ? index.map((i) => `${ANALYSIS_KEY_PREFIX}${i}`) : await kvListKeys(ANALYSIS_KEY_PREFIX);
      const analyses: any[] = [];
      for (const key of keys) {
        const item = await kvGet<Record<string, any>>(key);
        if (item) {
          analyses.push({
            id: item.id,
            name: item.name,
            domain: item.domain,
            ip: item.ip,
            created: item.timestamp,
            riskLevel: item.risk?.level,
            score: item.risk?.score,
            kits: item.phishingKits?.length || 0,
            databases: item.databases?.length || 0,
          });
        }
      }
      analyses.sort((a: any, b: any) => new Date(b.created).getTime() - new Date(a.created).getTime());
      return NextResponse.json({ success: true, data: analyses, message: `Found ${analyses.length} forensic resource(s)` });
    } catch (error) {
      return NextResponse.json({ success: true, data: [], message: 'Unable to list analyses' });
    }
  }

  if (action === 'get') {
    if (!idParam) return NextResponse.json({ success: false, error: 'Analysis id/name required' });
    const item = await kvGet<Record<string, any>>(`${ANALYSIS_KEY_PREFIX}${idParam}`);
    if (!item) return NextResponse.json({ success: false, error: 'Analysis resource not found' });
    return NextResponse.json({ success: true, data: item });
  }

  if (action === 'delete') {
    if (!idParam) return NextResponse.json({ success: false, error: 'Analysis id required' });
    await kvDel(`${ANALYSIS_KEY_PREFIX}${idParam}`);
    const index = (await kvGet<string[]>(INDEX_KEY)) || [];
    await kvSet(INDEX_KEY, index.filter((i) => i !== idParam));
    return NextResponse.json({ success: true, message: 'Analysis resource deleted' });
  }

  return NextResponse.json({
    success: true,
    message: 'Advanced Web Forensic Engine ready. POST a domain to start analysis.',
    capabilities: ['DNS Recon (A/AAAA/MX/TXT/NS/CNAME)', 'Subdomain Enumeration (crt.sh)', 'Directory Fuzzing (exposed paths)', 'Phishing Kit Detection (.zip/.rar/.tar.gz)', 'Database Exposure (.sql/.db)', 'Source Attribution (emails/telegram/tracking/API keys)', 'Per-site resource containers (fuzzing_tree/artifacts/phishing_kits/databases/_metadata)'],
  });
}