import { NextRequest, NextResponse } from 'next/server';
import { upsertIOC, createAnalysis } from '@/lib/store';
import { kvGet, kvSet, kvListKeys, kvDel } from '@/lib/kv';
import { lookupVirusTotalDomain } from '@/lib/intel/virustotal';
import { runForensicAnalysis, ForensicMetadata } from '@/lib/intel/forensics';
import { buildZip, mirrorUrls, mimeForPath } from '@/lib/intel/wgetExport';

export const maxDuration = 300;

const ANALYSIS_KEY_PREFIX = 'nexus:forensics:';
const INDEX_KEY = 'nexus:forensics:index';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { domain, action } = body;

    // wget-style bulk export: mirror all discovered paths into a ZIP
    if (action === 'wget') {
      const urls = Array.isArray(body.urls) ? body.urls.slice(0, 60) : [];
      if (urls.length === 0) {
        return NextResponse.json({ success: false, error: 'No paths to mirror' }, { status: 400 });
      }
      const files = await mirrorUrls(urls.map((u: any) => ({ url: String(u.url), name: String(u.name || '') })));
      if (files.length === 0) {
        return NextResponse.json({ success: false, error: 'No path content could be downloaded (all blocked/empty)' }, { status: 502 });
      }
      const zip = buildZip(files);
      const safeDomain = String(domain || 'target').replace(/[^a-zA-Z0-9._-]/g, '_');
      return new NextResponse(new Uint8Array(zip), {
        status: 200,
        headers: {
          'Content-Type': 'application/zip',
          'Content-Disposition': `attachment; filename="analisis_${safeDomain}_wget.zip"`,
          'Content-Length': String(zip.length),
        },
      });
    }

    if (!domain) {
      return NextResponse.json({ success: false, error: 'Domain is required for forensic analysis' }, { status: 400 });
    }

    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');

    const results = await runForensicAnalysis(cleanDomain);
    const vt = await lookupVirusTotalDomain(cleanDomain).catch(() => null);

    const containerName = results.name;
    const containerKey = `${ANALYSIS_KEY_PREFIX}${containerName}`;

    await kvSet(containerKey, results);

    try {
      const index = (await kvGet<string[]>(INDEX_KEY)) || [];
      if (!index.includes(containerName)) {
        index.push(containerName);
        await kvSet(INDEX_KEY, index.slice(-100));
      }
    } catch { /* index best-effort */ }

    try {
      await upsertIOC({
        type: 'DOMAIN',
        value: cleanDomain,
        description: `Forensic Analysis: ${results.risk.level} risk - ${results.fuzzingSummary.exposed} exposed paths, ${results.artifacts.filter(a => a.category === 'phishing_kit').length} kit(s), ${results.artifacts.filter(a => a.category === 'database').length} db(s)`,
        severity: results.risk.level === 'CRITICAL' || results.risk.level === 'HIGH' ? 'HIGH' : 'MEDIUM',
        confidence: 90,
        status: results.risk.level === 'CRITICAL' ? 'MALICIOUS' : results.risk.level === 'HIGH' ? 'SUSPICIOUS' : 'UNKNOWN',
        source: 'Forensic-Engine',
        rawResponse: JSON.stringify(results).substring(0, 8000),
        tags: ['forensics', 'full-analysis', 'live-crawl', 'fuzzing', 'phishing-kit', 'db-exposure', results.risk.level.toLowerCase(), ...(vt?.verdict ? [`vt:${vt.verdict.toLowerCase()}`] : [])],
      });
      await createAnalysis({
        iocId: results.id,
        source: 'Forensic-Engine',
        sourceType: 'CUSTOM',
        rawData: JSON.stringify(results).substring(0, 8000),
        summary: `Forensic analysis of ${cleanDomain}: ${results.risk.level} (${results.risk.score}/100), ${results.fuzzingSummary.totalProbed} paths probed, ${results.fuzzingSummary.exposed} exposed, ${results.artifacts.filter(a => a.downloaded).length} artifacts downloaded`,
        verified: true,
      });
    } catch (storeError) {
      console.error('Store save error (non-critical):', storeError);
    }

    return NextResponse.json({
      success: true,
      source: 'Advanced Web Forensic Engine v5.1 (Lookyloo-style)',
      fetchedLive: true,
      data: { ...results, virusTotal: vt },
      message: `Forensic analysis complete. Risk Level: ${results.risk.level}. Score: ${results.risk.score}/100. Crawled: ${Object.keys(results.resourceTree.children || {}).length} pages, Fuzzed: ${results.fuzzingSummary.totalProbed} paths, Artifacts: ${results.artifacts.filter(a => a.downloaded).length}`,
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

  if (action === 'content') {
    const url = searchParams.get('url') || '';
    if (!/^https?:\/\//i.test(url)) {
      return NextResponse.json({ success: false, error: 'Invalid URL (must be http/https)' }, { status: 400 });
    }
    try {
      const res = await fetch(url, {
        redirect: 'follow',
        headers: { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) NEXUS-Forensic/5.1' },
        signal: AbortSignal.timeout(20000),
      });
      if (!res.ok) {
        return NextResponse.json({ success: false, error: `Target returned HTTP ${res.status}` }, { status: 502 });
      }
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.length > 10 * 1024 * 1024) {
        return NextResponse.json({ success: false, error: 'Content too large (>10MB)' }, { status: 413 });
      }
      const path = new URL(url).pathname;
      const rawName = path.split('/').filter(Boolean).pop() || 'resource.html';
      const safeName = rawName.replace(/[\\/:*?"<>|]/g, '_').slice(0, 80) || 'resource.html';
      return new NextResponse(new Uint8Array(buf), {
        status: 200,
        headers: {
          'Content-Type': mimeForPath(rawName),
          'Content-Disposition': `attachment; filename="${safeName}"`,
          'Content-Length': String(buf.length),
        },
      });
    } catch (error) {
      return NextResponse.json({ success: false, error: 'Content fetch failed (timeout/blocked)' }, { status: 502 });
    }
  }

  if (action === 'list') {
    try {
      const index = (await kvGet<string[]>(INDEX_KEY)) || [];
      const analyses: any[] = [];
      for (const name of index) {
        const item = await kvGet<Record<string, any>>(`${ANALYSIS_KEY_PREFIX}${name}`);
        if (item) {
          analyses.push({
            id: item.id,
            name: item.name,
            domain: item.domain,
            ip: item.ip,
            asn: item.asn,
            isp: item.isp,
            created: item.timestamp,
            riskLevel: item.risk?.level,
            score: item.risk?.score,
            kits: item.artifacts?.filter((a: any) => a.category === 'phishing_kit' && a.downloaded).length || 0,
            databases: item.artifacts?.filter((a: any) => a.category === 'database' && a.downloaded).length || 0,
            pagesCrawled: item.resourceTree ? countNodes(item.resourceTree) : 0,
            fuzzed: item.fuzzingSummary?.totalProbed || 0,
            exposed: item.fuzzingSummary?.exposed || 0,
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

  if (action === 'tree') {
    if (!idParam) return NextResponse.json({ success: false, error: 'Analysis id/name required' });
    const item = await kvGet<Record<string, any>>(`${ANALYSIS_KEY_PREFIX}${idParam}`);
    if (!item) return NextResponse.json({ success: false, error: 'Analysis resource not found' });
    return NextResponse.json({ success: true, data: item.resourceTree });
  }

  return NextResponse.json({
    success: true,
    message: 'Advanced Web Forensic Engine ready. POST a domain to start live capture analysis.',
    capabilities: ['Live Crawl (gospider-style, max depth 3, 45 pages + robots.txt/sitemap.xml seeding)', 'JS Secret + API Endpoint Extraction (SecretFinder-style)', 'Directory Fuzzing (ffuf/dirb-style, 220+ paths + recursive fuzzing inside discovered dirs + crawl-discovered dirs)', 'Directory Listing Crawl (wget -r style, Apache/nginx indexes)', 'Artifact Deep Analysis (wget/curl-style): ZIP/TAR.GZ internal file trees, SQL schema/table/email parsing, SQLite scan, config key parsing', 'Resource Tree (interactive, requests/redirects/dependencies)', 'Infrastructure Graph (DNS/MX/NS/Subdomains/Hosting)', 'Evidence Download (phishing kits, databases, configs, backups)', 'Per-path content download (wget-style) + bulk ZIP export'],
  });
}

function countNodes(node: any): number {
  if (!node) return 0;
  let count = 1;
  if (node.children && Array.isArray(node.children)) {
    for (const child of node.children) count += countNodes(child);
  }
  return count;
}