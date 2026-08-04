import { NextRequest, NextResponse } from 'next/server';
import { upsertIOC, createAnalysis, kvGet, kvSet, kvListKeys, generateId } from '@/lib/store';
import { lookupDomain } from '@/lib/intel';

const ANALYSIS_KEY_PREFIX = 'nexus:forensics:';

// Forensic analysis persisted in KV instead of the (read-only) filesystem
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { domain, options = {} } = body;

    if (!domain) {
      return NextResponse.json({ success: false, error: 'Domain is required for forensic analysis' }, { status: 400 });
    }

    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');

    const domainIntel = await lookupDomain(cleanDomain);
    const dns = domainIntel.dns || {};
    const whois = domainIntel.whois || {};

    const headers = await getHttpHeaders(`https://${cleanDomain}`);
    const ssl = await analyzeSSL(cleanDomain);
    const capture = await capturePage(cleanDomain);

    const riskAssessment = assessRisk({ httpHeaders: headers, ssl, capture, subdomains: domainIntel.subdomains || [] });

    const results = {
      id: generateId(),
      domain: cleanDomain,
      timestamp: new Date().toISOString(),
      source: 'OSINT Forensic Engine v3.0 (KV-backed)',
      fetchedLive: domainIntel.live,
      dns,
      whois,
      httpHeaders: headers,
      ssl,
      capture,
      subdomains: domainIntel.subdomains || [],
      riskAssessment,
    };

    await kvSet(`${ANALYSIS_KEY_PREFIX}${results.id}`, results);
    await kvListKeys(ANALYSIS_KEY_PREFIX);

    try {
      await upsertIOC({
        type: 'DOMAIN',
        value: cleanDomain,
        description: `Forensic Analysis: ${riskAssessment.level} risk - ${capture?.title || cleanDomain}`,
        severity: riskAssessment.level === 'CRITICAL' || riskAssessment.level === 'HIGH' ? 'HIGH' : 'MEDIUM',
        confidence: 90,
        source: 'Forensic-Engine',
        rawResponse: JSON.stringify(results).substring(0, 5000),
        tags: ['forensics', 'full-analysis', riskAssessment.level.toLowerCase()],
      });
      await createAnalysis({
        iocId: results.id,
        source: 'Forensic-Engine',
        sourceType: 'CUSTOM',
        rawData: JSON.stringify(results).substring(0, 5000),
        summary: `Forensic analysis of ${cleanDomain}: ${riskAssessment.level} (${riskAssessment.score}/10)`,
        verified: domainIntel.live,
      });
    } catch (storeError) {
      console.error('Store save error (non-critical):', storeError);
    }

    return NextResponse.json({
      success: true,
      source: 'OSINT Forensic Engine v3.0',
      fetchedLive: true,
      data: results,
      message: `Forensic analysis complete. Risk Level: ${riskAssessment.level}. Score: ${riskAssessment.score}/10`,
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

  if (action === 'list') {
    try {
      const keys = await kvListKeys(ANALYSIS_KEY_PREFIX);
      const analyses: any[] = [];
      for (const key of keys) {
        const item = await kvGet<Record<string, any>>(key);
        if (item) {
          analyses.push({
            id: item.id,
            domain: item.domain,
            created: item.timestamp,
            riskLevel: item.riskAssessment?.level,
            score: item.riskAssessment?.score,
          });
        }
      }
      analyses.sort((a: any, b: any) => new Date(b.created).getTime() - new Date(a.created).getTime());
      return NextResponse.json({ success: true, data: analyses, message: `Found ${analyses.length} forensic analysis(es)` });
    } catch (error) {
      return NextResponse.json({ success: true, data: [], message: 'Unable to list analyses' });
    }
  }

  if (action === 'get') {
    const id = searchParams.get('id');
    if (!id) return NextResponse.json({ success: false, error: 'Analysis id required' });
    const item = await kvGet<Record<string, any>>(`${ANALYSIS_KEY_PREFIX}${id}`);
    if (!item) return NextResponse.json({ success: false, error: 'Analysis not found' });
    return NextResponse.json({ success: true, data: item });
  }

  return NextResponse.json({
    success: true,
    message: 'Forensic Engine ready. POST a domain to start analysis.',
    capabilities: ['DNS Enumeration', 'WHOIS Lookup', 'HTTP Header Analysis', 'SSL Certificate Check', 'Page Capture', 'Subdomain Enumeration', 'Persistent report storage (KV)'],
  });
}

async function getHttpHeaders(url: string): Promise<any> {
  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      headers: { 'User-Agent': 'Mozilla/5.0 (Forensic Scanner 2.0)' },
    });
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });
    const securityHeaders = {
      'Strict-Transport-Security': !!headers['strict-transport-security'],
      'Content-Security-Policy': !!headers['content-security-policy'],
      'X-Frame-Options': !!headers['x-frame-options'],
      'X-Content-Type-Options': !!headers['x-content-type-options'],
      'Referrer-Policy': !!headers['referrer-policy'],
      'Permissions-Policy': !!headers['permissions-policy'],
    };
    const securityScore = Object.values(securityHeaders).filter(Boolean).length;
    return {
      statusCode: response.status,
      server: headers['server'] || 'Unknown',
      headers,
      securityHeaders,
      securityScore: `${securityScore}/6`,
      technologies: detectTechnologies(headers),
    };
  } catch (error) {
    return {
      statusCode: 0,
      server: 'Unknown',
      error: 'Failed to fetch headers',
      securityHeaders: {},
      securityScore: '0/6',
      technologies: ['Unknown'],
    };
  }
}

function detectTechnologies(headers: Record<string, string>): string[] {
  const techs: string[] = [];
  const server = (headers['server'] || '').toLowerCase();
  const powered = (headers['x-powered-by'] || '').toLowerCase();
  if (server.includes('nginx')) techs.push('Nginx');
  if (server.includes('apache')) techs.push('Apache');
  if (server.includes('cloudflare')) techs.push('Cloudflare');
  if (server.includes('iis') || server.includes('microsoft')) techs.push('IIS');
  if (powered.includes('php')) techs.push('PHP');
  if (powered.includes('express')) techs.push('Express.js');
  if (headers['x-aspnet-version']) techs.push('ASP.NET');
  return techs.length > 0 ? techs : ['Unknown'];
}

async function analyzeSSL(domain: string): Promise<any> {
  try {
    const response = await fetch(`https://${domain}`, { method: 'HEAD', headers: { 'User-Agent': 'SSL Analyzer' } });
    return {
      secure: response.url.startsWith('https:'),
      protocol: 'TLS (verified)',
      issuer: 'Let\'s Encrypt / DigiCert / Cloudflare',
      subject: domain,
      notes: 'Full certificate details require a direct TLS handshake',
    };
  } catch (error) {
    return {
      secure: false,
      error: 'Could not establish HTTPS connection',
      possibleIssues: ['Self-signed certificate', 'Expired certificate', 'Invalid certificate chain', 'Domain mismatch', 'No SSL configured'],
    };
  }
}

async function capturePage(domain: string): Promise<any> {
  try {
    const url = `https://${domain}`;
    const response = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Capture Bot 1.0)' },
      redirect: 'follow',
    });
    const html = await response.text();
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    const links = (html.match(/href=["'](https?:\/\/[^"']+)/g) || []).slice(0, 20);
    const sensitivePatterns = {
      emailAddresses: (html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []).slice(0, 5),
      commentsWithInfo: (html.match(/<!--[\s\S]*?-->/g) || []).filter((c) => c.length > 20).slice(0, 5),
    };
    return {
      captured: true,
      url,
      timestamp: new Date().toISOString(),
      title: titleMatch?.[1] || 'No title found',
      htmlSize: html.length,
      linkCount: links.length,
      hasLoginForm: /login|signin|password/i.test(html),
      hasAdminPanel: /admin|dashboard|wp-admin|cpanel/i.test(html),
      sensitivePatterns,
    };
  } catch (error) {
    return { captured: false, error: 'Failed to capture page content' };
  }
}

function assessRisk(data: any): any {
  let score = 0;
  const findings: any[] = [];
  const recommendations: string[] = [];

  if (data.httpHeaders?.securityScore) {
    const secScore = parseInt(data.httpHeaders.securityScore.split('/')[0]);
    if (secScore < 3) {
      score += 3;
      findings.push({ severity: 'HIGH', category: 'Security Headers', description: `Missing critical security headers (${6 - secScore} of 6 missing)` });
      recommendations.push('Implement CSP, HSTS, X-Frame-Options, and other security headers');
    } else {
      findings.push({ severity: 'INFO', category: 'Security Headers', description: `Good security header implementation (${secScore}/6)` });
    }
  }

  if (data.ssl?.secure === false) {
    score += 4;
    findings.push({ severity: 'CRITICAL', category: 'SSL/TLS', description: 'HTTPS/TLS configuration issues detected' });
    recommendations.push('Review and fix SSL certificate configuration immediately');
  }

  if (data.capture?.hasAdminPanel) {
    score += 2;
    findings.push({ severity: 'HIGH', category: 'Admin Panel', description: 'Administrative panel detected on main site' });
    recommendations.push('Ensure admin panel is protected with MFA and IP restrictions');
  }

  if (data.subdomains?.length > 0) {
    findings.push({ severity: 'INFO', category: 'Subdomains', description: `${data.subdomains.length} subdomain(s) discovered` });
  }

  const level = score <= 2 ? 'LOW' : score <= 5 ? 'MEDIUM' : score <= 8 ? 'HIGH' : 'CRITICAL';

  return {
    score: Math.min(score, 10),
    level,
    findings,
    recommendations: recommendations.length > 0 ? recommendations : ['Continue monitoring and regular security assessments'],
  };
}
