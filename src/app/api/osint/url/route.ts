import { NextRequest, NextResponse } from 'next/server';
import { lookupDomain } from '@/lib/intel';
import { upsertIOC } from '@/lib/store';

// URL Analysis — heuristics engine + real DNS/IP enrichment
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const url = searchParams.get('url');

  if (!url) {
    return NextResponse.json(
      {
        success: false,
        error: 'URL is required',
        suggestion: 'Enter a valid URL (e.g., https://example.com/page)',
      },
      { status: 400 }
    );
  }

  try {
    let domain: string;
    try {
      domain = new URL(url).hostname;
    } catch {
      domain = url.replace(/^https?:\/\//, '').split('/')[0];
    }

    const domainIntel = await lookupDomain(domain);
    const dnsResult = domainIntel.dns?.A || null;
    const ipData = dnsResult?.Answer?.[0]?.data || null;

    const riskAssessment = assessURLRisk(url, domainIntel, ipData);

    const resultData = {
      url,
      domain,
      timestamp: new Date().toISOString(),
      source: domainIntel.live ? 'Multi-Source-Analysis' : 'cached-data',
      fetchedLive: domainIntel.live,
      dns: domainIntel.dns,
      securityChecks: {
        usesHTTPS: url.startsWith('https'),
        hasPath: url.includes('/'),
        hasQuery: url.includes('?'),
        hasSuspiciousChars: /[@%]/.test(url),
        isIPAddress: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain),
        isShortened: /bit\.ly|tinyurl|t\.co|goo\.gl|short\.link/i.test(domain),
      },
      riskAssessment,
      recommendations: generateRecommendations(riskAssessment),
    };

    try {
      await upsertIOC({
        type: 'URL',
        value: url,
        description: `URL Analysis: ${domain} — ${riskAssessment.level} risk`,
        severity: riskAssessment.level,
        confidence: riskAssessment.confidence,
        status: riskAssessment.status,
        source: 'URL-Scanner',
        rawResponse: JSON.stringify(resultData).substring(0, 3000),
        tags: ['url', 'scanned', riskAssessment.level.toLowerCase()],
      });
    } catch (storeError) {
      console.error('Store save error (non-critical):', storeError);
    }

    return NextResponse.json({
      success: true,
      ...resultData,
      data: resultData,
      message: `URL analysis complete. Risk Level: ${riskAssessment.level}`,
    });
  } catch (error) {
    console.error('URL Analysis Error:', error);
    const fallback = {
      level: 'MEDIUM',
      confidence: 50,
      status: 'UNKNOWN',
      score: 50,
      category: 'Unclassified',
      safeBrowsing: 'Not checked',
      indicators: [] as string[],
      findings: ['Could not complete full analysis — showing partial results'],
    };
    return NextResponse.json({
      success: true,
      source: 'emergency-fallback',
      timestamp: new Date().toISOString(),
      fetchedLive: false,
      url,
      domain: url.replace(/^https?:\/\//, '').split('/')[0],
      securityChecks: { usesHTTPS: url.startsWith('https'), hasPath: true, hasQuery: url.includes('?') },
      riskAssessment: fallback,
      data: { riskAssessment: fallback },
      message: 'Partial analysis completed',
    });
  }
}

function assessURLRisk(url: string, domainIntel: any, ipData: string | null): any {
  let score = 30;
  const findings: string[] = [];

  if (!url.startsWith('https')) {
    score += 20;
    findings.push('WARNING: URL does not use HTTPS encryption');
  } else {
    findings.push('URL uses HTTPS encryption');
  }

  if (url.includes('@')) {
    score += 25;
    findings.push('SUSPICIOUS: URL contains @ symbol (possible phishing attempt)');
  }
  if (url.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
    score += 15;
    findings.push('NOTE: URL contains direct IP address instead of domain');
  }
  if (/bit\.ly|tinyurl|t\.co|goo\.gl|short\.link/i.test(url)) {
    score += 10;
    findings.push('NOTE: URL is a shortened link — actual destination hidden');
  }

  if (ipData) {
    findings.push(`DNS resolves to ${ipData}`);
  } else if (domainIntel.dns?.A?.Status === 3) {
    score += 25;
    findings.push('WARNING: Domain does not exist (NXDOMAIN)');
  }

  if (domainIntel.security?.hasSPF) {
    findings.push('Domain has SPF configured');
  } else if (domainIntel.live) {
    score += 5;
    findings.push('Domain missing SPF record');
  }

  const level = score >= 70 ? 'HIGH' : score >= 50 ? 'MEDIUM' : 'LOW';
  const status = score >= 70 ? 'SUSPICIOUS' : score >= 50 ? 'UNKNOWN' : 'BENIGN';

  return {
    level,
    confidence: Math.max(20, 100 - score),
    status,
    score,
    category: score >= 70 ? 'High Risk' : score >= 50 ? 'Caution' : 'Low Risk',
    safeBrowsing: 'Not checked (add SAFE_BROWSING_API_KEY)',
    indicators: [],
    findings,
  };
}

function generateRecommendations(riskAssessment: any): string[] {
  if (riskAssessment.score >= 70) {
    return [
      'DO NOT visit this URL without proper sandboxing',
      'Report this URL to phishing reporting services',
      'Block at network perimeter if possible',
      'Alert security team for investigation',
    ];
  }
  if (riskAssessment.score >= 50) {
    return [
      'Exercise caution when accessing this URL',
      'Verify the legitimacy of the site before entering credentials',
      'Consider accessing via isolated environment first',
    ];
  }
  return [
    'Standard precautions apply',
    'Verify HTTPS certificate validity',
    'Monitor for any suspicious behavior',
  ];
}
