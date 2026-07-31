import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

// URL Analysis - Real scanning with multiple checks
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const url = searchParams.get('url');
  
  if (!url) {
    return NextResponse.json({ error: 'URL is required' }, { status: 400 });
  }

  try {
    // Extract domain from URL
    let domain: string;
    try {
      const urlObj = new URL(url);
      domain = urlObj.hostname;
    } catch {
      // If not a valid URL, treat as domain
      domain = url;
    }
    
    // Run parallel checks
    const [dnsResult, ipInfo] = await Promise.allSettled([
      // DNS resolution via Google DoH
      fetch(`https://dns.google/resolve?name=${domain}&type=A`, {
        headers: { 'Accept': 'application/dns-json' }
      }).then(r => r.json()),
      
      // IP info for the resolved IP (if we get one)
      fetch(`http://ip-api.com/json/${domain}?fields=status,country,city,isp,org,proxy,hosting`, {
        signal: AbortSignal.timeout(8000)
      }).then(r => r.json())
    ]);
    
    const resultData = {
      url,
      domain,
      timestamp: new Date().toISOString(),
      source: 'Multi-Source',
      fetchedLive: true,
      dns: dnsResult.status === 'fulfilled' ? dnsResult.value : null,
      ipInfo: ipInfo.status === 'fulfilled' ? ipInfo.value : null,
      securityChecks: {
        usesHTTPS: url.startsWith('https'),
        hasPath: url.includes('/'),
        hasQuery: url.includes('?')
      },
      riskAssessment: assessURLRisk(url, dnsResult, ipInfo)
    };
    
    // Save to database
    await db.iOC.upsert({
      where: { value: url },
      update: { lastUpdated: new Date() },
      create: {
        type: 'URL',
        value: url,
        description: `URL Analysis: ${domain}`,
        severity: resultData.riskAssessment.level,
        confidence: resultData.riskAssessment.confidence,
        status: resultData.riskAssessment.status,
        source: 'URL-Scanner',
        rawResponse: JSON.stringify(resultData),
        tags: JSON.stringify(['url', 'scanned'])
      }
    });
    
    return NextResponse.json({
      success: true,
      ...resultData
    });
    
  } catch (error) {
    console.error('URL Analysis Error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to analyze URL',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 502 });
  }
}

function assessURLRisk(
  url: string, 
  dnsResult: PromiseSettledResult<any>, 
  ipResult: PromiseSettledResult<any>
) {
  let score = 50;
  const findings: string[] = [];
  
  // Check protocol
  if (!url.startsWith('https')) {
    score += 15;
    findings.push('WARNING: URL does not use HTTPS encryption');
  }
  
  // Check for suspicious patterns
  if (url.includes('@')) {
    score += 20;
    findings.push('SUSPICIOUS: URL contains @ symbol (possible phishing)');
  }
  if (url.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
    score += 10;
    findings.push('NOTE: URL contains direct IP address');
  }
  if (url.includes('bit.ly') || url.includes('tinyurl') || url.includes('t.co')) {
    score += 10;
    findings.push('NOTE: URL is a shortened link - destination hidden');
  }
  
  // Check DNS results
  if (dnsResult.status === 'fulfilled' && dnsResult.value.Answer) {
    findings.push(`DNS resolves to ${dnsResult.value.Answer.length} address(es)`);
  } else if (dnsResult.status === 'fulfilled' && !dnsResult.value.Answer) {
    score += 25;
    findings.push('WARNING: Domain does not resolve in DNS');
  }
  
  // Check IP info
  if (ipResult.status === 'fulfilled' && ipResult.value.proxy) {
    score += 20;
    findings.push('WARNING: Resolved IP is a known proxy/VPN');
  }
  if (ipResult.status === 'fulfilled' && ipResult.value.hosting) {
    score += 10;
    findings.push('NOTE: Resolved IP belongs to hosting provider');
  }
  
  return {
    level: score >= 70 ? 'HIGH' : score >= 50 ? 'MEDIUM' : 'LOW',
    confidence: Math.max(0, 100 - score),
    status: score >= 70 ? 'SUSPICIOUS' : score >= 50 ? 'UNKNOWN' : 'BENIGN',
    score,
    findings
  };
}
