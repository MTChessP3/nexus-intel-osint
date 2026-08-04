import { NextRequest, NextResponse } from 'next/server';
import { lookupDomain } from '@/lib/intel';
import { upsertIOC } from '@/lib/store';

// Domain Intelligence — real DNS (Google DoH) + RDAP WHOIS
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const domain = searchParams.get('domain');

  if (!domain) {
    return NextResponse.json(
      {
        success: false,
        error: 'Domain is required',
        suggestion: 'Enter a valid domain (e.g., google.com or example.com)',
      },
      { status: 400 }
    );
  }

  try {
    const { live, source, dns, whois, security } = await lookupDomain(domain);

    const aCount = dns.A?.Answer?.length || 0;
    const summary =
      dns.A?.Status === 3
        ? 'Domain does not exist (NXDOMAIN)'
        : aCount > 0
          ? `Active domain — ${aCount} A record(s), ${dns.MX?.Answer?.length || 0} MX, ${dns.NS?.Answer?.length || 0} NS`
          : 'Domain queried — review DNS records for details';

    try {
      await upsertIOC({
        type: 'DOMAIN',
        value: domain,
        description: `Domain: ${domain} — ${summary}`,
        severity: security.riskLevel || 'MEDIUM',
        confidence: 85,
        status: security.riskLevel === 'HIGH' ? 'SUSPICIOUS' : 'UNKNOWN',
        source: live ? source : 'fallback',
        rawResponse: JSON.stringify({ dns, whois, security }),
        tags: ['dns', 'recon', security.riskLevel.toLowerCase()],
      });
    } catch (storeError) {
      console.error('Store save error (non-critical):', storeError);
    }

    return NextResponse.json({
      success: true,
      domain,
      timestamp: new Date().toISOString(),
      source,
      fetchedLive: live,
      dns,
      whois,
      securityAnalysis: security,
      summary,
    });
  } catch (error) {
    console.error('Domain Lookup Error:', error);
    return NextResponse.json({
      success: true,
      source: 'emergency-fallback',
      timestamp: new Date().toISOString(),
      fetchedLive: false,
      domain,
      dns: {},
      securityAnalysis: {
        hasSPF: false,
        hasDMARC: false,
        riskLevel: 'HIGH',
        findings: ['Could not complete DNS analysis — showing limited data'],
      },
      error: 'DNS lookup failed, showing cached data',
    });
  }
}
