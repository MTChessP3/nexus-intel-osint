import { NextRequest, NextResponse } from 'next/server';
import { buildDomainIntel } from '@/lib/intel/domain';
import { upsertIOC } from '@/lib/store';

export const maxDuration = 60;

// Domain Intelligence — DNS, email security, WHOIS/RDAP, subdomains (crt.sh),
// IP/ASN infrastructure and risk scoring via the Domain Intel module.
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
    const intel = await buildDomainIntel(domain);

    try {
      await upsertIOC({
        type: 'DOMAIN',
        value: intel.domain,
        description: `Domain: ${intel.domain} — ${intel.summary}`,
        severity: intel.risk.level,
        confidence: 100 - intel.risk.score,
        status: intel.risk.level === 'HIGH' || intel.risk.level === 'CRITICAL' ? 'SUSPICIOUS' : 'UNKNOWN',
        source: intel.source,
        rawResponse: JSON.stringify(intel).substring(0, 3000),
        tags: ['dns', 'recon', intel.risk.level.toLowerCase()],
      });
    } catch (storeError) {
      console.error('Store save error (non-critical):', storeError);
    }

    return NextResponse.json({
      success: true,
      domain: intel.domain,
      timestamp: intel.timestamp,
      source: intel.source,
      fetchedLive: intel.live,
      // Backward-compatible keys used by older UI sections:
      dns: intel.records,
      whois: intel.whois,
      securityAnalysis: {
        hasSPF: intel.emailSecurity.hasSPF,
        hasDMARC: intel.emailSecurity.hasDMARC,
        hasDKIM: intel.emailSecurity.hasDKIM,
        riskLevel: intel.emailSecurity.riskLevel,
        findings: intel.emailSecurity.findings,
      },
      summary: intel.summary,
      // Full Domain Intel payload consumed by the Domain Intel panel:
      domainIntel: intel,
    });
  } catch (error) {
    console.error('Domain Lookup Error:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'Domain lookup failed' },
      { status: 500 }
    );
  }
}
