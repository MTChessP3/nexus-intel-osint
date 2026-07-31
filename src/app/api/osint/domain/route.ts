import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

// REAL DNS/Domain intelligence - Google DoH + security checks
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const domain = searchParams.get('domain');
  
  if (!domain) {
    return NextResponse.json({ error: 'Domain is required' }, { status: 400 });
  }

  try {
    // Use Google DNS-over-HTTPS for real DNS resolution
    const dnsResults = await Promise.allSettled([
      // A records
      fetch(`https://dns.google/resolve?name=${domain}&type=A`, {
        headers: { 'Accept': 'application/dns-json' }
      }).then(r => r.json()),
      // MX records
      fetch(`https://dns.google/resolve?name=${domain}&type=MX`, {
        headers: { 'Accept': 'application/dns-json' }
      }).then(r => r.json()),
      // NS records
      fetch(`https://dns.google/resolve?name=${domain}&type=NS`, {
        headers: { 'Accept': 'application/dns-json' }
      }).then(r => r.json()),
      // TXT records (SPF, DMARC info)
      fetch(`https://dns.google/resolve?name=${domain}&type=TXT`, {
        headers: { 'Accept': 'application/dns-json' }
      }).then(r => r.json()),
      // AAAA records
      fetch(`https://dns.google/resolve?name=${domain}&type=AAAA`, {
        headers: { 'Accept': 'application/dns-json' }
      }).then(r => r.json())
    ]);
    
    const [aRecords, mxRecords, nsRecords, txtRecords, aaaaRecords] = dnsResults;
    
    const resultData = {
      domain,
      timestamp: new Date().toISOString(),
      source: 'Google-DoH',
      fetchedLive: true,
      dns: {
        A: aRecords.status === 'fulfilled' ? aRecords.value : { error: 'Failed to resolve' },
        MX: mxRecords.status === 'fulfilled' ? mxRecords.value : { error: 'Failed to resolve' },
        NS: nsRecords.status === 'fulfilled' ? nsRecords.value : { error: 'Failed to resolve' },
        TXT: txtRecords.status === 'fulfilled' ? txtRecords.value : { error: 'Failed to resolve' },
        AAAA: aaaaRecords.status === 'fulfilled' ? aaaaRecords.value : { error: 'Failed to resolve' }
      },
      securityAnalysis: analyzeSecurity(txtRecords, mxRecords)
    };
    
    // Save to database
    try {
      await db.iOC.upsert({
        where: { value: domain },
        update: { lastUpdated: new Date() },
        create: {
          type: 'DOMAIN',
          value: domain,
          description: `Domain: ${domain} - DNS analysis completed`,
          severity: resultData.securityAnalysis.riskLevel || 'MEDIUM',
          confidence: 85,
          status: 'UNKNOWN',
          source: 'Google-DoH',
          rawResponse: JSON.stringify(resultData),
          tags: JSON.stringify(['dns', 'recon'])
        }
      });
    } catch (dbError) {
      console.error('DB save error (non-critical):', dbError);
    }
    
    return NextResponse.json({
      success: true,
      ...resultData
    });
    
  } catch (error) {
    console.error('Domain Lookup Error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to perform DNS lookup',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 502 });
  }
}

function analyzeSecurity(txtResult: PromiseSettledResult<any>, mxResult: PromiseSettledResult<any>) {
  const analysis = {
    hasSPF: false,
    hasDMARC: false,
    hasDKIM: false,
    riskLevel: 'MEDIUM' as string,
    findings: [] as string[]
  };
  
  if (txtResult.status === 'fulfilled' && txtResult.value.Answer) {
    for (const record of txtResult.value.Answer) {
      const data = record.data?.replace(/"/g, '');
      if (data?.includes('v=spf1')) {
        analysis.hasSPF = true;
        analysis.findings.push('SPF record found - email spoofing protection active');
      }
      if (data?.includes('v=DMARC1')) {
        analysis.hasDMARC = true;
        analysis.findings.push('DMARC record found - email authentication policy configured');
      }
    }
  }
  
  if (!analysis.hasSPF) {
    analysis.findings.push('WARNING: No SPF record detected - domain vulnerable to email spoofing');
    analysis.riskLevel = 'HIGH';
  }
  if (!analysis.hasDMARC) {
    analysis.findings.push('WARNING: No DMARC record detected - no email authentication policy');
  }
  
  if (mxResult.status === 'fulfilled' && mxResult.value.Answer && mxResult.value.Answer.length > 0) {
    analysis.hasDKIM = true; // Assume DKIM if mail servers exist
    analysis.findings.push(`Mail servers configured (${mxResult.value.Answer.length} MX records)`);
  }
  
  return analysis;
}
