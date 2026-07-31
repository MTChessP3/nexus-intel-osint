import { NextRequest, NextResponse } from 'next/server';

// Domain Analysis API
// Uses Google DNS-over-HTTPS for REAL DNS resolution
// Compatible with Vercel serverless environment

export const runtime = 'nodejs';
export const maxDuration = 30;

export async function POST(request: NextRequest) {
  try {
    const { domain } = await request.json();
    
    if (!domain) {
      return NextResponse.json({ error: 'Se requiere un dominio' }, { status: 400 });
    }

    // Validate domain format
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    
    if (!domainRegex.test(cleanDomain) || cleanDomain.length > 253) {
      return NextResponse.json({ error: 'Formato de dominio inválido', suggestion: 'Ejemplo: google.com, example.org' }, { status: 400 });
    }

    // Use multiple REAL DNS services
    const [dnsInfo, securityInfo] = await Promise.allSettled([
      getDNSInfo(cleanDomain),
      getSecurityInfo(cleanDomain)
    ]);

    const dns = dnsInfo.status === 'fulfilled' ? dnsInfo.value : null;
    const security = securityInfo.status === 'fulfilled' ? securityInfo.value : null;

    // Try WHOIS but don't fail if it doesn't work
    let whoisInfo = null;
    try {
      const whoisResult = await getWHOISInfo(cleanDomain);
      whoisInfo = whoisResult;
    } catch (e) {
      console.log('[DOMAIN] WHOIS unavailable, continuing without it');
      whoisInfo = {
        registrar: 'No disponible',
        creationDate: null,
        expiryDate: null,
        registrantCountry: null,
        nameServers: [],
        ageDays: null,
        privacyEnabled: null,
        error: 'Servicio WHOIS temporalmente no disponible'
      };
    }

    // Calculate reputation score
    let reputationScore = 70; // Start neutral
    const indicators: string[] = [];
    const recommendations: string[] = [];

    if (security?.malicious) {
      reputationScore -= 40;
      indicators.push('🔴 Dominio marcado como malicioso');
      recommendations.push('BLOQUEAR este dominio inmediatamente');
    }

    if (whoisInfo?.ageDays && whoisInfo.ageDays < 30 && whoisInfo.ageDays !== null) {
      reputationScore -= 15;
      indicators.push('🟠 Dominio muy reciente (< 30 días)');
      recommendations.push('Mayor sospecha - dominios nuevos son comúnmente maliciosos');
    }

    if (dns?.hasSPF === false) {
      reputationScore -= 10;
      indicators.push('⚠️ Sin registro SPF configurado');
      recommendations.push('Configurar SPF para seguridad de email');
    }

    if (dns?.hasDMARC === false) {
      reputationScore -= 5;
      indicators.push('⚠️ Sin política DMARC');
      recommendations.push('Implementar DMARC para protección contra phishing');
    }

    if (whoisInfo?.privacyEnabled === true) {
      reputationScore -= 5;
      indicators.push('ℹ️ WHOIS privacy activado');
    }

    // Determine final level
    let level = 'SEGURO';
    let color = '#22c55e';
    if (reputationScore <= 30) { level = 'PELIGROSO'; color = '#dc2626'; }
    else if (reputationScore <= 50) { level = 'SOSPECHOSO'; color = '#f97316'; }
    else if (reputationScore <= 70) { level = 'CAUTELA'; color = '#eab308'; }

    if (indicators.length === 0) {
      indicators.push('✅ Sin indicadores negativos encontrados');
      recommendations.push('Dominio aparentemente seguro - mantener monitoreo normal');
    }

    const result = {
      domain: cleanDomain,
      whois: whoisInfo || { error: 'No se pudo obtener información WHOIS' },
      dns: dns || { error: 'No se pudo obtener registros DNS' },
      security: security || { error: 'No se pudo verificar seguridad' },
      reputation: {
        score: Math.max(0, Math.min(100, Math.round(reputationScore))),
        level,
        color,
        indicators,
        recommendations
      },
      metadata: {
        analyzedAt: new Date().toISOString(),
        sources: ['Google DNS-over-HTTPS', 'Heuristic Security Analysis']
      }
    };

    return NextResponse.json({ success: true, data: result });

  } catch (error: any) {
    console.error('[DOMAIN] Error:', error);
    return NextResponse.json(
      { error: 'Error al analizar el dominio', details: error.message },
      { status: 500 }
    );
  }
}

async function getDNSInfo(domain: string): Promise<any> {
  try {
    // Use Google DNS-over-HTTPS for real DNS resolution
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(`https://dns.google/resolve?name=${domain}&type=A`, {
      headers: { 'Accept': 'application/dns-json' },
      signal: controller.signal
    });
    
    clearTimeout(timeout);
    
    if (!response.ok) {
      throw new Error(`DNS lookup failed: ${response.status}`);
    }
    
    const data = await response.json();

    if (data.Status !== 0) {
      throw new Error(`DNS Error Code: ${data.Status}`);
    }

    // Check for additional records in parallel
    const [mxResult, txtResult, nsResult] = await Promise.allSettled([
      fetch(`https://dns.google/resolve?name=${domain}&type=MX`, {
        headers: { 'Accept': 'application/dns-json' }
      }).then(r => r.json()),
      fetch(`https://dns.google/resolve?name=${domain}&type=TXT`, {
        headers: { 'Accept': 'application/dns-json' }
      }).then(r => r.json()),
      fetch(`https://dns.google/resolve?name=${domain}&type=NS`, {
        headers: { 'Accept': 'application/dns-json' }
      }).then(r => r.json())
    ]);

    const mxData = mxResult.status === 'fulfilled' ? mxResult.value : null;
    const txtData = txtResult.status === 'fulfilled' ? txtResult.value : null;
    const nsData = nsResult.status === 'fulfilled' ? nsResult.value : null;

    // Check SPF and DMARC from TXT records
    const txtRecords = txtData?.Answer || [];
    const hasSPF = txtRecords.some((r: any) => r.data?.toLowerCase().includes('spf'));
    const hasDMARC = txtRecords.some((r: any) => r.data?.toLowerCase().includes('dmarc'));

    return {
      aRecords: data.Answer?.map((r: any) => r.data) || [],
      mxRecords: mxData?.Answer?.map((r: any) => r.data.replace(/\d+ /g, '')) || [],
      nsRecords: nsData?.Answer?.map((r: any) => r.data) || [],
      txtRecords: txtRecords.map((r: any) => r.data) || [],
      hasSPF,
      hasDMARC,
      status: 'OK'
    };
  } catch (error) {
    console.error('[DNS] Info Error:', error);
    return {
      error: 'DNS lookup failed',
      status: 'ERROR',
      aRecords: [],
      hasSPF: false,
      hasDMARC: false
    };
  }
}

async function getWHOISInfo(domain: string): Promise<any> {
  try {
    // Use a public WHOIS API with timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000); // Shorter timeout

    const response = await fetch(`https://whois.freeaiapi.xyz/?hostname=${domain}`, {
      signal: controller.signal
    });
    
    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(`WHOIS service returned ${response.status}`);
    }

    const text = await response.text();
    
    // Parse basic WHOIS info
    const registrarMatch = text.match(/Registrar:\s*(.+)/i);
    const createdMatch = text.match(/Creation Date:\s*(.+)/i);
    const expirMatch = text.match(/Registry Expiry Date:\s*(.+)/i);
    const countryMatch = text.match(/Registrant Country:\s*(.+)/i);
    const nameServerMatch = text.match(/Name Server:\s*(.+)/gm);

    const creationDate = createdMatch ? new Date(createdMatch[1]) : null;
    const now = new Date();
    const ageDays = creationDate ? Math.floor((now.getTime() - creationDate.getTime()) / (1000 * 60 * 60 * 24)) : null;

    return {
      registrar: registrarMatch ? registrarMatch[1].trim() : 'Desconocido',
      creationDate: createdMatch ? createdMatch[1].trim() : null,
      expiryDate: expirMatch ? expirMatch[1].trim() : null,
      registrantCountry: countryMatch ? countryMatch[1].trim() : null,
      nameServers: nameServerMatch ? nameServerMatch.map((n: string) => n.replace(/Name Server:\s*/i, '').trim()) : [],
      ageDays,
      privacyEnabled: !countryMatch || text.toLowerCase().includes('redacted') || text.toLowerCase().includes('gdpr'),
      status: 'OK'
    };
  } catch (error) {
    console.error('[WHOIS] Error:', error);
    throw error; // Re-throw to handle in main function
  }
}

async function getSecurityInfo(domain: string): Promise<any> {
  try {
    // Suspicious TLDs
    const suspiciousTLDs = ['.xyz', '.top', '.click', '.link', '.work', '.gq', '.ml', '.ga', '.cf', '.tk', '.pw'];
    const isSuspiciousTLD = suspiciousTLDs.some(tld => domain.endsWith(tld));
    
    // Check for typosquatting patterns
    const popularDomains = ['google', 'facebook', 'microsoft', 'amazon', 'apple', 'netflix', 'twitter', 'instagram'];
    const isTyposquat = popularDomains.some(pd => 
      domain.includes(pd) && domain !== pd + '.com' && !domain.startsWith(pd + '.')
    );

    // Character repetition (e.g., goooogle.com)
    const hasRepeatedChars = /(.)\1{2,}/.test(domain.split('.')[0]);

    // Numeric-heavy domains
    const numericCount = (domain.match(/\d/g) || []).length;
    const isNumericHeavy = numericCount > domain.length * 0.4;

    // Check for homograph/similar characters
    const hasHomographs = /[àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ]/.test(domain);

    const malicious = isSuspiciousTLD || isTyposquat || hasRepeatedChars || isNumericHeavy || hasHomographs;
    
    const risks: string[] = [];
    if (isSuspiciousTLD) risks.push('TLD frecuentemente asociado con actividad maliciosa');
    if (isTyposquat) risks.push('Posible typosquatting de marca conocida');
    if (hasRepeatedChars) risks.push('Caracteres repetidos sospechosos');
    if (isNumericHeavy) risks.push('Dominio numérico atípico');
    if (hasHomographs) risks.push('Posible uso de caracteres homógrafos (IDN spoofing)');

    return {
      malicious,
      riskFactors: risks,
      googleSafeBrowsing: 'No verificado (requiere API key)',
      virusTotalStatus: 'No verificado',
      analysisType: 'Heuristic'
    };
  } catch (error) {
    console.error('[SECURITY] Info Error:', error);
    return {
      malicious: false,
      riskFactors: [],
      error: 'Security analysis unavailable'
    };
  }
}
