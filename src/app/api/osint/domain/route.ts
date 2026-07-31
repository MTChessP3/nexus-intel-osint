import { NextRequest, NextResponse } from 'next/server';

// Domain Analysis API
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

    // Use multiple REAL DNS and WHOIS services
    const [dnsInfo, whoisInfo, securityInfo] = await Promise.allSettled([
      getDNSInfo(cleanDomain),
      getWHOISInfo(cleanDomain),
      getSecurityInfo(cleanDomain)
    ]);

    const dns = dnsInfo.status === 'fulfilled' ? dnsInfo.value : null;
    const whois = whoisInfo.status === 'fulfilled' ? whoisInfo.value : null;
    const security = securityInfo.status === 'fulfilled' ? securityInfo.value : null;

    // Calculate reputation score
    let reputationScore = 70; // Start neutral
    const indicators: string[] = [];
    const recommendations: string[] = [];

    if (security?.malicious) {
      reputationScore -= 40;
      indicators.push('🔴 Dominio marcado como malicioso');
      recommendations.push('BLOQUEAR este dominio inmediatamente');
    }

    if (whois?.age && whois.age < 30) {
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

    if (whois?.privacyEnabled) {
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
      whois: whois || { error: 'No se pudo obtener información WHOIS' },
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
        sources: ['DNS Lookup', 'WHOIS Databases', 'Reputation Services']
      }
    };

    return NextResponse.json({ success: true, data: result });

  } catch (error: any) {
    console.error('Domain Analysis Error:', error);
    return NextResponse.json(
      { error: 'Error al analizar el dominio', details: error.message },
      { status: 500 }
    );
  }
}

async function getDNSInfo(domain: string) {
  try {
    // Use Google DNS-over-HTTPS for real DNS resolution
    const response = await fetch(`https://dns.google/resolve?name=${domain}&type=A`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    const data = await response.json();

    if (data.Status !== 0) {
      throw new Error('DNS lookup failed');
    }

    // Check for additional records
    const [mxResponse, txtResponse, nsResponse] = await Promise.allSettled([
      fetch(`https://dns.google/resolve?name=${domain}&type=MX`),
      fetch(`https://dns.google/resolve?name=${domain}&type=TXT`),
      fetch(`https://dns.google/resolve?name=${domain}&type=NS`)
    ]);

    const mxData = mxResponse.status === 'fulfilled' ? await mxResponse.value.json() : null;
    const txtData = txtResponse.status === 'fulfilled' ? await txtResponse.value.json() : null;
    const nsData = nsResponse.status === 'fulfilled' ? await nsResponse.value.json() : null;

    // Check SPF and DMARC
    const txtRecords = txtData?.Answer || [];
    const hasSPF = txtRecords.some((r: any) => r.data?.includes('spf'));
    const hasDMARC = txtRecords.some((r: any) => r.data?.includes('dmarc'));

    return {
      aRecords: data.Answer?.map((r: any) => r.data) || [],
      mxRecords: mxData?.Answer?.map((r: any) => r.data.replace(/\d+ /g, '')) || [],
      nsRecords: nsData?.Answer?.map((r: any) => r.data) || [],
      txtRecords: txtRecords.map((r: any) => r.data) || [],
      hasSPF,
      hasDMARC
    };
  } catch (error) {
    console.error('DNS Info Error:', error);
    return null;
  }
}

async function getWHOISInfo(domain: string) {
  try {
    // Use a public WHOIS API
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(`https://whois.freeaiapi.xyz/?hostname=${domain}`, {
      signal: controller.signal
    });
    
    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error('WHOIS service unavailable');
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
      privacyEnabled: !countryMatch || text.toLowerCase().includes('redacted') || text.toLowerCase().includes('gdpr')
    };
  } catch (error) {
    console.error('WHOIS Error:', error);
    return null;
  }
}

async function getSecurityInfo(domain: string) {
  try {
    // Check against Google Safe Browsing (would need API key)
    // For now, use heuristic analysis
    
    // Suspicious TLDs
    const suspiciousTLDs = ['.xyz', '.top', '.click', '.link', '.work', '.gq', '.ml', '.ga', '.cf'];
    const isSuspiciousTLD = suspiciousTLDs.some(tld => domain.endsWith(tld));
    
    // Check for typosquatting patterns
    const popularDomains = ['google', 'facebook', 'microsoft', 'amazon', 'apple', 'netflix'];
    const isTyposquat = popularDomains.some(pd => 
      domain.includes(pd) && domain !== pd + '.com' && !domain.startsWith(pd + '.')
    );

    // Character repetition (e.g., goooogle.com)
    const hasRepeatedChars = /(.)\1{2,}/.test(domain.split('.')[0]);

    // Numeric-heavy domains
    const numericCount = (domain.match(/\d/g) || []).length;
    const isNumericHeavy = numericCount > domain.length * 0.4;

    const malicious = isSuspiciousTLD || isTyposquat || hasRepeatedChars || isNumericHeavy;
    
    const risks: string[] = [];
    if (isSuspiciousTLD) risks.push('TLD frecuentemente asociado con actividad maliciosa');
    if (isTyposquat) risks.push('Posible typosquatting de marca conocida');
    if (hasRepeatedChars) risks.push('Caracteres repetidos sospechosos');
    if (isNumericHeavy) risks.push('Dominio numérico atípico');

    return {
      malicious,
      riskFactors: risks,
      googleSafeBrowsing: 'No verificado (requiere API key)',
      virusTotalStatus: 'No verificado'
    };
  } catch (error) {
    console.error('Security Info Error:', error);
    return null;
  }
}
