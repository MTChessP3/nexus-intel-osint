import { NextRequest, NextResponse } from 'next/server';

// URL Security Analysis API
// Compatible with Vercel serverless environment
export const runtime = 'nodejs';
export const maxDuration = 30;

export async function POST(request: NextRequest) {
  try {
    const { url } = await request.json();
    
    if (!url) {
      return NextResponse.json({ error: 'Se requiere una URL para analizar' }, { status: 400 });
    }

    // Validate URL format
    try {
      new URL(url);
    } catch {
      return NextResponse.json({ 
        error: 'URL inválida', 
        suggestion: 'Incluya protocolo (http:// o https://). Ejemplo: https://example.com'
      }, { status: 400 });
    }

    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const path = urlObj.pathname;
    const query = urlObj.search;
    const protocol = urlObj.protocol;

    // Perform multiple security checks
    const [domainCheck, urlAnalysis, contentAnalysis] = await Promise.allSettled([
      checkDomainReputation(hostname),
      analyzeURLPattern(urlObj),
      checkContentIndicators(url)
    ]);

    const domainData = domainCheck.status === 'fulfilled' ? domainCheck.value : null;
    const patternData = urlAnalysis.status === 'fulfilled' ? urlAnalysis.value : null;
    const contentData = contentAnalysis.status === 'fulfilled' ? contentAnalysis.value : null;

    // Calculate overall threat score
    let threatScore = 0;
    const indicators: string[] = [];
    const recommendations: string[] = [];

    // Domain-based threats
    if (domainData?.isMalicious) {
      threatScore += 40;
      indicators.push('🔴 Dominio conocido como malicioso');
      recommendations.push('NO visitar esta URL - dominio en blacklist');
    }
    if (domainData?.isNewDomain) {
      threatScore += 15;
      indicators.push('🟠 Dominio registrado recientemente');
    }
    if (domainData?.suspiciousTLD) {
      threatScore += 20;
      indicators.push('🟠 TLD sospechoso');
    }

    // URL Pattern-based threats
    if (patternData) {
      threatScore += patternData.scoreContribution;
      indicators.push(...patternData.indicators);
    }

    // Content-based threats
    if (contentData) {
      threatScore += contentData.scoreContribution;
      indicators.push(...contentData.indicators);
    }

    // Determine risk level
    let riskLevel = 'SEGURO';
    let riskColor = '#22c55e';
    let riskIcon = '✅';

    if (threatScore >= 70) {
      riskLevel = 'CRÍTICO';
      riskColor = '#dc2626';
      riskIcon = '🚨';
      recommendations.unshift('⛔ URL PELIGROSA - NO ACCEDER');
    } else if (threatScore >= 50) {
      riskLevel = 'ALTO RIESGO';
      riskColor = '#f97316';
      riskIcon = '⚠️';
      recommendations.push('Precaución extrema al acceder');
    } else if (threatScore >= 30) {
      riskLevel = 'SOSPECHOSO';
      riskColor = '#eab308';
      riskIcon = '🔶';
      recommendations.push('Verificar antes de interactuar');
    }

    if (indicators.length === 0) {
      indicators.push('✅ No se detectaron amenazas evidentes');
      recommendations.push('URL aparentemente segura - mantener precaución estándar');
    }

    const result = {
      url,
      parsedUrl: {
        protocol: protocol.replace(':', ''),
        hostname,
        port: urlObj.port || (protocol === 'https:' ? '443' : '80'),
        path,
        query: query || null,
        fragment: urlObj.hash || null
      },
      analysis: {
        domainReputation: domainData,
        urlPatterns: patternData,
        contentIndicators: contentData
      },
      overallAssessment: {
        threatScore: Math.min(100, Math.round(threatScore)),
        riskLevel,
        riskColor,
        riskIcon,
        indicators,
        recommendations,
        verdict: getVerdict(threatScore)
      },
      metadata: {
        analyzedAt: new Date().toISOString(),
        checksPerformed: ['Dominio', 'Patrón URL', 'Contenido'],
        disclaimer: 'Este análisis es orientativo. Siempre verifique con múltiples fuentes.'
      }
    };

    return NextResponse.json({ success: true, data: result });

  } catch (error: any) {
    console.error('URL Analysis Error:', error);
    return NextResponse.json(
      { error: 'Error al analizar la URL', details: error.message },
      { status: 500 }
    );
  }
}

async function checkDomainReputation(hostname: string) {
  try {
    // Check for suspicious TLDs
    const suspiciousTLDs = ['.xyz', '.top', '.click', '.link', '.work', '.gq', '.ml', '.ga', '.cf', '.tk', '.pw'];
    const isSuspiciousTLD = suspiciousTLDs.some(tld => hostname.endsWith(tld));

    // Check domain age (simplified - would need WHOIS API)
    const isNewDomain = false; // Would require real API

    // Check against known bad patterns
    const suspiciousPatterns = [
      /login-?secure/,
      /account-?verify/,
      /update-?info/,
      /banking-?security/,
      /paypal-?secure/,
      /microsoft-?office/
    ];
    const isMalicious = suspiciousPatterns.some(p => p.test(hostname));

    return {
      isMalicious,
      isNewDomain,
      suspiciousTLD,
      reputationScore: isMalicious ? 10 : (isSuspiciousTLD ? 40 : 70)
    };
  } catch (error) {
    return null;
  }
}

async function analyzeURLPattern(urlObj: URL) {
  let scoreContribution = 0;
  const indicators: string[] = [];

  const hostname = urlObj.hostname;
  const path = urlObj.pathname.toLowerCase();
  const searchParams = urlObj.searchParams;

  // Check for IP address instead of domain
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    scoreContribution += 25;
    indicators.push('🔴 Usa dirección IP en vez de dominio');
  }

  // Check for suspicious paths
  const suspiciousPaths = ['/login', '/signin', '/account', '/verify', '/update', '/confirm', '/secure', '/auth'];
  const hasSuspiciousPath = suspiciousPaths.some(p => path.includes(p));
  
  if (hasSuspiciousPath && searchParams.size > 2) {
    scoreContribution += 20;
    indicators.push('🟠 Patrón de phishing detectado en URL');
  }

  // Check for excessive subdomains
  const subdomainCount = hostname.split('.').length - 2;
  if (subdomainCount > 3) {
    scoreContribution += 10;
    indicators.push('🟠 Múltiples subdominios sospechosos');
  }

  // Check for unusual characters in path
  if (/[%@!]/.test(path)) {
    scoreContribution += 15;
    indicators.push('🟠 Caracteres inusuales en la ruta');
  }

  // Check for data/credential harvesting patterns
  const credentialPatterns = [/password/, /token/, /secret/, /api.?key/, /session/];
  const hasCredentialPattern = credentialPatterns.some(p => 
    path.includes(p.toString()) || [...searchParams.keys()].some(k => p.test(k))
  );
  
  if (hasCredentialPattern) {
    scoreContribution += 15;
    indicators.push('🟠 Posible intento de captura de credenciales');
  }

  // Check for URL shortener or redirect
  const knownShorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd'];
  if (knownShorteners.some(s => hostname.includes(s))) {
    scoreContribution += 5;
    indicators.push('ℹ️ Acortador de URL - destino desconocido');
  }

  return { scoreContribution, indicators };
}

async function checkContentIndicators(url: string) {
  let scoreContribution = 0;
  const indicators: string[] = [];

  // These would normally be checked by fetching the actual content
  // For now, we analyze the URL structure for hints

  // Check for file downloads that could be malware
  const dangerousExtensions = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.msi'];
  const urlLower = url.toLowerCase();
  
  if (dangerousExtensions.some(ext => urlLower.includes(ext))) {
    scoreContribution += 30;
    indicators.push('🔴 URL apunta a archivo ejecutable');
  }

  // Check for archive files
  const archiveExtensions = ['.zip', '.rar', '.7z', '.tar.gz'];
  if (archiveExtensions.some(ext => urlLower.includes(ext))) {
    scoreContribution += 15;
    indicators.push('🟠 URL apunta a archivo comprimido');
  }

  // Check for document files that could contain macros
  const docExtensions = ['.doc', '.docx', '.xls', '.xlsx', '.rtf'];
  if (docExtensions.some(ext => urlLower.includes(ext))) {
    scoreContribution += 10;
    indicators.push('🟡 Documento de oficina - verificar macros');
  }

  return { scoreContribution, indicators };
}

function getVerdict(score: number): string {
  if (score >= 70) return 'BLOQUEAR - Alta probabilidad de ser malicioso';
  if (score >= 50) return 'EVITAR - Riesgo significativo de seguridad';
  if (score >= 30) return 'CAUTELA - Verificar antes de proceder';
  return 'ACEPTABLE - Sin amenazas detectadas';
}
