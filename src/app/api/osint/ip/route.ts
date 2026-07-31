import { NextRequest, NextResponse } from 'next/server';

// IP Geolocation & Threat Intelligence API
// Uses ip-api.com for REAL geolocation data
export async function POST(request: NextRequest) {
  try {
    const { ip } = await request.json();
    
    if (!ip) {
      return NextResponse.json({ error: 'Se requiere una dirección IP' }, { status: 400 });
    }

    // Validate IP format (IPv4 and IPv6)
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    if (!ipRegex.test(ip)) {
      return NextResponse.json({ error: 'Formato de IP inválido. Use IPv4 (ej: 8.8.8.8) o IPv6' }, { status: 400 });
    }

    // REAL API CALL to ip-api.com (free tier, 45 requests/minute)
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000); // 10s timeout
    
    const response = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query`,
      { signal: controller.signal }
    );
    
    clearTimeout(timeout);
    const data = await response.json();

    if (data.status === 'fail') {
      return NextResponse.json({ 
        error: `Error de IP-API: ${data.message}`,
        suggestion: 'Verifique que la IP sea válida y pública'
      }, { status: 404 });
    }

    // Calculate threat score based on REAL indicators from ip-api.com
    let threatScore = 0;
    const threats: string[] = [];
    const recommendations: string[] = [];
    
    // Real proxy detection
    if (data.proxy) {
      threatScore += 35;
      threats.push('🔴 Proxy/VPN Detectado - IP anonimizada');
      recommendations.push('Bloquear si se requiere identificación real');
    }
    
    // Real hosting/datacenter detection  
    if (data.hosting) {
      threatScore += 25;
      threats.push('🟠 IP de Hosting/Data Center - No es residencial');
      recommendations.push('Verificar si es servicio cloud legítimo');
    }
    
    // Mobile connection
    if (data.mobile) {
      threatScore += 5;
      threats.push('📱 Conexión móvil detectada');
    }

    // Additional risk assessment based on ISP/Org
    const suspiciousISPs = ['ovh', 'digitalocean', 'aws', 'amazon', 'google', 'microsoft', 'azure', 'linode', 'vultr'];
    const orgLower = (data.org || '').toLowerCase();
    const ispLower = (data.isp || '').toLowerCase();
    
    if (suspiciousISPs.some(s => orgLower.includes(s) || ispLower.includes(s))) {
      if (!data.hosting) {
        threatScore += 15;
        threats.push('⚠️ Proveedor de cloud identificado');
      }
    }

    // Determine risk level with clear thresholds
    let riskLevel = 'BAJO';
    let riskColor = '#22c55e'; // green
    let riskIcon = '✅';
    
    if (threatScore >= 60) {
      riskLevel = 'CRÍTICO';
      riskColor = '#dc2626'; // red
      riskIcon = '🚨';
    } else if (threatScore >= 40) {
      riskLevel = 'ALTO';
      riskColor = '#f97316'; // orange
      riskIcon = '⚠️';
    } else if (threatScore >= 20) {
      riskLevel = 'MEDIO';
      riskColor = '#eab308'; // yellow
      riskIcon = '🔶';
    }

    // Generate contextual recommendations
    if (threatScore < 20) {
      recommendations.push('IP de bajo riesgo - Sin acción inmediata requerida');
    } else if (threatScore >= 40) {
      recommendations.push('Monitorear actividad de esta IP');
      recommendations.push('Considerar rate limiting');
    }
    if (threatScore >= 60) {
      recommendations.unshift('🚨 BLOQUEAR INMEDIATAMENTE - Alto riesgo');
    }

    const asnInfo = data.as ? data.as.split(' ')[0] : 'Desconocido';
    const ispOrg = data.org || data.isp || 'Desconocido';

    const result = {
      query: data.query,
      geolocation: {
        country: data.country || 'Desconocido',
        countryCode: data.countryCode || '--',
        region: data.regionName || 'Desconocido',
        city: data.city || 'Desconocido',
        postalCode: data.zip || 'N/A',
        latitude: data.lat || 0,
        longitude: data.lon || 0,
        timezone: data.timezone || 'UTC'
      },
      network: {
        isp: data.isp || 'Desconocido',
        org: ispOrg,
        asn: asnInfo,
        asFull: data.as || 'N/A',
        isMobile: Boolean(data.mobile),
        isProxy: Boolean(data.proxy),
        isHosting: Boolean(data.hosting)
      },
      threat: {
        score: Math.min(100, Math.round(threatScore)),
        level: riskLevel,
        color: riskColor,
        icon: riskIcon,
        indicators: threats.length > 0 ? threats : ['✅ Sin indicadores de amenaza'],
        recommendations
      },
      metadata: {
        analyzedAt: new Date().toISOString(),
        source: 'ip-api.com (API Real)',
        apiStatus: 'Operativo',
        version: '2.0'
      }
    };

    return NextResponse.json({ success: true, data: result });
    
  } catch (error: any) {
    console.error('IP Analysis Error:', error);
    
    if (error.name === 'AbortError') {
      return NextResponse.json(
        { error: 'Timeout: La API de geolocalización tardó demasiado en responder', suggestion: 'Intente nuevamente en unos segundos' },
        { status: 504 }
      );
    }
    
    return NextResponse.json(
      { error: 'Error al analizar la dirección IP', details: error.message },
      { status: 500 }
    );
  }
}

// GET endpoint for quick lookup
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const ip = searchParams.get('ip');
  
  if (!ip) {
    return NextResponse.json({ error: 'Parámetro "ip" requerido' }, { status: 400 });
  }
  
  // Reuse POST logic
  return POST(new Request('', { method: 'POST', body: JSON.stringify({ ip }) }));
}
