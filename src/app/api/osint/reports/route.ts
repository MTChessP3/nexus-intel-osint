import { NextRequest, NextResponse } from 'next/server';

// Executive Report Generator API
export async function POST(request: NextRequest) {
  try {
    const { reportType, data, options = {} } = await request.json();
    
    if (!reportType) {
      return NextResponse.json({ 
        error: 'Se requiere el tipo de informe',
        availableTypes: ['threat-summary', 'ip-intel', 'cve-analysis', 'full-assessment', 'ioc-report']
      }, { status: 400 });
    }

    let report;

    switch (reportType.toLowerCase()) {
      case 'threat-summary':
        report = generateThreatSummaryReport(data);
        break;
      case 'ip-intel':
        report = generateIPIntelReport(data);
        break;
      case 'cve-analysis':
        report = generateCVEAnalysisReport(data);
        break;
      case 'full-assessment':
        report = generateFullAssessmentReport(data);
        break;
      case 'ioc-report':
        report = generateIOCReport(data);
        break;
      default:
        return NextResponse.json({ 
          error: `Tipo de informe no reconocido: ${reportType}`,
          availableTypes: ['threat-summary', 'ip-intel', 'cve-analysis', 'full-assessment', 'ioc-report']
        }, { status: 400 });
    }

    return NextResponse.json({
      success: true,
      data: {
        report,
        metadata: {
          generatedAt: new Date().toISOString(),
          type: reportType,
          classification: options.classification || 'CONFIDENTIAL',
          version: '1.0'
        }
      }
    });

  } catch (error: any) {
    console.error('Report Generation Error:', error);
    return NextResponse.json(
      { error: 'Error al generar el informe', details: error.message },
      { status: 500 }
    );
  }
}

function generateThreatSummaryReport(threatData: any) {
  const now = new Date();
  const dateStr = now.toLocaleDateString('es-ES', { 
    year: 'numeric', month: 'long', day: 'numeric' 
  });

  return {
    title: 'Informe Ejecutivo de Inteligencia de Amenazas',
    subtitle: `Resumen de Amenazas - ${dateStr}`,
    executiveSummary: {
      content: threatData?.globalThreatLevel 
        ? `El nivel global de amenazas se encuentra actualmente en "${threatData.globalThreatLevel.level}" con una puntuación de ${threatData.globalThreatLevel.score}/100. Se han identificado ${threatData.activeThreats?.length || 0} vulnerabilidades recientes y ${threatData.campaigns?.filter((c: any) => c.status === 'ACTIVE').length || 0} campañas activas que requieren atención inmediata.`
        : 'Se recomienda ejecutar un análisis completo de amenazas antes de generar este informe.',
      keyFindings: [
        'Monitoreo continuo de IOCs activo',
        'Integración con bases de datos de vulnerabilidades (NIST NVD)',
        'Detección de campañas de amenazas persistentes'
      ],
      recommendations: [
        'Revisar y actualizar reglas de firewall basadas en IOCs detectados',
        'Aplicar parches críticos para CVEs de alta severidad',
        'Capacitar al personal sobre campañas de phishing activas'
      ]
    },
    sections: [
      {
        title: 'Nivel Global de Amenazas',
        content: threatData?.globalThreatLevel || null,
        type: 'metric'
      },
      {
        title: 'Vulnerabilidades Recientes',
        content: formatVulnerabilitiesForReport(threatData?.activeThreats || []),
        type: 'table'
      },
      {
        title: 'Campañas Activas',
        content: threatData?.campaigns || [],
        type: 'list'
      },
      {
        title: 'Grupos APT Monitoreados',
        content: threatData?.aptGroups || [],
        type: 'grid'
      }
    ],
    footer: {
      disclaimer: 'Este informe fue generado automáticamente por NEXUS INTEL OSINT Platform. Los datos provienen de fuentes públicas y deben ser verificados antes de tomar decisiones críticas.',
      nextReview: new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString()
    }
  };
}

function generateIPIntelReport(ipData: any) {
  if (!ipData) {
    return {
      title: 'Informe de Intelencia IP',
      error: 'No se proporcionaron datos de IP para generar el informe.'
    };
  }

  return {
    title: 'Informe de Intelencia IP',
    subtitle: `Análisis de ${ipData.query || 'IP desconocida'}`,
    executiveSummary: {
      content: `La dirección IP ${ipData.query} ha sido analizada y clasificada con nivel de amenaza "${ipData.threat?.level || 'UNKNOWN'}" (${ipData.threat?.score || 0}/100). La IP está ubicada en ${ipData.geolocation?.city || 'desconocido'}, ${ipData.geolocation?.country || 'desconocido'} y es operada por ${ipData.network?.isp || 'ISP desconocido'}.`,
      keyFindings: ipData.threat?.indicators || [],
      recommendations: ipData.threat?.recommendations || []
    },
    sections: [
      {
        title: 'Información Geolocalización',
        content: ipData.geolocation,
        type: 'location'
      },
      {
        title: 'Información de Red',
        content: ipData.network,
        type: 'network'
      },
      {
        title: 'Evaluación de Amenazas',
        content: ipData.threat,
        type: 'threat'
      }
    ],
    actionItems: ipData.threat?.score >= 40 ? [
      `Considerar bloqueo de IP ${ipData.query} en perimeter firewall`,
      'Agregar a lista de monitoreo de seguridad',
      'Notificar al equipo SOC sobre actividad sospechosa'
    ] : [
      'Continuar monitoreo normal',
      'Registrar análisis en logs de inteligencia'
    ]
  };
}

function generateCVEAnalysisReport(cveData: any) {
  const cves = cveData?.results || [cveData];
  
  return {
    title: 'Informe de Análisis de Vulnerabilidades',
    subtitle: `Análisis de ${cves.length} vulnerabilidad(es)`,
    executiveSummary: {
      content: cveData?.statistics
        ? `Se analizaron ${cveData.statistics.total} vulnerabilidades. Distribución por severidad: ${Object.entries(cveData.statistics.bySeverity).map(([k,v]) => `${k}: ${v}`).join(', ')}. Puntuación CVSS promedio: ${cveData.statistics.avgScore}, máxima: ${cveData.statistics.highestScore}.`
        : 'Análisis de vulnerabilidad individual.',
      keyFindings: cves.slice(0, 5).map((cve: any) => ({
        id: cve.id,
        severity: cve.cvss?.severity,
        score: cve.cvss?.score
      })),
      recommendations: generateCVERecommendations(cves)
    },
    sections: [
      {
        title: 'Estadísticas Generales',
        content: cveData?.statistics || null,
        type: 'stats'
      },
      {
        title: 'Detalles de Vulnerabilidades',
        content: cves.map(formatCVEForReport),
        type: 'detailed-list'
      }
    ],
    remediationPriority: cves
      .sort((a: any, b: any) => (b.cvss?.score || 0) - (a.cvss?.score || 0))
      .slice(0, 5)
      .map((cve: any) => ({
        priority: cve.cvss?.score >= 9 ? 'CRÍTICO' : cve.cvss?.score >= 7 ? 'ALTO' : 'MEDIO',
        cveId: cve.id,
        score: cve.cvss?.score,
        action: getRemediationAction(cve)
      }))
  };
}

function generateFullAssessmentReport(allData: any) {
  return {
    title: 'Informe Integral de Seguridad OSINT',
    subtitle: 'Evaluación Completa de Postura de Seguridad',
    executiveSummary: {
      content: 'Este informe integral combina múltiples fuentes de inteligencia OSINT para proporcionar una visión completa del panorama actual de amenazas y la postura de seguridad detectada.',
      scope: [
        'Inteligencia de direcciones IP analizadas',
        'Búsqueda de vulnerabilidades (CVE)',
        'Feed de amenazas en tiempo real',
        'Indicadores de compromiso (IOCs)',
        'Campañas de amenazas activas'
      ],
      overallRisk: allData?.threatData?.globalThreatLevel?.level || 'MODERADO'
    },
    sections: [
      {
        title: 'Resumen de Amenazas Globales',
        content: allData?.threatData?.globalThreatLevel,
        type: 'summary'
      },
      {
        title: 'IOCs Relevantes',
        content: allData?.threatData?.iocs?.slice(0, 20) || [],
        type: 'table'
      },
      {
        title: 'Campañas en Curso',
        content: allData?.threatData?.campaigns || [],
        type: 'campaigns'
      }
    ],
    strategicRecommendations: [
      'Implementar monitoreo continuo de IOCs en SIEM/SOC',
      'Establecer proceso de parcheo acelerado para CVEs críticos',
      'Desplegar soluciones de protección contra amenazas basadas en intel',
      'Programar ejercicios de red team basados en TTPs observados',
      'Revisar y actualizar políticas de acceso basado en amenazas actuales'
    ],
    appendix: {
      dataSources: [
        'NIST National Vulnerability Database (NVD)',
        'ip-api.com (Geolocalización)',
        'AlienVault OTX (IOCs)',
        'Fuentes de Threat Intelligence públicas'
      ],
      methodology: 'Análisis automatizado con correlación multi-fuente',
      limitations: 'Los datos están sujetos a disponibilidad de APIs externas y rate limits'
    }
  };
}

function generateIOCReport(iocData: any) {
  return {
    title: 'Informe de Indicadores de Compromiso (IOCs)',
    subtitle: `Reporte de ${iocData?.iocs?.length || 0} IOCs`,
    executiveSummary: {
      content: `Se han recopilado y analizado ${iocData?.iocs?.length || 0} indicadores de compromiso de diversas fuentes. Los IOCs cubren tipos: ${Object.keys(iocData?.statistics?.iocByType || {}).join(', ') || 'varios'}.`,
      iocBreakdown: iocData?.statistics?.iocByType || {},
      threatDistribution: iocData?.statistics?.iocByThreatLevel || {}
    },
    sections: [
      {
        title: 'IOCs por Tipo',
        content: groupIOCsByType(iocData?.iocs || []),
        type: 'grouped'
      },
      {
        title: 'IOCs Críticos (Acción Inmediata)',
        content: (iocData?.iocs || []).filter((ioc: any) => 
          ioc.threatLevel === 'CRITICAL' || ioc.threatLevel === 'High'
        ),
        type: 'critical'
      }
    ],
    implementationGuide: {
      firewall: 'Importar IPs y dominios en reglas de bloqueo',
      siem: 'Crear reglas de correlación para detección',
      dns: 'Configurar DNS sinkhole para dominios maliciosos',
      email: 'Agregar a listas negras de spam/phishing',
      edr: 'Configurar detección de hashes maliciosos'
    }
  };
}

// Helper functions

function formatVulnerabilitiesForReport(vulns: any[]) {
  return vulns.map(v => ({
    id: v.id,
    description: v.description?.substring(0, 150),
    severity: v.severity,
    cvssScore: v.cvssScore,
    published: v.published
  }));
}

function formatCVEForReport(cve: any) {
  return {
    id: cve.id,
    description: cve.descriptions,
    cvss: cve.cvss,
    cwe: cve.cwe,
    references: cve.references?.slice(0, 3),
    status: cve.status,
    dates: cve.dates
  };
}

function generateCVERecommendations(cves: any[]): string[] {
  const hasCritical = cves.some((c: any) => c.cvss?.severity === 'CRITICAL');
  const hasHigh = cves.some((c: any) => c.cvss?.severity === 'HIGH');
  
  const recs = [];
  
  if (hasCritical) {
    recs.push('🚨 PRIORIDAD CRÍTICA: Aplicar parches para CVEs CRÍTICAS dentro de 72 horas');
  }
  if (hasHigh) {
    recs.push('⚠️ ALTA PRIORIDAD: Remediar CVEs de severidad ALTA dentro de 2 semanas');
  }
  
  recs.push('Realizar evaluación de impacto para cada CVE identificada');
  recs.push('Verificar si sistemas internos son afectados');
  recs.push('Implementar controles mitigantes mientras se aplica parche');
  recs.push('Documentar excepciones si no se puede parchear inmediatamente');
  
  return recs;
}

function getRemediationAction(cve: any): string {
  if (!cve.cvss?.score) return 'Evaluar impacto';
  if (cve.cvss.score >= 9) return 'Parche crítico - 72h';
  if (cve.cvss.score >= 7) return 'Parche alto - 2 semanas';
  if (cve.cvss.score >= 4) return 'Parche medio - 30 días';
  return 'Parche bajo - siguiente ciclo';
}

function groupIOCsByType(iocs: any[]): Record<string, any[]> {
  return iocs.reduce((acc, ioc) => {
    const type = ioc.type || 'unknown';
    if (!acc[type]) acc[type] = [];
    acc[type].push(ioc);
    return acc;
  }, {} as Record<string, any[]>);
}
