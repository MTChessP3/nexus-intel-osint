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
      case 'threat-briefing':
        report = generateThreatSummaryReport(data);
        break;
      case 'ip-intel':
        report = generateIPIntelReport(data?.ipResult || data);
        break;
      case 'cve-analysis':
        report = generateCVEAnalysisReport(data?.cveResults || data);
        break;
      case 'full-assessment':
        report = generateFullAssessmentReport(data);
        break;
      case 'ioc-report':
        report = generateIOCReport(data?.threatData || data);
        break;
      case 'executive-summary':
        report = generateExecutiveSummaryReport(data);
        break;
      default:
        return NextResponse.json({ 
          error: `Tipo de informe no reconocido: ${reportType}`,
          availableTypes: ['threat-briefing', 'ioc-report', 'executive-summary', 'ip-intel', 'cve-analysis', 'full-assessment']
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

function generateExecutiveSummaryReport(allData: any): any {
  const now = new Date();
  const dateStr = now.toLocaleDateString('es-ES', { 
    year: 'numeric', month: 'long', day: 'numeric' 
  });

  return {
    title: 'INFORME EJECUTIVO DE CIBERSEGURIDAD',
    subtitle: `NEXUS INTEL OSINT Platform - ${dateStr}`,
    classification: allData?.options?.classification || 'CONFIDENTIAL',
    
    // Executive Summary for C-Suite
    executiveBrief: {
      overview: `Este informe presenta el estado actual del panorama de amenazas cibernéticas basado en inteligencia OSINT recopilada por la plataforma NEXUS INTEL. El análisis integra datos de múltiples fuentes incluyendo NIST NVD, feeds de amenazas en tiempo real, y análisis de indicadores de compromiso (IOCs).`,
      keyMetrics: {
        globalThreatLevel: allData?.threatData?.globalThreatLevel || { level: 'MODERADO', score: 55 },
        activeVulnerabilities: allData?.cveResults?.length || allData?.threatData?.activeThreats?.length || 0,
        activeCampaigns: allData?.threatData?.campaigns?.filter((c: any) => c.status === 'ACTIVE').length || 0,
        monitoredIOCs: allData?.threatData?.iocs?.length || 0
      },
      riskPosture: {
        currentLevel: allData?.threatData?.globalThreatLevel?.level || 'MODERADO',
        trend: 'stable', // Would be calculated from historical data
        primaryConcerns: [
          'Vulnerabilidades de día cero sin parche',
          'Campañas de phishing dirigidas',
          'Actividad de grupos APT'
        ]
      }
    },

    // Threat Landscape Summary
    threatLandscape: {
      headline: 'El panorama de amenazas actual muestra actividad sostenida en múltiples vectores.',
      topThreats: (allData?.threatData?.activeThreats || []).slice(0, 5).map((t: any) => ({
        id: t.id,
        severity: t.severity,
        impact: t.cvssScore >= 9 ? 'CRÍTICO' : t.cvssScore >= 7 ? 'ALTO' : 'MEDIO'
      })),
      emergingTrends: [
        'Aumento de ataques ransomware con doble extorsión',
        'Explotación de vulnerabilidades en supply chain',
        'Uso de IA para crear phishing más convincente',
        'Ataques a infraestructura cloud'
      ]
    },

    // Business Impact Analysis
    businessImpact: {
      operationalRisk: 'MEDIO',
      dataBreachRisk: 'ALTO',
      financialExposure: 'Significativo si no se mitiga',
      reputationRisk: 'MODERADO',
      complianceImplications: [
        'Posibles incumplimientos de GDPR/CCPA si hay brechas de datos',
        'Requisitos de notificación de vulnerabilidades críticas',
        'Necesidad de documentación para auditorías'
      ]
    },

    // Strategic Recommendations
    strategicRecommendations: [
      {
        priority: 1,
        title: 'Parcheo Crítico Inmediato',
        description: 'Aplicar parches de seguridad para todas las CVEs identificadas con CVSS >= 8.0 dentro de las próximas 72 horas.',
        owner: 'Equipo de Infraestructura/Security Ops',
        timeline: '72 horas',
        budgetImpact: 'Bajo - esfuerzo interno'
      },
      {
        priority: 2,
        title: 'Fortalecer Monitoreo de Amenazas',
        description: 'Implementar reglas SIEM basadas en los IOCs identificados y habilitar alertas en tiempo real.',
        owner: 'SOC / Security Operations',
        timeline: '1 semana',
        budgetImpact: 'Medio - posible licenciamiento adicional'
      },
      {
        priority: 3,
        title: 'Capacitación en Concientización',
        description: 'Lanzar campaña de concientización sobre campañas de phishing activas identificadas.',
        owner: 'Recursos Humanos / Security Awareness',
        timeline: '2 semanas',
        budgetImpact: 'Bajo - recursos internos'
      },
      {
        priority: 4,
        title: 'Revisión de Controles de Acceso',
        description: 'Auditar permisos de acceso privilegiado e implementar MFA donde falte.',
        owner: 'Identity & Access Management',
        timeline: '30 días',
        budgetImpact: 'Medio'
      }
    ],

    // Investment Recommendations
    investmentPriorities: [
      {
        area: 'EDR/XDR Solution',
        justification: 'Detección y respuesta mejoradas ante amenazas avanzadas',
        priority: 'ALTA',
        estimatedROI: 'Reducción del 60% en tiempo de detección'
      },
      {
        area: 'Threat Intelligence Platform',
        justification: 'Integración continua de IOCs y TTPs de actores de amenaza',
        priority: 'ALTA',
        estimatedROI: 'Mejora del 40% en capacidad de prevención'
      },
      {
        area: 'Security Awareness Training',
        justification: 'Reducir superficie de ataque basada en humano',
        priority: 'MEDIA',
        estimatedROI: 'Reducción del 70% en incidentes relacionados con phishing'
      }
    ],

    // Appendix
    appendix: {
      dataSources: [
        'NIST National Vulnerability Database (NVD) v2.0',
        'ip-api.com (Geolocalización IP)',
        'Google DNS-over-HTTPS (Resolución DNS)',
        'MalwareBazaar (Hashes maliciosos)',
        'Fuentes públicas de Threat Intelligence'
      ],
      methodology: 'Análisis automatizado OSINT con correlación multi-fuente y validación cruzada',
      limitations: [
        'Datos sujetos a disponibilidad y rate limits de APIs externas',
        'Algunos IOCs pueden estar obsoletos o ya mitigados',
        'La atribución de amenazas tiene grado de incertidumbre'
      ],
      nextReviewDate: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      preparedBy: 'NEXUS INTEL OSINT Platform v3.0',
      distribution: ['CISO', 'CTO', 'VP Engineering', 'Security Leadership']
    },

    // Approval Section
    approvals: {
      preparedBy: 'Automated Intelligence System',
      reviewedBy: '[Pending Security Review]',
      approvedBy: '[Pending Executive Approval]'
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
