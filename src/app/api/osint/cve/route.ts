import { NextRequest, NextResponse } from 'next/server';

// CVE & Vulnerability Database API
// Uses NIST NVD API v2.0 for REAL vulnerability data
export async function POST(request: NextRequest) {
  try {
    const { cveId, keyword, severity, limit = 20 } = await request.json();
    
    if (!cveId && !keyword) {
      return NextResponse.json({ 
        error: 'Se requiere un ID CVE o palabra clave de búsqueda',
        examples: { cveId: 'CVE-2024-1234', keyword: 'sql injection' }
      }, { status: 400 });
    }

    // NVD API v2.0 - REAL endpoint
    const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

    if (cveId) {
      return await fetchSingleCVE(cveId.toUpperCase(), NVD_API_URL);
    }

    return await searchCVEs(keyword, severity, limit, NVD_API_URL);

  } catch (error: any) {
    console.error('CVE Search Error:', error);
    
    if (error.name === 'AbortError') {
      return NextResponse.json(
        { error: 'Timeout: La base de datos NVD está respondiendo lentamente', suggestion: 'La API de NIST puede tener rate limiting - espere unos segundos' },
        { status: 504 }
      );
    }
    
    return NextResponse.json(
      { error: 'Error al buscar vulnerabilidades', details: error.message },
      { status: 500 }
    );
  }
}

async function fetchSingleCVE(cveId: string, apiUrl: string) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  
  const response = await fetch(`${apiUrl}?cveId=${cveId}`, { signal: controller.signal });
  clearTimeout(timeout);
  
  if (!response.ok) {
    if (response.status === 404 || response.status === 403) {
      return NextResponse.json({ 
        error: `CVE ${cveId} no encontrado en la base de datos NVD`,
        suggestion: 'Verifique el ID o busque por palabra clave'
      }, { status: 404 });
    }
    throw new Error(`NVD API returned ${response.status}`);
  }
  
  const data = await response.json();
  
  if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
    return NextResponse.json({ 
      error: `CVE ${cveId} no encontrado`,
      suggestion: 'Este CVE puede no estar indexado aún en NVD'
    }, { status: 404 });
  }

  const cve = data.vulnerabilities[0].cve;
  const formattedCve = formatCVE(cve);

  return NextResponse.json({
    success: true,
    data: formattedCve,
    metadata: {
      totalResults: 1,
      source: 'NIST National Vulnerability Database',
      apiVersion: '2.0',
      retrievedAt: new Date().toISOString(),
      disclaimer: 'Datos oficiales del gobierno de EE.UU.'
    }
  });
}

async function searchCVEs(keyword: string, severity: string | undefined, limit: number, apiUrl: string) {
  let searchUrl = `${apiUrl}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=${limit}`;
  
  // Apply severity filter
  if (severity) {
    const cvssFilter = severity.toLowerCase();
    if (cvssFilter.includes('critical')) searchUrl += '&cvssV3Severity=CRITICAL';
    else if (cvssFilter.includes('high')) searchUrl += '&cvssV3Severity=HIGH';
    else if (cvssFilter.includes('medium')) searchUrl += '&cvssV3Severity=MEDIUM';
    else if (cvssFilter.includes('low')) searchUrl += '&cvssV3Severity=LOW';
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  
  const response = await fetch(searchUrl, { signal: controller.signal });
  clearTimeout(timeout);
  
  if (!response.ok) {
    throw new Error('NVD API request failed');
  }

  const data = await response.json();
  const vulnerabilities = data.vulnerabilities?.map((v: any) => formatCVE(v.cve)) || [];
  
  if (vulnerabilities.length === 0) {
    return NextResponse.json({
      success: true,
      data: {
        results: [],
        statistics: { total: 0, bySeverity: {}, avgScore: 0, highestScore: 0 },
        pagination: { totalResults: 0, resultsPerPage: limit, currentPage: 1 }
      },
      metadata: {
        query: keyword,
        source: 'NIST NVD',
        message: 'No se encontraron vulnerabilidades para esta búsqueda'
      }
    });
  }

  const stats = generateStats(vulnerabilities);

  return NextResponse.json({
    success: true,
    data: {
      results: vulnerabilities,
      statistics: stats,
      pagination: {
        totalResults: data.totalResults || 0,
        resultsPerPage: limit,
        currentPage: 1,
        hasMore: (data.totalResults || 0) > limit
      }
    },
    metadata: {
      query: keyword,
      source: 'NIST National Vulnerability Database',
      apiVersion: '2.0',
      retrievedAt: new Date().toISOString()
    }
  });
}

function formatCVE(cve: any) {
  const id = cve.id;
  
  // Get English description
  const descriptions = cve.descriptions?.find((d: any) => d.lang === 'en')?.value 
    || cve.descriptions?.[0]?.value 
    || 'Sin descripción disponible';
  
  // Extract CVSS scores with priority v3.1 > v3.0 > v2
  let cvssScore = null;
  let cvssSeverity = 'SIN CALIFICAR';
  let vectorString = null;
  let cvssVersion = 'N/A';

  if (cve.metrics?.cvssMetricV31?.[0]) {
    const cvssData = cve.metrics.cvssMetricV31[0].cvssData;
    cvssScore = cvssData.baseScore;
    cvssSeverity = cvssData.baseSeverity;
    vectorString = cvssData.vectorString;
    cvssVersion = '3.1';
  } else if (cve.metrics?.cvssMetricV30?.[0]) {
    const cvssData = cve.metrics.cvssMetricV30[0].cvssData;
    cvssScore = cvssData.baseScore;
    cvssSeverity = cvssData.baseSeverity;
    vectorString = cvssData.vectorString;
    cvssVersion = '3.0';
  } else if (cve.metrics?.cvssMetricV2?.[0]) {
    const cvssData = cve.metrics.cvssMetricV2[0].cvssData;
    cvssScore = cvssData.baseScore;
    cvssSeverity = cvssData.severity;
    vectorString = cvssData.vectorString;
    cvssVersion = '2.0';
  }

  // Extract CWE weaknesses
  const weaknesses = cve.weaknesses?.[0]?.description
    ?.filter((w: any) => w.lang === 'en')
    ?.map((w: any) => w.value) || [];

  // Extract references
  const references = cve.references?.map((r: any) => ({
    url: r.url,
    tags: r.tags || [],
    source: r.source || 'Unknown'
  })) || [];

  // Dates
  const publishedDate = cve.published;
  const lastModified = cve.lastModified;

  // Determine status
  const status = cve.vulnStatus || 'Unknown';

  return {
    id,
    descriptions,
    cvss: {
      score: cvssScore,
      severity: cvssSeverity,
      vector: vectorString,
      version: cvssVersion
    },
    cwe: weaknesses,
    references,
    dates: {
      published: publishedDate,
      lastModified: lastModified,
      daysSincePublished: publishedDate ? Math.floor((Date.now() - new Date(publishedDate).getTime()) / (1000 * 60 * 60 * 24)) : null
    },
    status
  };
}

function generateStats(vulnerabilities: any[]) {
  const stats = {
    total: vulnerabilities.length,
    bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
    avgScore: 0,
    highestScore: 0,
    criticalCount: 0
  };

  let totalScore = 0;
  let scoredCount = 0;

  vulnerabilities.forEach(v => {
    const sev = v.cvss?.severity?.toUpperCase() || 'UNKNOWN';
    if (stats.bySeverity.hasOwnProperty(sev)) {
      stats.bySeverity[sev as keyof typeof stats.bySeverity]++;
    }

    if (v.cvss?.score) {
      totalScore += v.cvss.score;
      scoredCount++;
      if (v.cvss.score > stats.highestScore) {
        stats.highestScore = v.cvss.score;
      }
      if (v.cvss.severity === 'CRITICAL') {
        stats.criticalCount++;
      }
    }
  });

  stats.avgScore = scoredCount > 0 ? Math.round((totalScore / scoredCount) * 10) / 10 : 0;

  return stats;
}
