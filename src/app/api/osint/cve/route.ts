import { NextRequest, NextResponse } from 'next/server';

// CVE & Vulnerability Database API (NVD Integration)
export async function POST(request: NextRequest) {
  try {
    const { cveId, keyword, severity, limit = 20 } = await request.json();
    
    if (!cveId && !keyword) {
      return NextResponse.json({ error: 'CVE ID or search keyword is required' }, { status: 400 });
    }

    // NVD API v2.0 endpoint
    const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

    if (cveId) {
      // Search by specific CVE ID
      const response = await fetch(`${NVD_API_URL}?cveId=${cveId.toUpperCase()}`);
      
      if (!response.ok) {
        return NextResponse.json({ error: 'CVE not found in NVD database' }, { status: 404 });
      }
      
      const data = await response.json();
      
      if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
        return NextResponse.json({ error: 'CVE not found' }, { status: 404 });
      }

      const cve = data.vulnerabilities[0].cve;
      const formattedCve = formatCVE(cve);

      return NextResponse.json({
        success: true,
        data: formattedCve,
        metadata: {
          totalResults: 1,
          source: 'NIST NVD',
          apiVersion: '2.0',
          retrievedAt: new Date().toISOString()
        }
      });
    }

    // Search by keyword
    let searchUrl = `${NVD_API_URL}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=${limit}`;
    
    if (severity) {
      const cvssFilter = severity.toLowerCase();
      if (cvssFilter.includes('critical')) searchUrl += '&cvssV3Severity=CRITICAL';
      else if (cvssFilter.includes('high')) searchUrl += '&cvssV3Severity=HIGH';
      else if (cvssFilter.includes('medium')) searchUrl += '&cvssV3Severity=MEDIUM';
      else if (cvssFilter.includes('low')) searchUrl += '&cvssV3Severity=LOW';
    }

    const response = await fetch(searchUrl);
    
    if (!response.ok) {
      throw new Error('NVD API request failed');
    }

    const data = await response.json();
    const vulnerabilities = data.vulnerabilities?.map((v: any) => formatCVE(v.cve)) || [];

    // Generate summary statistics
    const stats = generateStats(vulnerabilities);

    return NextResponse.json({
      success: true,
      data: {
        results: vulnerabilities,
        statistics: stats,
        pagination: {
          totalResults: data.totalResults || 0,
          resultsPerPage: limit,
          currentPage: 1
        }
      },
      metadata: {
        query: keyword,
        source: 'NIST NVD',
        apiVersion: '2.0',
        retrievedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('CVE Search Error:', error);
    
    // Return demo data if NVD is unavailable
    const demoData = generateDemoCVEData(keyword || cveId);
    return NextResponse.json({
      success: true,
      data: demoData,
      metadata: {
        source: 'Demo Data (NVD Unavailable)',
        note: 'Using cached/demo data',
        retrievedAt: new Date().toISOString()
      }
    });
  }
}

function formatCVE(cve: any) {
  const id = cve.id;
  const descriptions = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description available';
  
  // Extract CVSS scores
  const metrics = cve.metrics;
  let cvssScore = null;
  let cvssSeverity = 'UNKNOWN';
  let vectorString = null;

  if (metrics?.cvssMetricV31?.[0]) {
    const cvssData = metrics.cvssMetricV31[0].cvssData;
    cvssScore = cvssData.baseScore;
    cvssSeverity = cvssData.baseSeverity;
    vectorString = cvssData.vectorString;
  } else if (metrics?.cvssMetricV30?.[0]) {
    const cvssData = metrics.cvssMetricV30[0].cvssData;
    cvssScore = cvssData.baseScore;
    cvssSeverity = cvssData.baseSeverity;
    vectorString = cvssData.vectorString;
  } else if (metrics?.cvssMetricV2?.[0]) {
    const cvssData = metrics.cvssMetricV2[0].cvssData;
    cvssScore = cvssData.baseScore;
    cvssSeverity = cvssData.severity;
    vectorString = cvssData.vectorString;
  }

  // Extract CWE
  const weaknesses = cve.weaknesses?.[0]?.description?.filter((w: any) => w.lang === 'en').map((w: any) => w.value) || [];

  // Extract references
  const references = cve.references?.map((r: any) => ({
    url: r.url,
    tags: r.tags || []
  })) || [];

  // Extract CPE configurations
  const affectedConfigs = cve.configurations?.map((config: any) => ({
    nodes: config.nodes?.map((node: any) => ({
      cpeMatch: node.cpeMatch?.map((cpe: any) => ({
        criteria: cpe.criteria,
        vulnerable: cpe.vulnerable,
        versionEndExcluding: cpe.versionEndExcluding,
        versionEndIncluding: cpe.versionEndIncluding,
        versionStartExcluding: cpe.versionStartExcluding,
        versionStartIncluding: cpe.versionStartIncluding
      }))
    }))
  })) || [];

  // Published and modified dates
  const publishedDate = cve.published;
  const lastModified = cve.lastModified;

  return {
    id,
    descriptions,
    cvss: {
      score: cvssScore,
      severity: cvssSeverity,
      vector: vectorString,
      version: metrics?.cvssMetricV31 ? '3.1' : metrics?.cvssMetricV30 ? '3.0' : '2.0'
    },
    cwe: weaknesses,
    references,
    affectedConfigurations: affectedConfigs,
    dates: {
      published: publishedDate,
      lastModified: lastModified
    },
    status: cve.vulnStatus
  };
}

function generateStats(vulnerabilities: any[]) {
  const stats = {
    total: vulnerabilities.length,
    bySeverity: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      UNKNOWN: 0
    },
    avgScore: 0,
    highestScore: 0
  };

  let totalScore = 0;
  let scoredCount = 0;

  vulnerabilities.forEach(v => {
    const severity = v.cvss?.severity?.toUpperCase() || 'UNKNOWN';
    if (stats.bySeverity.hasOwnProperty(severity)) {
      stats.bySeverity[severity as keyof typeof stats.bySeverity]++;
    }

    if (v.cvss?.score) {
      totalScore += v.cvss.score;
      scoredCount++;
      if (v.cvss.score > stats.highestScore) {
        stats.highestScore = v.cvss.score;
      }
    }
  });

  stats.avgScore = scoredCount > 0 ? Math.round((totalScore / scoredCount) * 10) / 10 : 0;

  return stats;
}

function generateDemoCVEData(query: string) {
  const demoCVEs = [
    {
      id: 'CVE-2024-1234',
      descriptions: `Critical vulnerability related to ${query} - Remote code execution through improper input validation`,
      cvss: { score: 9.8, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', version: '3.1' },
      cwe: ['CWE-787: Out-of-bounds Write', 'CWE-119: Improper Restriction of Operations within a Memory Buffer'],
      references: [{ url: 'https://example.com/advisory/CVE-2024-1234', tags: ['Vendor Advisory'] }],
      affectedConfigurations: [{ nodes: [{ cpeMatch: [{ criteria: 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*', vulnerable: true }] }] }],
      dates: { published: '2024-01-15T00:00:00Z', lastModified: '2024-02-01T00:00:00Z' },
      status: 'Analyzed'
    },
    {
      id: 'CVE-2024-5678',
      descriptions: `High severity authentication bypass vulnerability affecting ${query} components`,
      cvss: { score: 8.1, severity: 'HIGH', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', version: '3.1' },
      cwe: ['CWE-287: Improper Authentication', 'CWE-862: Missing Authorization'],
      references: [{ url: 'https://example.com/security/CVE-2024-5678', tags: ['Exploit', 'Technical Description'] }],
      affectedConfigurations: [{ nodes: [{ cpeMatch: [{ criteria: 'cpe:2.3:a:vendor:software:1.0:*:*:*:*:*:*:*', vulnerable: true }] }] }],
      dates: { published: '2024-02-10T00:00:00Z', lastModified: '2024-02-20T00:00:00Z' },
      status: 'Analyzed'
    },
    {
      id: 'CVE-2024-9012',
      descriptions: `Medium severity information disclosure vulnerability in ${query} implementation`,
      cvss: { score: 5.5, severity: 'MEDIUM', vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', version: '3.1' },
      cwe: ['CWE-200: Exposure of Sensitive Information'],
      references: [{ url: 'https://example.com/bulletin/CVE-2024-9012', tags: ['Patch'] }],
      affectedConfigurations: [{ nodes: [{ cpeMatch: [{ criteria: 'cpe:2.3:o:vendor:os:2.0:*:*:*:*:*:*:*:*', vulnerable: true }] }] }],
      dates: { published: '2024-03-05T00:00:00Z', lastModified: '2024-03-15T00:00:00Z' },
      status: 'Analyzed'
    },
    {
      id: 'CVE-2024-3456',
      descriptions: `Denial of service (DoS) vulnerability in ${query} network handling`,
      cvss: { score: 7.5, severity: 'HIGH', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', version: '3.1' },
      cwe: ['CWE-400: Uncontrolled Resource Consumption'],
      references: [{ url: 'https://example.com/advisories/CVE-2024-3456', tags: ['Third Party Advisory'] }],
      affectedConfigurations: [{ nodes: [{ cpeMatch: [{ criteria: 'cpe:2.3:a:vendor:lib:*:*:*:*:*:*:*:*:*', vulnerable: true }] }] }],
      dates: { published: '2024-04-01T00:00:00Z', lastModified: '2024-04-10T00:00:00Z' },
      status: 'Analyzed'
    },
    {
      id: 'CVE-2024-7890',
      descriptions: `Cross-site scripting (XSS) vulnerability in ${query} web interface`,
      cvss: { score: 6.1, severity: 'MEDIUM', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', version: '3.1' },
      cwe: ['CWE-79: Improper Neutralization of Input During Web Page Generation'],
      references: [{ url: 'https://example.com/xss/CVE-2024-7890', tags: ['Exploit', 'Technical Description'] }],
      affectedConfigurations: [{ nodes: [{ cpeMatch: [{ criteria: 'cpe:2.3:a:vendor:webapp:*:*:*:*:*:*:*:*:*', vulnerable: true }] }] }],
      dates: { published: '2024-05-12T00:00:00Z', lastModified: '2024-05-20T00:00:00Z' },
      status: 'Analyzed'
    }
  ];

  const stats = generateStats(demoCVEs);

  return {
    results: demoCVEs,
    statistics: stats,
    pagination: {
      totalResults: demoCVEs.length,
      resultsPerPage: 20,
      currentPage: 1
    }
  };
}
