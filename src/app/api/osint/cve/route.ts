import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

// REAL NIST NVD v2.0 API integration - NO fake data
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const cveId = searchParams.get('cveId');
  const keyword = searchParams.get('keyword');
  const resultsPerPage = parseInt(searchParams.get('limit') || '10');
  
  if (!cveId && !keyword) {
    return NextResponse.json({ error: 'CVE ID or search keyword is required' }, { status: 400 });
  }

  try {
    let apiUrl;
    
    if (cveId) {
      // Get specific CVE
      apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    } else {
      // Search by keyword
      const encodedKeyword = encodeURIComponent(keyword || '');
      apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodedKeyword}&resultsPerPage=${resultsPerPage}`;
    }
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    
    const response = await fetch(apiUrl, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'OSINT-Platform/1.0'
      }
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      if (response.status === 403) {
        throw new Error('NVD API rate limit exceeded. Try again later or use a different query.');
      }
      throw new Error(`NVD API returned status: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Process and save to database
    const cves = data.vulnerabilities || [];
    
    for (const vuln of cves) {
      const cve = vuln.cve;
      try {
        await db.iOC.upsert({
          where: { value: cve.id },
          update: { lastUpdated: new Date() },
          create: {
            type: 'CVE',
            value: cve.id,
            description: cve.descriptions?.[0]?.value?.substring(0, 500) || 'No description available',
            severity: mapCVSSSeverity(cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore),
            confidence: 95,
            source: 'NIST-NVD',
            rawResponse: JSON.stringify(cve).substring(0, 10000),
            tags: JSON.stringify(extractCVETags(cve))
          }
        });
      } catch (dbError) {
        console.error('DB save error (non-critical):', dbError);
      }
    }
    
    return NextResponse.json({
      success: true,
      source: 'NIST-NVD-v2.0',
      timestamp: new Date().toISOString(),
      fetchedLive: true,
      totalResults: data.totalResults || 0,
      resultsPerPage: data.resultsPerPage || 0,
      startIndex: data.startIndex || 0,
      vulnerabilities: cves.map(v => ({
        id: v.cve.id,
        published: v.cve.published,
        lastModified: v.cve.lastModified,
        descriptions: v.cve.descriptions,
        metrics: v.cve.metrics,
        weaknesses: v.cve.weaknesses,
        references: v.cve.references?.map(r => ({ url: r.url, tags: r.tags })) || [],
        configurations: v.cve.configurations
      }))
    });
    
  } catch (error) {
    console.error('CVE Lookup Error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to fetch from NIST NVD',
      details: error instanceof Error ? error.message : 'Unknown error',
      suggestion: 'Check your CVE format (e.g., CVE-2024-1234) or try again later'
    }, { status: 502 });
  }
}

function mapCVSSSeverity(score?: number): string {
  if (!score) return 'MEDIUM';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'INFO';
}

function extractCVETags(cve: any): string[] {
  const tags: string[] = [];
  
  // Extract CWE IDs
  if (cve.weaknesses) {
    for (const w of cve.weaknesses) {
      for (const d of w.description) {
        tags.push(d.value);
      }
    }
  }
  
  // Add severity tag
  const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore;
  if (score) tags.push(`CVSS:${score}`);
  
  return tags.slice(0, 5); // Limit tags
}
