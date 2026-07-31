import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

// Hash Analysis - Real malware hash lookups
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const hash = searchParams.get('hash');
  
  if (!hash) {
    return NextResponse.json({ error: 'Hash is required (MD5, SHA1, or SHA256)' }, { status: 400 });
  }

  try {
    // Determine hash type by length
    const hashType = getHashType(hash);
    
    // Query MalwareBazaar
    let mbResult = null;
    try {
      const mbResponse = await fetch('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'OSINT-Platform/1.0'
        },
        body: `query=get_info&hash=${hash}`,
        signal: AbortSignal.timeout(15000)
      });
      
      if (mbResponse.ok) {
        mbResult = await mbResponse.json();
      }
    } catch (e) {
      console.error('MalwareBazaar error:', e);
    }
    
    // Also check VirusTotal public API (limited, no key needed for basic)
    let vtResult = null;
    try {
      const vtResponse = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
        signal: AbortSignal.timeout(10000),
        headers: {
          'User-Agent': 'OSINT-Platform/1.0'
        }
      });
      
      if (vtResponse.ok) {
        vtResult = await vtResponse.json();
      } else if (vtResponse.status === 404) {
        vtResult = { found: false };
      }
    } catch (e) {
      console.error('VirusTotal error:', e);
    }
    
    const resultData = {
      hash,
      hashType,
      timestamp: new Date().toISOString(),
      fetchedLive: true,
      sources: {
        malwarebazaar: mbResult ? {
          status: mbResult.query_status,
          data: mbResult.data || null
        } : { error: 'Failed to query' },
        virustotal: vtResult || { error: 'Failed to query or not found' }
      },
      analysis: analyzeHashResults(mbResult, vtResult)
    };
    
    // Save to database
    const isMalicious = mbResult?.query_status === 'ok' && mbResult?.data;
    
    await db.iOC.upsert({
      where: { value: hash },
      update: { lastUpdated: new Date() },
      create: {
        type: 'HASH',
        value: hash,
        description: isMalicious 
          ? `MalwareBazaar: ${mbResult.data.signature || 'Known malware'}`
          : `Hash lookup performed - ${hashType}`,
        severity: isMalicious ? 'CRITICAL' : 'MEDIUM',
        confidence: isMalicious ? 95 : 40,
        status: isMalicious ? 'MALICIOUS' : 'UNKNOWN',
        source: isMalicious ? 'MalwareBazaar' : 'Hash-Lookup',
        rawResponse: JSON.stringify(resultData).substring(0, 10000),
        tags: JSON.stringify(isMalicious ? ['malware', hashType.toLowerCase()] : [hashType.toLowerCase()])
      }
    });
    
    return NextResponse.json({
      success: true,
      ...resultData
    });
    
  } catch (error) {
    console.error('Hash Lookup Error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to perform hash lookup',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 502 });
  }
}

function getHashType(hash: string): string {
  const len = hash.length;
  if (len === 32) return 'MD5';
  if (len === 40) return 'SHA1';
  if (len === 64) return 'SHA256';
  if (len === 128) return 'SHA512';
  return 'Unknown';
}

function analyzeHashResults(mbResult: any, vtResult: any) {
  const findings: string[] = [];
  let threatLevel = 'INFO' as string;
  
  if (mbResult?.query_status === 'ok' && mbResult?.data) {
    const d = mbResult.data;
    findings.push(`File type: ${d.file_type || 'Unknown'}`);
    findings.push(`Signature: ${d.signature || 'No signature match'}`);
    findings.push(`First seen: ${d.first_seen || 'Unknown'}`);
    
    if (d.tags && d.tags.length > 0) {
      findings.push(`Tags: ${d.tags.join(', ')}`);
    }
    
    if (d.signature) {
      threatLevel = 'CRITICAL';
      findings.push('MALICIOUS: Known malware signature detected');
    }
  } else if (mbResult?.query_status === 'hash_not_found') {
    findings.push('Hash not found in MalwareBazaar database');
    threatLevel = 'LOW';
  }
  
  if (vtResult?.data?.attributes) {
    const attrs = vtResult.data.attributes;
    if (attrs.last_analysis_stats) {
      const stats = attrs.last_analysis_stats;
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      findings.push(`VirusTotal: ${malicious}/${malicious + (stats.undetected || 0)} engines detected as malicious`);
      
      if (malicious > 5) {
        threatLevel = 'CRITICAL';
      } else if (malicious > 0) {
        threatLevel = 'HIGH';
      }
    }
  }
  
  return {
    threatLevel,
    findings,
    recommendation: threatLevel === 'CRITICAL' 
      ? 'ISOLATE AND DELETE: This file is confirmed malware'
      : threatLevel === 'HIGH'
      ? 'Quarantine and investigate further'
      : 'Monitor and verify through additional sources'
  };
}
