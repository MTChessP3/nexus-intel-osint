import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

// Threat feeds with multiple sources - handles availability gracefully
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const feed = searchParams.get('feed'); // cisa, abusech, malwaredl, all
  const limit = parseInt(searchParams.get('limit') || '20');
  
  try {
    let feeds: any[] = [];
    const feedStatus: Record<string, { status: string; message?: string }> = {};
    
    // CISA Known Exploited Vulnerabilities
    if (feed === 'cisa' || feed === 'all') {
      try {
        const cisaResponse = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
          signal: AbortSignal.timeout(10000),
          headers: { 
            'User-Agent': 'OSINT-Platform/1.0',
            'Accept': 'application/json'
          }
        });
        
        if (cisaResponse.ok) {
          const cisaData = await cisaResponse.json();
          const vulnerabilities = cisaData.vulnerabilities || [];
          
          feedStatus['CISA-KEV'] = { status: 'ok' };
          
          for (const vuln of vulnerabilities.slice(0, limit)) {
            try {
              await db.threatFeed.create({
                data: {
                  feedName: 'CISA-KEV',
                  feedType: 'JSON',
                  entryTitle: `${vuln.cveID} - ${vuln.vulnerabilityName || 'Unknown'}`,
                  entryData: JSON.stringify(vuln),
                  iocExtracted: JSON.stringify([vuln.cveID]),
                  publishedAt: new Date(vuln.dateAdded)
                }
              });
              
              // Also save CVE to IOC database
              await db.iOC.upsert({
                where: { value: vuln.cveID },
                create: {
                  type: 'CVE',
                  value: vuln.cveID,
                  description: `${vuln.vendorProject} ${vuln.product}: ${vuln.shortDescription?.substring(0, 200)}`,
                  severity: 'CRITICAL',
                  confidence: 100,
                  status: 'MALICIOUS',
                  source: 'CISA-KEV',
                  tags: JSON.stringify(['known-exploited', 'cisa', vuln.product])
                },
                update: { lastUpdated: new Date() }
              });
            } catch (dbErr) {
              // Non-critical
            }
          }
          
          feeds.push({
            source: 'CISA-KEV',
            type: 'Known Exploited Vulnerabilities',
            count: vulnerabilities.length,
            lastUpdated: cisaData.dateReleased,
            status: 'active',
            entries: vulnerabilities.slice(0, Math.ceil(limit / 2)).map((v: any) => ({
              cveID: v.cveID,
              vendorProject: v.vendorProject,
              product: v.product,
              vulnerabilityName: v.vulnerabilityName,
              dateAdded: v.dateAdded,
              shortDescription: v.shortDescription,
              requiredAction: v.requiredAction,
              dueDate: v.dueDate
            }))
          });
        } else {
          feedStatus['CISA-KEV'] = { status: 'error', message: `HTTP ${cisaResponse.status}` };
        }
      } catch (e: any) {
        console.error('CISA feed error:', e.message);
        feedStatus['CISA-KEV'] = { status: 'error', message: e.message.includes('fetch') ? 'Network error or blocked' : e.message };
      }
    }
    
    // Abuse.ch SSL Blacklist
    if (feed === 'abusech' || feed === 'all') {
      try {
        const abusechResponse = await fetch('https://sslbl.abuse.ch/blacklist/json/', {
          signal: AbortSignal.timeout(15000),
          headers: { 'User-Agent': 'OSINT-Platform/1.0' }
        });
        
        if (abusechResponse.ok) {
          const abusechData = await abusechResponse.json();
          const entries = Array.isArray(abusechData) ? abusechData : (abusechData.data || []);
          
          feedStatus['AbuseCH-SSLBL'] = { status: 'ok' };
          
          feeds.push({
            source: 'AbuseCH-SSLBL',
            type: 'Malicious SSL Certificate Blacklist',
            count: entries.length,
            status: 'active',
            entries: entries.slice(0, Math.ceil(limit / 2)).map((entry: any) => ({
              sha256: entry.sha256_fingerprint || entry.sha256,
              status: entry.status,
              listingReason: entry.listing_reason
            }))
          });
        } else {
          feedStatus['AbuseCH-SSLBL'] = { status: 'error', message: `HTTP ${abusechResponse.status}` };
        }
      } catch (e: any) {
        console.error('AbuseCH error:', e.message);
        feedStatus['AbuseCH-SSLBL'] = { status: 'error', message: e.message };
      }
    }
    
    // MalwareBazaar
    if (feed === 'malwaredl' || feed === 'all') {
      try {
        const mbResponse = await fetch('https://mb-api.abuse.ch/api/v1/', {
          method: 'POST',
          signal: AbortSignal.timeout(15000),
          headers: { 
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'OSINT-Platform/1.0'
          },
          body: 'query=get_recent&limit=10'
        });
        
        if (mbResponse.ok) {
          const mbData = await mbResponse.json();
          
          if (mbData.query_status === 'ok' && mbData.data) {
            feedStatus['MalwareBazaar'] = { status: 'ok' };
            
            feeds.push({
              source: 'MalwareBazaar',
              type: 'Recent Malware Samples',
              count: mbData.data.length,
              status: 'active',
              entries: mbData.data.map((sample: any) => ({
                sha256: sample.sha256_hash,
                md5: sample.md5_hash,
                fileType: sample.file_type,
                signature: sample.signature,
                firstSeen: sample.first_seen,
                lastSeen: sample.last_seen,
                tags: sample.tags
              }))
            });
            
            // Save malware hashes
            for (const sample of mbData.data.slice(0, 5)) {
              try {
                await db.iOC.upsert({
                  where: { value: sample.sha256_hash },
                  create: {
                    type: 'HASH',
                    value: sample.sha256_hash,
                    description: `MalwareBazaar: ${sample.file_type} - ${sample.signature || 'Unknown malware'}`,
                    severity: 'CRITICAL',
                    confidence: 95,
                    status: 'MALICIOUS',
                    source: 'MalwareBazaar',
                    rawResponse: JSON.stringify(sample).substring(0, 5000),
                    tags: JSON.stringify(sample.tags || ['malware'])
                  },
                  update: { lastUpdated: new Date() }
                });
              } catch (dbErr) {}
            }
          } else {
            feedStatus['MalwareBazaar'] = { status: 'error', message: mbData.query_status || 'Unknown error' };
          }
        } else {
          feedStatus['MalwareBazaar'] = { status: 'error', message: `HTTP ${mbResponse.status}` };
        }
      } catch (e: any) {
        console.error('MalwareBazaar error:', e.message);
        feedStatus['MalwareBazaar'] = { status: 'error', message: e.message.includes('Unauthorized') ? 'API requires authentication' : e.message };
      }
    }

    return NextResponse.json({
      success: true,
      timestamp: new Date().toISOString(),
      fetchedLive: true,
      totalFeeds: feeds.length,
      feeds,
      feedStatus,
      message: feeds.length > 0 
        ? `Successfully loaded ${feeds.length} feed(s)` 
        : 'No feeds available. External APIs may be restricted in this environment.'
    });
    
  } catch (error) {
    console.error('Threat Feed Error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to fetch threat feeds',
      details: error instanceof Error ? error.message : 'Unknown error',
      suggestion: 'Some threat intelligence sources require specific access or may be rate-limited'
    }, { status: 502 });
  }
}
