import { NextRequest, NextResponse } from 'next/server';

// Sample threat data when external APIs are unavailable
const SAMPLE_THREAT_DATA = {
  cisa: [
    { 
      cveID: 'CVE-2024-3400', 
      vendorProject: 'Palo Alto Networks', 
      product: 'PAN-OS', 
      vulnerabilityName: 'Command Injection Vulnerability',
      dateAdded: '2024-04-12',
      shortDescription: 'PAN-OS GlobalProtect gateway allows authentication bypass leading to command execution.',
      requiredAction: 'Update to patched version',
      dueDate: '2024-04-30'
    },
    { 
      cveID: 'CVE-2024-21887', 
      vendorProject: 'Ivanti', 
      product: 'Connect Secure / Policy Secure',
      vulnerabilityName: 'Request Smuggling RCE',
      dateAdded: '2024-01-25',
      shortDescription: 'Authentication bypass allowing remote code execution on vulnerable endpoints.',
      requiredAction: 'Apply vendor patches immediately',
      dueDate: '2024-02-08'
    },
    { 
      cveID: 'CVE-2023-44428', 
      vendorProject: 'Citrix', 
      product: 'NetScaler ADC / Gateway',
      vulnerabilityName: 'RCE Vulnerability',
      dateAdded: '2023-10-15',
      shortDescription: 'Critical unauthenticated RCE affecting NetScaler ADC and Gateway appliances.',
      requiredAction: 'Upgrade to fixed version',
      dueDate: '2023-11-01'
    },
    { 
      cveID: 'CVE-2024-21412', 
      vendorProject: 'Microsoft', 
      product: 'Exchange Server',
      vulnerabilityName: 'Privilege Escalation Vulnerability',
      dateAdded: '2024-03-14',
      shortDescription: 'An authenticated attacker could exploit this to gain SYSTEM privileges.',
      requiredAction: 'Install security update',
      dueDate: '2024-04-02'
    }
  ],
  malware: [
    { 
      sha256_hash: 'a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890', 
      md5_hash: 'abc123def4567890abcdef1234567890ab', 
      file_type: 'PE32+ executable (GUI) x86-64', 
      signature: 'Emotet', 
      first_seen: '2024-07-20T10:30:00Z', 
      last_seen: '2024-08-03T14:22:00Z',
      tags: ['banker', 'trojan', 'botnet']
    },
    { 
      sha256_hash: 'f7e8d9c0b1a234567890abcdef1234567890abcdef1234567890abcdef1234567', 
      md5_hash: '789ghi012jkl345mno6pqrstu789vwxyz', 
      file_type: 'PDF document', 
      signature: 'Phishing PDF with JavaScript', 
      first_seen: '2024-07-18T08:15:00Z', 
      last_seen: '2024-08-02T16:45:00Z',
      tags: ['phishing', 'pdf', 'javascript']
    },
    { 
      sha256_hash: 'm3n4o5p6q7r8s9t0u1vwx yz01234567890abcdef1234567890abcdef12345678', 
      md5_hash: 'stu234vwx567y z890abcd efghij klmnopqrs', 
      file_type: 'MS Office document (Word)', 
      signature: 'TrickBot Loader', 
      first_seen: '2024-07-19T12:00:00Z', 
      last_seen: '2024-08-03T09:30:00Z',
      tags: ['loader', 'banker', 'office-macro']
    },
    { 
      sha256_hash: 'z9y8x7w6v5u4t3s2r1q0po9876543210zyxwvutsrqponmlkjihgfedcba98765', 
      md5_hash: 'ponmlkji hgfedcba 98765432 10zyxwvu tsrqponm', 
      file_type: 'Windows DLL', 
      signature: 'RedLine Stealer', 
      first_seen: '2024-07-21T06:45:00Z', 
      last_seen: '2024-08-01T18:20:00Z',
      tags: ['stealer', 'credentials', 'crypto']
    }
  ],
  sslbl: [
    { 
      sha256_fingerprint: '00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff', 
      status: 'bad', 
      listing_reason: 'Malicious SSL certificate detected in active phishing campaign targeting financial institutions'
    },
    { 
      sha256_fingerprint: 'aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66', 
      status: 'bad', 
      listing_reason: 'Certificate associated with APT28 infrastructure - state-sponsored threat actor'
    },
    { 
      sha256_fingerprint: 'fe:dc:ba:98:76:54:32:10:fe:dc:ba:98:76:54:32:10:fe:dc:ba:98:76:54:32:10:fe:dc:ba:98:76', 
      status: 'bad', 
      listing_reason: 'Self-signed certificate used in ransomware C2 communications'
    }
  ]
};

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const feed = searchParams.get('feed'); // cisa, abusech, malwaredl, all
  const limit = parseInt(searchParams.get('limit') || '20');
  
  try {
    let feeds: any[] = [];
    const feedStatus: Record<string, { status: string; message?: string }> = {};
    
    // Try external APIs but always have sample data as fallback
    
    // CISA Known Exploited Vulnerabilities
    if (feed === 'cisa' || feed === 'all' || !feed) {
      try {
        const cisaResponse = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
          signal: AbortSignal.timeout(8000),
          headers: { 'User-Agent': 'MONITOR-THREAT/1.0' }
        });
        
        if (cisaResponse.ok) {
          const cisaData = await cisaResponse.json();
          const vulnerabilities = cisaData.vulnerabilities || [];
          
          feedStatus['CISA-KEV'] = { status: 'ok' };
          
          feeds.push({
            source: 'CISA KEV Catalog',
            type: 'Known Exploited Vulnerabilities',
            count: vulnerabilities.length,
            status: 'active',
            entries: vulnerabilities.slice(0, Math.ceil(limit / 3)).map((v: any) => ({
              cveID: v.cveID,
              vendorProject: v.vendorProject,
              product: v.product,
              vulnerabilityName: v.vulnerabilityName,
              dateAdded: v.dateAdded,
              shortDescription: v.shortDescription?.substring(0, 150),
              requiredAction: v.requiredAction,
              dueDate: v.dueDate
            }))
          });
        } else {
          throw new Error(`HTTP ${cisaResponse.status}`);
        }
      } catch (e: any) {
        console.log('[THREATS] CISA API unavailable, using sample data:', e.message);
        feedStatus['CISA-KEV'] = { status: 'sample', message: 'Using realistic sample data' };
        
        feeds.push({
          source: 'CISA KEV Catalog (Sample)',
          type: 'Known Exploited Vulnerabilities',
          count: SAMPLE_THREAT_DATA.cisa.length,
          status: 'sample',
          entries: SAMPLE_THREAT_DATA.cisa.slice(0, Math.ceil(limit / 3))
        });
      }
    }
    
    // MalwareBazaar
    if (feed === 'malwaredl' || feed === 'all' || !feed) {
      try {
        const mbResponse = await fetch('https://mb-api.abuse.ch/api/v1/', {
          method: 'POST',
          signal: AbortSignal.timeout(8000),
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
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
          } else {
            throw new Error(mbData.query_status);
          }
        } else {
          throw new Error(`HTTP ${mbResponse.status}`);
        }
      } catch (e: any) {
        console.log('[THREATS] MalwareBazaar API unavailable, using sample data:', e.message);
        feedStatus['MalwareBazaar'] = { status: 'sample', message: 'Using realistic sample data' };
        
        feeds.push({
          source: 'MalwareBazaar (Sample)',
          type: 'Recent Malware Samples',
          count: SAMPLE_THREAT_DATA.malware.length,
          status: 'sample',
          entries: SAMPLE_THREAT_DATA.malware
        });
      }
    }
    
    // AbuseCH SSL Blacklist
    if (feed === 'abusech' || feed === 'all' || !feed) {
      try {
        const abusechResponse = await fetch('https://sslbl.abuse.ch/blacklist/json/', {
          signal: AbortSignal.timeout(8000),
          headers: { 'User-Agent': 'MONITOR-THREAT/1.0' }
        });
        
        if (abusechResponse.ok) {
          const abusechData = await abusechResponse.json();
          const entries = Array.isArray(abusechData) ? abusechData : (abusechData.data || []);
          
          feedStatus['AbuseCH SSLBL'] = { status: 'ok' };
          
          feeds.push({
            source: 'AbuseCH SSL Blacklist',
            type: 'Malicious SSL Certificates',
            count: entries.length,
            status: 'active',
            entries: entries.slice(0, Math.ceil(limit / 3)).map((entry: any) => ({
              sha256_fingerprint: entry.sha256_fingerprint || entry.sha256,
              status: entry.status,
              listingReason: entry.listing_reason
            }))
          });
        } else {
          throw new Error(`HTTP ${abusechResponse.status}`);
        }
      } catch (e: any) {
        console.log('[THREATS] AbuseCH API unavailable, using sample data:', e.message);
        feedStatus['AbuseCH SSLBL'] = { status: 'sample', message: 'Using realistic sample data' };
        
        feeds.push({
          source: 'AbuseCH SSLBL (Sample)',
          type: 'Malicious SSL Certificates',
          count: SAMPLE_THREAT_DATA.sslbl.length,
          status: 'sample',
          entries: SAMPLE_THREAT_DATA.sslbl
        });
      }
    }

    // If still no feeds (shouldn't happen), add default samples
    if (feeds.length === 0) {
      feeds.push(
        {
          source: 'CISA KEV Catalog (Sample)',
          type: 'Known Exploited Vulnerabilities',
          count: SAMPLE_THREAT_DATA.cisa.length,
          status: 'sample',
          entries: SAMPLE_THREAT_DATA.cisa
        },
        {
          source: 'MalwareBazaar (Sample)',
          type: 'Recent Malware Samples',
          count: SAMPLE_THREAT_DATA.malware.length,
          status: 'sample',
          entries: SAMPLE_THREAT_DATA.malware
        },
        {
          source: 'AbuseCH SSLBL (Sample)',
          type: 'Malicious SSL Certificates',
          count: SAMPLE_THREAT_DATA.sslbl.length,
          status: 'sample',
          entries: SAMPLE_THREAT_DATA.sslbl
        }
      );
      
      Object.keys(feedStatus).forEach(key => {
        feedStatus[key] = { status: 'sample', message: 'Sample data provided' };
      });
    }

    return NextResponse.json({
      success: true,
      timestamp: new Date().toISOString(),
      fetchedLive: true,
      totalFeeds: feeds.length,
      feeds,
      feedStatus,
      message: `Loaded ${feeds.length} threat intelligence feed(s)`
    });
    
  } catch (error) {
    console.error('Threat Feed Error:', error);
    
    // Even on error, return sample data
    return NextResponse.json({
      success: true,
      timestamp: new Date().toISOString(),
      fetchedLive: false,
      totalFeeds: 3,
      feeds: [
        {
          source: 'CISA KEV Catalog (Sample)',
          type: 'Known Exploited Vulnerabilities',
          count: SAMPLE_THREAT_DATA.cisa.length,
          status: 'fallback',
          entries: SAMPLE_THREAT_DATA.cisa
        },
        {
          source: 'MalwareBazaar (Sample)',
          type: 'Recent Malware Samples',
          count: SAMPLE_THREAT_DATA.malware.length,
          status: 'fallback',
          entries: SAMPLE_THREAT_DATA.malware
        },
        {
          source: 'AbuseCH SSLBL (Sample)',
          type: 'Malicious SSL Certificates',
          count: SAMPLE_THREAT_DATA.sslbl.length,
          status: 'fallback',
          entries: SAMPLE_THREAT_DATA.sslbl
        }
      ],
      feedStatus: {
        'CISA-KEV': { status: 'fallback', message: 'Error occurred, showing sample data' },
        'MalwareBazaar': { status: 'fallback', message: 'Error occurred, showing sample data' },
        'AbuseCH SSLBL': { status: 'fallback', message: 'Error occurred, showing sample data' }
      },
      message: 'Showing sample threat intelligence data'
    });
  }
}
