import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

// REAL ip-api.com integration - NO fake data
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const ip = searchParams.get('ip');
  
  if (!ip) {
    return NextResponse.json({ error: 'IP address is required' }, { status: 400 });
  }

  try {
    // Call REAL ip-api.com API
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query`, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/json'
      }
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      throw new Error(`ip-api.com returned status: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Save to database
    let savedIOC = null;
    try {
      savedIOC = await db.iOC.upsert({
        where: { value: ip },
        update: {
          lastUpdated: new Date(),
          rawResponse: JSON.stringify(data),
          status: data.status === 'success' ? 'SUSPICIOUS' : 'UNKNOWN',
          severity: data.proxy || data.hosting ? 'HIGH' : 'MEDIUM'
        },
        create: {
          type: 'IP',
          value: ip,
          description: `IP Geolocation: ${data.city || 'Unknown'}, ${data.country || 'Unknown'}`,
          severity: data.proxy || data.hosting ? 'HIGH' : (data.mobile ? 'LOW' : 'MEDIUM'),
          confidence: data.status === 'success' ? 90 : 30,
          source: 'ip-api.com',
          rawResponse: JSON.stringify(data),
          tags: JSON.stringify([
            data.proxy && 'proxy',
            data.hosting && 'hosting',
            data.mobile && 'mobile',
            data.isp || 'ISP: ' + data.isp
          ].filter(Boolean))
        }
      });

      // Save analysis record with correct foreign key
      if (savedIOC?.id) {
        await db.analysis.create({
          data: {
            iocId: savedIOC.id,
            source: 'ip-api.com',
            sourceType: 'GEO_IP',
            rawData: JSON.stringify(data),
            summary: `Location: ${data.city}, ${data.regionName}, ${data.country}. ISP: ${data.org || data.isp}`,
            verified: data.status === 'success'
          }
        });
      }
    } catch (dbError) {
      console.error('DB save error (non-critical):', dbError);
    }
    
    // Return REAL data only - no fallbacks
    return NextResponse.json({
      success: true,
      source: 'ip-api.com',
      timestamp: new Date().toISOString(),
      fetchedLive: true,
      data: data
    });
    
  } catch (error) {
    console.error('IP Lookup Error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to fetch from ip-api.com',
      details: error instanceof Error ? error.message : 'Unknown error',
      suggestion: 'Verify the IP address is valid and try again'
    }, { status: 502 });
  }
}

// POST to add IOC manually
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { ip, description, tags, severity } = body;
    
    if (!ip) {
      return NextResponse.json({ error: 'IP address is required' }, { status: 400 });
    }
    
    const ioc = await db.iOC.create({
      data: {
        type: 'IP',
        value: ip,
        description: description || `Manually added IP: ${ip}`,
        severity: severity || 'MEDIUM',
        confidence: 70,
        status: 'UNKNOWN',
        source: 'manual',
        tags: JSON.stringify(tags || [])
      }
    });
    
    return NextResponse.json({ success: true, ioc });
  } catch (error) {
    console.error('Create IOC Error:', error);
    return NextResponse.json({ 
      success: false, 
      error: 'Failed to create IOC',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}
