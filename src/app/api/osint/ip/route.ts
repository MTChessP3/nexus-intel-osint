import { NextRequest, NextResponse } from 'next/server';
import { lookupIP } from '@/lib/intel';
import { upsertIOC, createAnalysis, createAlert } from '@/lib/store';

// IP Intelligence — real ip-api.com lookup with persistent store
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const ip = searchParams.get('ip');

  if (!ip) {
    return NextResponse.json(
      {
        success: false,
        error: 'IP address is required',
        suggestion: 'Enter a valid IP address (e.g., 8.8.8.8 or 185.220.101.34)',
      },
      { status: 400 }
    );
  }

  try {
    const { live, source, data } = await lookupIP(ip);

    const threatLevel = data.proxy || data.hosting ? 'ELEVATED' : 'NORMAL';

    try {
      const ioc = await upsertIOC({
        type: 'IP',
        value: ip,
        description: `IP Geolocation: ${data.city || 'Unknown'}, ${data.country || 'Unknown'}`,
        severity: data.proxy || data.hosting ? 'HIGH' : data.mobile ? 'LOW' : 'MEDIUM',
        confidence: live ? 90 : 75,
        status: data.proxy || data.hosting ? 'SUSPICIOUS' : 'UNKNOWN',
        source: live ? source : 'cached',
        rawResponse: JSON.stringify(data),
        tags: [data.proxy && 'proxy', data.hosting && 'hosting', data.mobile && 'mobile', `ISP: ${data.isp || 'Unknown'}`].filter(Boolean),
      });

      await createAnalysis({
        iocId: ioc.id,
        source,
        sourceType: 'GEO_IP',
        rawData: JSON.stringify(data),
        summary: `Location: ${data.city}, ${data.regionName}, ${data.country}. ISP: ${data.org || data.isp}`,
        verified: live,
      });

      if (data.proxy || data.hosting) {
        await createAlert({
          iocId: ioc.id,
          title: `Suspicious IP Detected: ${ip}`,
          description: `IP has proxy/hosting flags. Location: ${data.city}, ${data.country}`,
          severity: 'HIGH',
          type: 'ANOMALY_DETECTED',
        });
      }
    } catch (storeError) {
      console.error('Store save error (non-critical):', storeError);
    }

    return NextResponse.json({
      success: true,
      source,
      timestamp: new Date().toISOString(),
      fetchedLive: live,
      data,
      analysis: {
        threatLevel,
        recommendations:
          data.proxy ? [
            'This IP is a known proxy/VPN — additional verification recommended',
            'Check for multiple accounts from this IP',
            'Consider blocking if not required for business',
          ] : data.hosting ? [
            'This IP is from a hosting provider — could be server/shared hosting',
            'Higher risk of being compromised or misused',
            'Monitor for suspicious activity',
          ] : [
            'Standard residential/business IP',
            'No immediate threats detected',
            'Continue normal monitoring',
          ],
      },
    });
  } catch (error) {
    console.error('IP Lookup Error:', error);
    const { data } = await lookupIP(ip);
    return NextResponse.json({
      success: true,
      source: 'fallback-data',
      timestamp: new Date().toISOString(),
      fetchedLive: false,
      data,
      error: 'Primary lookup failed, showing cached data',
      details: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}

// POST: manually add an IP IOC
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { ip, description, tags, severity } = body;

    if (!ip) {
      return NextResponse.json({ success: false, error: 'IP address is required' }, { status: 400 });
    }

    const ioc = await upsertIOC({
      type: 'IP',
      value: ip,
      description: description || `Manually added IP: ${ip}`,
      severity: severity || 'MEDIUM',
      confidence: 70,
      status: 'UNKNOWN',
      source: 'manual',
      tags: tags || [],
    });

    return NextResponse.json({
      success: true,
      ioc,
      message: `IP ${ip} added successfully`,
    });
  } catch (error: any) {
    console.error('Create IOC Error:', error);
    return NextResponse.json(
      { success: false, error: error.message || 'Failed to create IOC', details: error.message },
      { status: 500 }
    );
  }
}
