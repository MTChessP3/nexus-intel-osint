import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

// Report Generation - Executive summaries and briefings
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const type = searchParams.get('type') || 'executive';
  
  try {
    // Gather all data for report
    const [iocs, alerts, threatFeeds, analyses] = await Promise.all([
      db.iOC.findMany({ orderBy: { lastUpdated: 'desc' }, take: 100 }),
      db.alert.findMany({ where: { status: 'ACTIVE' }, orderBy: { createdAt: 'desc' }, take: 50 }),
      db.threatFeed.findMany({ orderBy: { fetchedAt: 'desc' }, take: 20 }),
      db.analysis.groupBy({
        by: ['source'],
        _count: true,
        orderBy: { _count: { source: 'desc' } }
      })
    ]);
    
    const reportData = {
      metadata: {
        generatedAt: new Date().toISOString(),
        platform: 'OSINT-Platform v8.0',
        reportType: type
      },
      executiveSummary: {
        totalIOCs: iocs.length,
        activeAlerts: alerts.length,
        criticalIOCs: iocs.filter(i => i.severity === 'CRITICAL').length,
        maliciousIOCs: iocs.filter(i => i.status === 'MALICIOUS').length,
        sourcesCovered: [...new Set(iocs.map(i => i.source).filter(Boolean))],
        dateRange: {
          earliest: iocs[iocs.length - 1]?.firstSeen || new Date(),
          latest: iocs[0]?.lastUpdated || new Date()
        }
      },
      severityBreakdown: {
        CRITICAL: iocs.filter(i => i.severity === 'CRITICAL').length,
        HIGH: iocs.filter(i => i.severity === 'HIGH').length,
        MEDIUM: iocs.filter(i => i.severity === 'MEDIUM').length,
        LOW: iocs.filter(i => i.severity === 'LOW').length,
        INFO: iocs.filter(i => i.severity === 'INFO').length
      },
      typeDistribution: {
        IP: iocs.filter(i => i.type === 'IP').length,
        DOMAIN: iocs.filter(i => i.type === 'DOMAIN').length,
        URL: iocs.filter(i => i.type === 'URL').length,
        HASH: iocs.filter(i => i.type === 'HASH').length,
        CVE: iocs.filter(i => i.type === 'CVE').length,
        EMAIL: iocs.filter(i => i.type === 'EMAIL').length
      },
      topThreats: alerts.slice(0, 10).map(alert => ({
        id: alert.id,
        title: alert.title,
        severity: alert.severity,
        type: alert.type,
        createdAt: alert.createdAt
      })),
      recentIntelligence: iocs.slice(0, 15).map(ioc => ({
        id: ioc.id,
        type: ioc.type,
        value: ioc.value,
        severity: ioc.severity,
        status: ioc.status,
        source: ioc.source,
        lastUpdated: ioc.lastUpdated
      })),
      analysisCoverage: analyses.map(a => ({
        source: a.source,
        count: a._count
      }))
    };
    
    // Save report to database
    await db.report.create({
      data: {
        title: `${type.charAt(0).toUpperCase() + type.slice(1)} Report`,
        type: type.toUpperCase() as any,
        content: JSON.stringify(reportData),
        format: 'json'
      }
    });
    
    return NextResponse.json({
      success: true,
      ...reportData
    });
    
  } catch (error) {
    console.error('Report Error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to generate report',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}
