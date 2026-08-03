import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

// Export functionality - PDF, CSV, JSON
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const format = searchParams.get('format') || 'json'; // json, csv
  const type = searchParams.get('type'); // Filter by IOC type
  const status = searchParams.get('status');
  const severity = searchParams.get('severity');
  
  try {
    // Build query
    const where: any = {};
    if (type) where.type = type.toUpperCase();
    if (status) where.status = status.toUpperCase();
    if (severity) where.severity = severity.toUpperCase();
    
    const iocs = await db.iOC.findMany({
      where,
      orderBy: { lastUpdated: 'desc' },
      include: {
        analyses: { take: 1 },
        alerts: { where: { status: 'ACTIVE' }, take: 3 }
      }
    });
    
    const timestamp = new Date().toISOString();
    
    switch (format.toLowerCase()) {
      case 'csv':
        return exportCSV(iocs, timestamp);
      
      case 'json':
      default:
        return exportJSON(iocs, timestamp);
    }
    
  } catch (error) {
    console.error('Export Error:', error);
    return NextResponse.json({
      success: false,
      error: 'Export failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}

function exportJSON(iocs: any[], timestamp: string) {
  const report = {
    metadata: {
      title: 'MONITOR-THREAT Export',
      generatedAt: timestamp,
      platform: 'OSINT-Platform v8.0',
      totalIOCs: iocs.length,
      sources: [...new Set(iocs.map(i => i.source).filter(Boolean))]
    },
    summary: {
      byType: countBy(iocs, 'type'),
      bySeverity: countBy(iocs, 'severity'),
      byStatus: countBy(iocs, 'status'),
      bySource: countBy(iocs, 'source')
    },
    data: iocs.map(ioc => ({
      id: ioc.id,
      type: ioc.type,
      value: ioc.value,
      description: ioc.description,
      severity: ioc.severity,
      confidence: ioc.confidence,
      status: ioc.status,
      source: ioc.source,
      tags: JSON.parse(ioc.tags || '[]'),
      firstSeen: ioc.firstSeen,
      lastUpdated: ioc.lastUpdated,
      analysisCount: ioc.analyses?.length || 0,
      activeAlerts: ioc.alerts?.length || 0,
      rawResponse: ioc.rawResponse ? JSON.parse(ioc.rawResponse) : null
    }))
  };
  
  return new NextResponse(JSON.stringify(report, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="osint-export-${timestamp.split('T')[0]}.json"`
    }
  });
}

function exportCSV(iocs: any[], timestamp: string) {
  const headers = [
    'ID', 'Type', 'Value', 'Description', 'Severity', 
    'Confidence', 'Status', 'Source', 'Tags', 
    'First Seen', 'Last Updated', 'Analyses', 'Alerts'
  ];
  
  const rows = iocs.map(ioc => [
    ioc.id,
    ioc.type,
    ioc.value,
    `"${(ioc.description || '').replace(/"/g, '""')}"`,
    ioc.severity,
    ioc.confidence,
    ioc.status,
    ioc.source || '',
    `"${JSON.parse(ioc.tags || '[]').join('; ')}"`,
    ioc.firstSeen,
    ioc.lastUpdated,
    ioc.analyses?.length || 0,
    ioc.alerts?.length || 0
  ]);
  
  const csvContent = [
    `# MONITOR-THREAT Export`,
    `# Generated: ${timestamp}`,
    `# Total IOCs: ${iocs.length}`,
    '',
    headers.join(','),
    ...rows.map(row => row.join(','))
  ].join('\n');
  
  return new NextResponse(csvContent, {
    headers: {
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="osint-export-${timestamp.split('T')[0]}.csv"`
    }
  });
}

function countBy(arr: any[], field: string): Record<string, number> {
  return arr.reduce((acc, item) => {
    const key = item[field] || 'unknown';
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
}
