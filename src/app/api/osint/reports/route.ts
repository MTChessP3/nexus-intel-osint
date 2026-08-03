import { NextRequest, NextResponse } from 'next/server';
import { writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { existsSync } from 'fs';

const REPORTS_DIR = join(process.cwd(), 'generated-reports');

interface ReportConfig {
  title: string;
  modules: string[];
  format: 'PDF' | 'JSON' | 'CSV' | 'HTML';
  includeIOCs: boolean;
  includeThreats: boolean;
  includeTimeline: boolean;
  customData?: any;
  executiveSummary: boolean;
  recommendations: boolean;
}

interface GeneratedReport {
  id: string;
  config: ReportConfig;
  timestamp: string;
  content: {
    executiveSummary?: any;
    moduleData: Record<string, any>;
    iocs?: any[];
    threats?: any[];
    timeline?: any[];
    statistics: any;
    recommendations?: string[];
  };
  filePath: string;
}

async function ensureDir(dir: string) {
  if (!existsSync(dir)) {
    await mkdir(dir, { recursive: true });
  }
}

function generateId(): string {
  return `rpt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// Generate executive summary based on selected modules
async function generateExecutiveSummary(modules: string[], iocData: any[], threatData: any[]): Promise<any> {
  const summary = {
    overallRiskLevel: 'MEDIUM' as string,
    keyFindings: [] as string[],
    criticalItems: 0,
    highRiskItems: 0,
    totalIndicators: 0,
    coverage: modules,
    generatedAt: new Date().toISOString()
  };
  
  // Analyze IOCs
  if (iocData && iocData.length > 0) {
    summary.totalIndicators = iocData.length;
    summary.criticalItems = iocData.filter((i: any) => i.severity === 'CRITICAL').length;
    summary.highRiskItems = iocData.filter((i: any) => i.severity === 'HIGH').length;
    
    if (summary.criticalItems > 5) {
      summary.overallRiskLevel = 'CRITICAL';
      summary.keyFindings.push(`${summary.criticalItems} CRITICAL severity indicators detected`);
    } else if (summary.criticalItems > 0 || summary.highRiskItems > 10) {
      summary.overallRiskLevel = 'HIGH';
      summary.keyFindings.push(`High concentration of severe indicators`);
    }
    
    const maliciousCount = iocData.filter((i: any) => i.status === 'MALICIOUS').length;
    if (maliciousCount > 0) {
      summary.keyFindings.push(`${maliciousCount} indicators confirmed as MALICIOUS`);
    }
  }
  
  // Analyze threats
  if (threatData && threatData.length > 0) {
    const activeThreats = threatData.filter((t: any) => t.status !== 'resolved');
    summary.keyFindings.push(`${activeThreats.length} active threats being tracked`);
  }
  
  // Module-specific findings
  if (modules.includes('ip')) {
    summary.keyFindings.push('IP Intelligence analysis included');
  }
  if (modules.includes('domain')) {
    summary.keyFindings.push('Domain forensics analysis included');
  }
  if (modules.includes('darkweb')) {
    summary.keyFindings.push('Dark web monitoring data included');
    summary.overallRiskLevel = summary.overallRiskLevel === 'MEDIUM' ? 'ELEVATED' : summary.overallRiskLevel;
  }
  if (modules.includes('mobile')) {
    summary.keyFindings.push('Mobile application security assessment included');
  }
  
  return summary;
}

// Generate recommendations based on data
function generateRecommendations(data: Record<string, any>): string[] {
  const recommendations: string[] = [];
  
  // IOC-based recommendations
  if (data.iocs) {
    const criticalIocs = data.iocs.filter((i: any) => i.severity === 'CRITICAL');
    if (criticalIocs.length > 0) {
      recommendations.push(`Immediate action required for ${criticalIocs.length} CRITICAL indicators - consider blocking in security controls`);
    }
    
    const maliciousIocs = data.iocs.filter((i: any) => i.status === 'MALICIOUS');
    if (maliciousIocs.length > 0) {
      recommendations.push(`${maliciousIocs.length} malicious indicators should be added to blocklists immediately`);
    }
  }
  
  // Domain-based recommendations
  if (data.domain?.riskAssessment?.findings) {
    data.domain.riskAssessment.findings.forEach((finding: string) => {
      recommendations.push(`Domain Security: ${finding}`);
    });
  }
  
  // Dark web recommendations
  if (data.darkweb?.aiAnalysis?.recommendedActions) {
    recommendations.push(...data.darkweb.aiAnalysis.recommendedActions.slice(0, 3));
  }
  
  // Mobile recommendations
  if (data.mobile?.aiAssessment?.recommendations) {
    recommendations.push(...data.mobile.aiAssessment.recommendations.slice(0, 3));
  }
  
  // General recommendations
  recommendations.push(
    'Schedule regular threat intelligence updates',
    'Review and update IOC feeds weekly',
    'Conduct security awareness training based on current threats'
  );
  
  return [...new Set(recommendations)].slice(0, 10);
}

// Generate timeline of events
function generateTimeline(modules: string[], allData: Record<string, any>): any[] {
  const timeline: any[] = [];
  const now = new Date();
  
  // Add recent events based on modules
  if (modules.includes('iocs') && allData.iocs) {
    allData.iocs.slice(0, 5).forEach((ioc: any, idx: number) => {
      timeline.push({
        date: new Date(now.getTime() - idx * 3600000).toISOString(),
        event: `IOC ${ioc.type} ${ioc.value} ${ioc.status}`,
        type: 'ioc',
        severity: ioc.severity
      });
    });
  }
  
  if (modules.includes('threats') && allData.threats) {
    allData.threats.slice(0, 3).forEach((threat: any, idx: number) => {
      timeline.push({
        date: new Date(now.getTime() - (idx + 1) * 7200000).toISOString(),
        event: `Threat update: ${threat.title || threat.name}`,
        type: 'threat',
        severity: 'INFO'
      });
    });
  }
  
  // Add system events
  timeline.push({
    date: now.toISOString(),
    event: 'Report generated',
    type: 'system',
    severity: 'INFO'
  });
  
  return timeline.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const config: ReportConfig = {
      title: body.title || 'MONITOR-THREAT Intelligence Report',
      modules: body.modules || ['dashboard', 'iocs'],
      format: body.format || 'PDF',
      includeIOCs: body.includeIOCs ?? true,
      includeThreats: body.includeThreats ?? true,
      includeTimeline: body.includeTimeline ?? true,
      customData: body.customData,
      executiveSummary: body.executiveSummary ?? true,
      recommendations: body.recommendations ?? true
    };
    
    console.log('[REPORTS] Generating report:', config.title);
    
    // Gather data from different sources
    const moduleData: Record<string, any> = {};
    
    // Fetch IOC data if requested
    let iocData: any[] = [];
    if (config.includeIOCs || config.modules.includes('iocs')) {
      try {
        const iocResponse = await fetch(`${process.env.NEXT_PUBLIC_BASE_URL || ''}/api/osint/iocs?limit=100`);
        if (iocResponse.ok) {
          const iocResult = await iocResponse.json();
          iocData = iocResult.data || [];
          moduleData.iocs = iocData;
        }
      } catch (e) {
        console.log('Could not fetch IOCs for report');
      }
    }
    
    // Fetch threat data if requested
    let threatData: any[] = [];
    if (config.includeThreats || config.modules.includes('threats')) {
      try {
        const threatResponse = await fetch(`${process.env.NEXT_PUBLIC_BASE_URL || ''}/api/osint/threats?limit=50`);
        if (threatResponse.ok) {
          const threatResult = await threatResponse.json();
          threatData = threatResult.feeds || threatResult.data || [];
          moduleData.threats = threatData;
        }
      } catch (e) {
        console.log('Could not fetch threats for report');
      }
    }
    
    // Include custom data if provided
    if (config.customData) {
      Object.keys(config.customData).forEach(key => {
        moduleData[key] = config.customData[key];
      });
    }
    
    // Generate executive summary
    let execSummary;
    if (config.executiveSummary) {
      execSummary = await generateExecutiveSummary(config.modules, iocData, threatData);
    }
    
    // Generate recommendations
    let recs;
    if (config.recommendations) {
      recs = generateRecommendations(moduleData);
    }
    
    // Generate timeline
    let timeline;
    if (config.includeTimeline) {
      timeline = generateTimeline(config.modules, moduleData);
    }
    
    // Compile report
    const report: GeneratedReport = {
      id: generateId(),
      config,
      timestamp: new Date().toISOString(),
      content: {
        executiveSummary: execSummary,
        moduleData,
        iocs: config.includeIOCs ? iocData : undefined,
        threats: config.includeThreats ? threatData : undefined,
        timeline,
        statistics: {
          totalIOCs: iocData.length,
          totalThreats: threatData.length,
          modulesIncluded: config.modules.length,
          format: config.format
        },
        recommendations: recs
      },
      filePath: ''
    };
    
    // Save report
    await ensureDir(REPORTS_DIR);
    const fileName = `${report.id}_${config.format.toLowerCase()}.json`;
    const filePath = join(REPORTS_DIR, fileName);
    
    await writeFile(filePath, JSON.stringify(report, null, 2));
    report.filePath = filePath;
    
    return NextResponse.json({
      success: true,
      source: 'Report Generator v2.0',
      fetchedLive: true,
      data: report,
      message: `Report "${config.title}" generated successfully`
    });
    
  } catch (error) {
    console.error('Report generation error:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Report generation failed'
    }, { status: 500 });
  }
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action');
  
  if (action === 'list') {
    // List available reports
    try {
      if (!existsSync(REPORTS_DIR)) {
        return NextResponse.json({ success: true, data: [] });
      }
      
      const { readdir } = require('fs/promises');
      const files = await readdir(REPORTS_DIR);
      
      const reports = files.map(f => ({
        name: f,
        created: f.split('_')[1]?.replace('.json', '') || 'unknown'
      }));
      
      return NextResponse.json({ 
        success: true, 
        data: reports.sort((a, b) => b.created.localeCompare(a.created))
      });
    } catch (error) {
      return NextResponse.json({ success: false, error: 'Failed to list reports' });
    }
  }
  
  if (action === 'get') {
    // Get specific report
    const id = searchParams.get('id');
    if (!id) {
      return NextResponse.json({ success: false, error: 'Report ID required' });
    }
    
    try {
      const { readFile } = require('fs/promises');
      const files = await readdir(REPORTS_DIR);
      const reportFile = files.find(f => f.startsWith(id));
      
      if (!reportFile) {
        return NextResponse.json({ success: false, error: 'Report not found' });
      }
      
      const content = await readFile(join(REPORTS_DIR, reportFile), 'utf-8');
      return NextResponse.json({ success: true, data: JSON.parse(content) });
    } catch (error) {
      return NextResponse.json({ success: false, error: 'Failed to read report' });
    }
  }
  
  // Return report templates and options
  return NextResponse.json({
    success: true,
    source: 'Report Generator v2.0',
    data: {
      templates: [
        {
          id: 'executive',
          name: 'Executive Summary',
          description: 'High-level overview for leadership',
          modules: ['dashboard', 'iocs', 'threats'],
          recommendedFor: ['CISO', 'C-Suite', 'Board']
        },
        {
          id: 'technical',
          name: 'Technical Analysis',
          description: 'Detailed technical findings',
          modules: ['ip', 'domain', 'url', 'hash', 'cve'],
          recommendedFor: ['SOC Analysts', 'Incident Response', 'Threat Hunters']
        },
        {
          id: 'threat-hunt',
          name: 'Threat Hunt Report',
          description: 'Focused threat intelligence',
          modules: ['darkweb', 'threats', 'ai'],
          recommendedFor: ['Threat Intelligence Team', 'Red Team']
        },
        {
          id: 'mobile-security',
          name: 'Mobile Security Assessment',
          description: 'Mobile app security analysis',
          modules: ['mobile'],
          recommendedFor: ['Mobile Security Team', 'App Developers']
        },
        {
          id: 'comprehensive',
          name: 'Comprehensive Report',
          description: 'All modules, complete analysis',
          modules: ['dashboard', 'ip', 'domain', 'url', 'hash', 'cve', 'ai', 'darkweb', 'threats', 'iocs', 'mobile'],
          recommendedFor: ['Full Security Audit', 'Compliance']
        },
        {
          id: 'forensics',
          name: 'Digital Forensics',
          description: 'Domain/IP forensic deep dive',
          modules: ['domain', 'ip', 'forensics'],
          recommendedFor: ['DFIR Team', 'Law Enforcement']
        }
      ],
      formats: ['PDF', 'JSON', 'CSV', 'HTML'],
      exportOptions: {
        includeRawData: true,
        includeVisualizations: true,
        includeIOCList: true,
        includeRecommendations: true,
        includeTimeline: true
      },
      scheduling: {
        supported: true,
        intervals: ['daily', 'weekly', 'monthly', 'quarterly']
      }
    }
  });
}
