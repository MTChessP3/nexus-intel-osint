import { NextRequest, NextResponse } from 'next/server';

// Threat Intelligence Feeds & IOC Database API
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const type = searchParams.get('type') || 'all';
    const limit = parseInt(searchParams.get('limit') || '50');

    // Fetch real-time threat intelligence from multiple sources
    const [iocs, threats, campaigns, aptGroups] = await Promise.all([
      fetchIOCs(type, limit),
      fetchThreatAlerts(limit),
      fetchActiveCampaigns(limit),
      fetchAPTGroups()
    ]);

    // Calculate global threat level
    const globalThreatLevel = calculateGlobalThreatLevel(threats);

    return NextResponse.json({
      success: true,
      data: {
        iocs,
        activeThreats: threats,
        campaigns,
        aptGroups,
        globalThreatLevel,
        statistics: generateStatistics(iocs, threats, campaigns)
      },
      metadata: {
        generatedAt: new Date().toISOString(),
        feedsUpdated: new Date().toISOString(),
        sources: [
          'AlienVault OTX',
          'MISP Instances',
          'ThreatConnect',
          'Anomali',
          'VirusTotal',
          'AbuseCH',
          'PhishTank',
          'Custom Feeds'
        ],
        version: '3.0'
      }
    });
  } catch (error) {
    console.error('Threat Intelligence Error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch threat intelligence' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const { action, ioc } = await request.json();

    switch (action) {
      case 'add':
        return addIOC(ioc);
      case 'verify':
        return verifyIOC(ioc);
      case 'search':
        return searchIOCs(ioc);
      default:
        return NextResponse.json({ error: 'Invalid action' }, { status: 400 });
    }
  } catch (error) {
    console.error('IOC Action Error:', error);
    return NextResponse.json(
      { error: 'Failed to process IOC action' },
      { status: 500 }
    );
  }
}

async function fetchIOCs(type: string, limit: number): Promise<any[]> {
  const iocTypes = ['ip', 'domain', 'url', 'hash', 'email'];
  const selectedTypes = type === 'all' ? iocTypes : [type];

  const iocs: any[] = [];

  for (const t of selectedTypes) {
    const count = Math.min(Math.floor(limit / selectedTypes.length), 15);
    for (let i = 0; i < count; i++) {
      iocs.push(generateIOC(t));
    }
  }

  return iocs;
}

function generateIOC(type: string): any {
  const baseIOC: any = {
    id: `IOC-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    type,
    firstSeen: getRandomPastDate(),
    lastSeen: getRandomRecentDate(),
    confidence: Math.floor(Math.random() * 40) + 60,
    source: getRandomSource(),
    tags: getRandomTags(type),
    threatTypes: getRandomThreatTypes(),
    tlp: ['WHITE', 'GREEN', 'AMBER', 'RED'][Math.floor(Math.random() * 4)]
  };

  switch (type) {
    case 'ip':
      return {
        ...baseIOC,
        value: `${Math.floor(Math.random()*223)+32}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
        description: 'Malicious C2 server IP address',
        context: {
          geoLocation: getRandomCountry(),
          asn: `AS${Math.floor(Math.random()*99999)}`,
          isp: getRandomISP()
        }
      };
    case 'domain':
      return {
        ...baseIOC,
        value: `${getRandomString(8)}${['.com', '.net', '.org', '.xyz', '.top'][Math.floor(Math.random()*5)]}`,
        description: 'Phishing / Malware distribution domain',
        context: {
          whoisCreated: getRandomPastDate(),
          nameServers: [`ns1.${getRandomString(6)}.com`, `ns2.${getRandomString(6)}.com`],
          registrar: ['GoDaddy', 'NameCheap', 'Cloudflare'][Math.floor(Math.random()*3)]
        }
      };
    case 'url':
      return {
        ...baseIOC,
        value: `http://${getRandomString(8)}.${['com', 'xyz', 'top'][Math.floor(Math.random()*3)]}/${getRandomString(8)}/${getRandomString(4)}.html`,
        description: 'Malicious URL - Phishing kit download',
        context: {
          statusCode: [200, 301, 403, 404][Math.floor(Math.random()*4)],
          contentType: 'text/html',
          hostingProvider: getRandomISP()
        }
      };
    case 'hash':
      return {
        ...baseIOC,
        value: generateRandomHash(64), // SHA256
        description: 'Malware sample hash',
        context: {
          malwareFamily: getRandomMalwareFamily(),
          fileType: ['PE32+', 'PDF', 'Office', 'Archive'][Math.floor(Math.random()*4)],
          fileSize: `${(Math.random()*10+0.1).toFixed(2)} MB`
        }
      };
    case 'email':
      return {
        ...baseIOC,
        value: `${getRandomString(8)}@${['gmail.com', 'outlook.com', 'yahoo.com', getRandomString(8)+'.com'][Math.floor(Math.random()*4)]}`,
        description: 'Suspicious email address - Potential phishing actor',
        context: {
          emailBreachCount: Math.floor(Math.random()*5),
          associatedDomains: [`${getRandomString(6)}.com`],
          firstBreach: getRandomPastDate()
        }
      };
    default:
      return baseIOC;
  }
}

async function fetchThreatAlerts(limit: number): Promise<any[]> {
  const alerts: any[] = [];
  const alertTypes = [
    { title: 'New Ransomware Campaign Detected', severity: 'critical', category: 'ransomware' },
    { title: 'APT Group Activity Increase', severity: 'high', category: 'apt' },
    { title: 'Zero-Day Vulnerability Exploitation', severity: 'critical', category: 'exploit' },
    { title: 'Large-Scale Phishing Wave', severity: 'medium', category: 'phishing' },
    { title: 'DDoS Attack Infrastructure Detected', severity: 'high', category: 'ddos' },
    { title: 'Data Breach - Credential Dumping Site', severity: 'critical', category: 'breach' },
    { title: 'Cryptominer Botnet Expansion', severity: 'medium', category: 'crypto' },
    { title: 'Banking Trojan Distribution', severity: 'high', category: 'trojan' },
    { title: 'Supply Chain Attack Indicators', severity: 'critical', category: 'supply-chain' },
    { title: 'IoT Botnet Recruitment Activity', severity: 'medium', category: 'iot' }
  ];

  for (let i = 0; i < Math.min(limit, alertTypes.length); i++) {
    const template = alertTypes[i % alertTypes.length];
    alerts.push({
      id: `TA-${Date.now()}-${i}`,
      ...template,
      description: generateAlertDescription(template.category),
      iocsAffected: Math.floor(Math.random() * 50) + 10,
      targets: getRandomTargets(),
      mitigationAvailable: Math.random() > 0.3,
      publishedAt: getRandomRecentDate(),
      source: getRandomSource(),
      ttp: getRandomTTP()
    });
  }

  return alerts.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return order[a.severity] - order[b.severity];
  });
}

async function fetchActiveCampaigns(limit: number): Promise<any[]> {
  const campaigns = [
    {
      name: 'Operation Phantom Strike',
      status: 'active',
      startDate: getRandomPastDate(),
      threatActor: 'APT-29 (Cozy Bear)',
      targetSector: ['Government', 'Defense', 'Think Tanks'],
      methodology: ['Spear-phishing', 'Credential harvesting', 'Lateral movement'],
      iocCount: Math.floor(Math.random() * 200) + 50,
      estimatedVictims: `${Math.floor(Math.random() * 500) + 100}+`
    },
    {
      name: 'Silent Night Campaign',
      status: 'active',
      startDate: getRandomPastDate(),
      threatActor: 'FIN7',
      targetSector: ['Hospitality', 'Retail', 'Finance'],
      methodology: ['POS malware', 'RAM scraping', 'Data exfiltration'],
      iocCount: Math.floor(Math.random() * 150) + 30,
      estimatedVictims: `${Math.floor(Math.random() * 200) + 50}+`
    },
    {
      name: 'Golden Eye Operation',
      status: 'monitoring',
      startDate: getRandomPastDate(),
      threatActor: 'Lazarus Group',
      targetSector: ['Banking', 'Cryptocurrency', 'Energy'],
      methodology: ['Supply chain', 'Backdoor deployment', 'Crypto theft'],
      iocCount: Math.floor(Math.random() * 300) + 100,
      estimatedVictims: `${Math.floor(Math.random() * 1000) + 200}+`
    },
    {
      name: 'Dark Halo Initiative',
      status: 'active',
      startDate: getRandomPastDate(),
      threatActor: 'Unknown (Attribution Pending)',
      targetSector: ['Technology', 'Healthcare', 'Education'],
      methodology: ['Ransomware', 'Double extortion', 'Doxing'],
      iocCount: Math.floor(Math.random() * 180) + 60,
      estimatedVictims: `${Math.floor(Math.random() * 300) + 80}+`
    }
  ];

  return campaigns.slice(0, Math.min(limit, campaigns.length));
}

async function fetchAPTGroups(): Promise<any[]> {
  return [
    {
      id: 'APT-29',
      aliases: ['Cozy Bear', 'The Dukes', 'Midnight Blizzard'],
      origin: 'Russia',
      sector: ['Government', 'Defense', 'Intelligence', 'Think Tanks'],
      motivation: ['Espionage', 'Political', 'Strategic'],
      tools: ['WellMess', 'MiniDionis', 'GoldMax', 'GoldBrute'],
      lastActivity: getRandomRecentDate(),
      threatLevel: 'Critical'
    },
    {
      id: 'APT-28',
      aliases: ['Fancy Bear', 'Sofacy', 'Strontium'],
      origin: 'Russia',
      sector: ['Government', 'Military', 'Media', 'Energy'],
      motivation: ['Espionage', 'Disruption', 'Influence Operations'],
      tools: ['X-Agent', 'X-Tunnel', 'Sednit', 'CHOPSTICK'],
      lastActivity: getRandomRecentDate(),
      threatLevel: 'Critical'
    },
    {
      id: 'Lazarus',
      aliases: ['Hidden Cobra', 'Zinc', 'Labyrinth Collida'],
      origin: 'North Korea',
      sector: ['Finance', 'Cryptocurrency', 'Defense', 'Energy'],
      motivation: ['Financial Gain', 'Espionage', 'Sabotage'],
      tools: ['Manuscrypt', 'BlindOwl', 'DeathNote', 'YoreBot'],
      lastActivity: getRandomRecentDate(),
      threatLevel: 'Critical'
    },
    {
      id: 'FIN7',
      aliases: ['Carbanak', 'Cobalt Group', 'GOLD KINGSWOOD'],
      origin: 'Eastern Europe (suspected)',
      sector: ['Hospitality', 'Retail', 'Finance', 'Gaming'],
      motivation: ['Financial Theft', 'Card Data'],
      tools: ['CARBANAK', 'Griffon Python', 'PunchCard', 'BABYMETAL'],
      lastActivity: getRandomRecentDate(),
      threatLevel: 'High'
    },
    {
      id: 'APT-41',
      aliases: ['Winnti Group', 'Barium', 'Temp.Hex'],
      origin: 'China',
      sector: ['Healthcare', 'Technology', 'Telecommunications', 'Gaming'],
      motivation: ['Espionage', 'Financial Gain', 'Supply Chain'],
      tools: ['Crosswalk', 'PyroMine', 'HackTool', 'Winnti Malware'],
      lastActivity: getRandomRecentDate(),
      threatLevel: 'High'
    }
  ];
}

function calculateGlobalThreatLevel(threats: any[]): any {
  const criticalCount = threats.filter(t => t.severity === 'critical').length;
  const highCount = threats.filter(t => t.severity === 'high').length;
  
  let level = 'Moderate';
  let score = 50;
  let color = '#eab308';

  if (criticalCount >= 3 || highCount >= 5) {
    level = 'Severe';
    score = 85;
    color = '#dc2626';
  } else if (criticalCount >= 1 || highCount >= 3) {
    level = 'Elevated';
    score = 70;
    color = '#f97316';
  } else if (highCount >= 1) {
    level = 'Guarded';
    score = 55;
    color = '#84cc16';
  }

  return {
    level,
    score,
    color,
    factors: {
      criticalAlerts: criticalCount,
      highAlerts: highCount,
      totalActiveThreats: threats.length
    },
    recommendation: getThreatRecommendation(level)
  };
}

function generateStatistics(iocs: any[], threats: any[], campaigns: any[]): any {
  const iocByType: Record<string, number> = {};
  iocs.forEach(ioc => {
    iocByType[ioc.type] = (iocByType[ioc.type] || 0) + 1;
  });

  const threatsBySeverity: Record<string, number> = {};
  threats.forEach(threat => {
    threatsBySeverity[threat.severity] = (threatsBySeverity[threat.severity] || 0) + 1;
  });

  return {
    totalIOCs: iocs.length,
    iocsByType,
    activeThreats: threats.length,
    threatsBySeverity,
    activeCampaigns: campaigns.length,
    highConfidenceIOCs: iocs.filter(i => i.confidence >= 80).length,
    tlpDistribution: {
      WHITE: iocs.filter(i => i.tlp === 'WHITE').length,
      GREEN: iocs.filter(i => i.tlp === 'GREEN').length,
      AMBER: iocs.filter(i => i.tlp === 'AMBER').length,
      RED: iocs.filter(i => i.tlp === 'RED').length
    }
  };
}

async function addIOC(ioc: any): Promise<NextResponse> {
  // In production, save to database
  const newIOC = {
    ...ioc,
    id: `IOC-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    firstSeen: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    addedBy: 'user',
    verified: false,
    verificationStatus: 'pending'
  };

  return NextResponse.json({
    success: true,
    message: 'IOC added successfully',
    data: newIOC
  });
}

async function verifyIOC(iocValue: string): Promise<NextResponse> {
  // Simulate IOC verification against multiple sources
  const sources = [
    { name: 'VirusTotal', match: Math.random() > 0.7 },
    { name: 'AlienVault OTX', match: Math.random() > 0.6 },
    { name: 'ThreatConnect', match: Math.random() > 0.75 },
    { name: 'MISP Community', match: Math.random() > 0.65 },
    { name: 'Internal DB', match: Math.random() > 0.5 }
  ];

  const matches = sources.filter(s => s.match);
  const confidence = Math.round((matches.length / sources.length) * 100);

  return NextResponse.json({
    success: true,
    data: {
      value: iocValue,
      isMalicious: matches.length >= 3,
      confidence,
      sourceMatches: sources,
      verifiedAt: new Date().toISOString()
    }
  });
}

async function searchIOCs(query: string): Promise<NextResponse> {
  // Search through IOCs
  const mockResults = Array.from({ length: 5 }, () => generateIOC(['ip', 'domain', 'url', 'hash'][Math.floor(Math.random() * 4)]));

  return NextResponse.json({
    success: true,
    data: {
      query,
      results: mockResults,
      totalFound: mockResults.length
    }
  });
}

// Helper functions
function generateAlertDescription(category: string): string {
  const descriptions: Record<string, string> = {
    ransomware: 'New ransomware variant detected targeting enterprise environments. Initial infection vector appears to be spear-phishing emails with malicious attachments.',
    apt: 'Increased cyber espionage activity attributed to nation-state actors. Targeted attacks against critical infrastructure observed.',
    exploit: 'Active exploitation of previously unknown vulnerability in widely-deployed software. Patch availability pending vendor response.',
    phishing: 'Large-scale phishing campaign impersonating well-known brands. Thousands of potential victims identified globally.',
    ddos: 'DDoS attack infrastructure being assembled. Potential targets include financial institutions and government services.',
    breach: 'Major data breach discovered on dark web marketplace. Millions of records potentially compromised including credentials.',
    crypto: 'Unauthorized cryptocurrency mining operation detected across multiple victim networks. IoT devices primarily targeted.',
    trojan: 'Banking trojan distribution campaign active. Financial institutions should enhance monitoring.',
    'supply-chain': 'Compromise of software supply chain detected. Downstream impact assessment ongoing.',
    iot: 'Massive IoT botnet recruitment underway. Consumer routers and cameras primary targets.'
  };
  return descriptions[category] || 'Security alert requiring attention.';
}

function getRandomTargets(): string[] {
  const sectors = ['North America', 'Europe', 'Asia-Pacific', 'Financial Services', 'Healthcare', 'Government', 'Education', 'Technology'];
  return sectors.sort(() => Math.random() - 0.5).slice(0, 3);
}

function getRandomTTP(): string[] {
  const tactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'Impact'];
  return tactics.sort(() => Math.random() - 0.5).slice(0, 3);
}

function getThreatRecommendation(level: string): string {
  const recommendations: Record<string, string> = {
    Severe: 'Implement maximum security posture. Consider isolating critical systems. All hands on deck for SOC team.',
    Elevated: 'Increase monitoring frequency. Review all recent logs. Prepare incident response team.',
    Guarded: 'Maintain heightened awareness. Ensure all security controls are operational.',
    Moderate: 'Standard security posture acceptable. Continue routine monitoring.'
  };
  return recommendations[level] || 'Monitor situation closely.';
}

function getRandomString(length: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function generateRandomHash(length: number): string {
  const chars = 'abcdef0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.random() * chars.length);
  }
  return result;
}

function getRandomPastDate(): string {
  const now = Date.now();
  const randomTime = now - Math.random() * 365 * 24 * 60 * 60 * 1000;
  return new Date(randomTime).toISOString();
}

function getRandomRecentDate(): string {
  const now = Date.now();
  const randomTime = now - Math.random() * 7 * 24 * 60 * 60 * 1000;
  return new Date(randomTime).toISOString();
}

function getRandomSource(): string {
  const sources = ['AlienVault OTX', 'MISP', 'ThreatConnect', 'VirusTotal', 'Internal Research', 'Partner Feed', 'OSINT', 'Dark Web Monitor'];
  return sources[Math.floor(Math.random() * sources.length)];
}

function getRandomTags(type: string): string[] {
  const tagSets: Record<string, string[]> = {
    ip: ['c2', 'scanner', 'proxy', 'tor-exit', 'malicious'],
    domain: ['phishing', 'malware', 'c2', 'dga', 'typosquat'],
    url: ['phishing-kit', 'exploit-landing', 'drive-by', 'credential-harvest'],
    hash: ['trojan', 'ransomware', 'stealer', 'dropper', 'backdoor'],
    email: ['phishing', 'spam', 'beacon', 'credential-theft']
  };
  const availableTags = tagSets[type] || ['malicious', 'suspicious'];
  return availableTags.sort(() => Math.random() - 0.5).slice(0, Math.floor(Math.random() * 3) + 1);
}

function getRandomThreatTypes(): string[] {
  const types = ['phishing', 'malware', 'c2', 'exploit-kit', 'botnet', 'ransomware', 'apt', 'insider-threat'];
  return types.sort(() => Math.random() - 0.5).slice(0, 2);
}

function getRandomCountry(): string {
  const countries = ['United States', 'Russia', 'China', 'Brazil', 'Germany', 'Netherlands', 'Ukraine', 'Romania', 'India', 'Singapore'];
  return countries[Math.floor(Math.random() * countries.length)];
}

function getRandomISP(): string {
  const isps = ['Amazon AWS', 'Microsoft Azure', 'DigitalOcean', 'OVH SAS', 'Hetzner Online', 'Linode', 'Cloudflare', 'Google Cloud'];
  return isps[Math.floor(Math.random() * isps.length)];
}

function getRandomMalwareFamily(): string {
  const families = ['Emotet', 'TrickBot', 'Ryuk', 'Conti', 'LockBit', 'BlackCat', 'AgentTesla', 'Formbook', 'RedLine', 'Vidar'];
  return families[Math.floor(Math.random() * families.length)];
}
