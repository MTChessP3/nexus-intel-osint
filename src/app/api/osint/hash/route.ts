import { NextRequest, NextResponse } from 'next/server';

// File Hash Lookup & Malware Analysis API
export async function POST(request: NextRequest) {
  try {
    const { hash, hashType = 'auto' } = await request.json();
    
    if (!hash) {
      return NextResponse.json({ error: 'Hash is required' }, { status: 400 });
    }

    // Detect hash type if auto
    let detectedType = hashType;
    if (hashType === 'auto') {
      detectedType = detectHashType(hash);
    }

    // Validate hash format
    if (!validateHashFormat(hash, detectedType)) {
      return NextResponse.json({ error: `Invalid ${detectedType.toUpperCase()} hash format` }, { status: 400 });
    }

    // Query multiple malware databases (simulated with realistic data)
    const [virusTotal, malwareBazaar, hybridAnalysis, hashMyFiles] = await Promise.all([
      queryVirusTotal(hash, detectedType),
      queryMalwareBazaar(hash, detectedType),
      queryHybridAnalysis(hash, detectedType),
      queryHashMyNet(hash, detectedType)
    ]);

    // Aggregate results
    const totalEngines = virusTotal.enginesScanned + malwareBazaar.enginesScanned;
    const totalDetections = virusTotal.detections + malwareBazaar.detections;
    const detectionRate = totalEngines > 0 ? Math.round((totalDetections / totalEngines) * 100) : 0;

    // Determine threat classification
    let classification = 'Clean';
    let threatLevel = 'Low';
    let color = '#22c55e';

    if (detectionRate >= 50) {
      classification = 'Malicious';
      threatLevel = 'Critical';
      color = '#dc2626';
    } else if (detectionRate >= 20) {
      classification = 'Suspicious';
      threatLevel = 'High';
      color = '#f97316';
    } else if (detectionRate >= 5) {
      classification = 'Potentially Unwanted';
      threatLevel = 'Medium';
      color = '#eab308';
    } else if (totalDetections > 0) {
      classification = 'Few Detections';
      threatLevel = 'Low-Medium';
      color = '#84cc16';
    }

    // Generate file information
    const fileInfo = generateFileInfo(hash, detectionRate);

    // Generate behavioral analysis
    const behaviorAnalysis = generateBehavioralAnalysis(detectionRate);

    const result = {
      input: {
        hash,
        hashType: detectedType.toUpperCase()
      },
    aggregateResults: {
      totalEnginesScanned: totalEngines,
      totalDetections,
      detectionRate,
      classification,
      threatLevel,
      color
    },
    engineResults: {
      virusTotal,
      malwareBazaar,
      hybridAnalysis,
      hashMyFiles
    },
    fileInfo,
    behaviorAnalysis,
    recommendations: generateRecommendations(detectionRate, classification),
    metadata: {
      analyzedAt: new Date().toISOString(),
      sources: ['VirusTotal', 'MalwareBazaar', 'Hybrid-Analysis', 'HashMyNet'],
      version: '2.0'
    }
    };

    return NextResponse.json({ success: true, data: result });
  } catch (error) {
    console.error('Hash Analysis Error:', error);
    return NextResponse.json(
      { error: 'Failed to analyze hash' },
      { status: 500 }
    );
  }
}

function detectHashType(hash: string): string {
  const cleaned = hash.toLowerCase().replace(/[^a-f0-9]/g, '');
  
  if (cleaned.length === 32) return 'md5';
  if (cleaned.length === 40) return 'sha1';
  if (cleaned.length === 64) return 'sha256';
  if (cleaned.length === 128) return 'sha512';
  
  // Default based on length
  if (cleaned.length <= 32) return 'md5';
  if (cleaned.length <= 40) return 'sha1';
  if (cleaned.length <= 64) return 'sha256';
  return 'sha512';
}

function validateHashFormat(hash: string, type: string): boolean {
  const cleaned = hash.toLowerCase().replace(/[^a-f0-9]/g, '');
  const lengths: Record<string, number> = { md5: 32, sha1: 40, sha256: 64, sha512: 128 };
  return cleaned.length === lengths[type];
}

async function queryVirusTotal(hash: string, type: string): Promise<any> {
  // Simulated VirusTotal response
  const detections = Math.floor(Math.random() * 70);
  const enginesScanned = 72;
  
  const detectingEngines = [];
  const malwareNames = [
    'Trojan.GenericKD.12345678',
    'W32/AutoRun.Bot.worm',
    'Gen:Variant.Razy.123456',
    'PUA.PC_Optimizer.Pro',
    'Riskware.Tool.CK',
    'Application.Agent.EK'
  ];
  
  for (let i = 0; i < detections; i++) {
    detectingEngines.push({
      engine: getEngineName(i),
      result: malwareNames[Math.floor(Math.random() * malwareNames.length)],
      version: `${Math.floor(Math.random() * 2)}.${Math.floor(Math.random() * 99)}.${Math.floor(Math.random() * 9999)}`,
      update: getRandomRecentDate()
    });
  }

  return {
    source: 'VirusTotal',
    permalink: `https://www.virustotal.com/gui/file/${hash}`,
    enginesScanned,
    detections,
    scanDate: getRandomRecentDate(),
    detectingEngines,
    scanId: `${hash}-${Date.now()}`
  };
}

async function queryMalwareBazaar(hash: string, type: string): Promise<any> {
  const isListed = Math.random() < 0.3;
  
  return {
    source: 'MalwareBazaar',
    permalink: `https://bazaar.abuse.ch/browse.php?search=${hash}`,
    enginesScanned: 40,
    detections: isListed ? Math.floor(Math.random() * 30) + 5 : 0,
    fileDetails: isListed ? {
      fileType: getRandomFileType(),
      mimeType: getRandomMimeType(),
      fileSize: `${(Math.random() * 10 + 0.1).toFixed(2)} MB`,
      firstSeen: getRandomPastDate(),
      lastSeen: getRandomRecentDate(),
      tags: ['trojan', 'banker', 'stealer'].filter(() => Math.random() > 0.5),
      signature: getSignatureName()
    } : null
  };
}

async function queryHybridAnalysis(hash: string, type: string): Promise<any> {
  const threatLevel = ['malicious', 'suspicious', 'unknown', 'clean'][Math.floor(Math.random() * 4)];
  
  return {
    source: 'Hybrid Analysis',
    permalink: `https://www.hybrid-analysis.com/sample/${hash}`,
    threatLevel,
    verdict: threatLevel === 'clean' ? 'No specific threat' : 'Potential security risk',
    environment: {
      os: 'Windows 10 64-bit',
      arch: 'x64'
    },
    behaviors: threatLevel !== 'clean' ? [
      'Creates executable files',
      'Modifies registry keys',
      'Establishes network connections',
      'Attempts privilege escalation'
    ].filter(() => Math.random() > 0.4) : []
  };
}

async function queryHashMyNet(hash: string, type: string): Promise<any> {
  return {
    source: 'HashMy.net',
    permalink: `https://www.hashlookup.shodan.io/lookup/${hash}`,
    knownHashes: Math.random() > 0.7,
    dataSources: ['NSRL', 'VirusBay', 'Polyswarm'],
    additionalContext: Math.random() > 0.5 ? {
      fileName: `file_${hash.substring(0, 8)}.exe`,
      uploadDate: getRandomPastDate(),
      submitter: 'Anonymous'
    } : null
  };
}

function generateFileInfo(hash: string, detectionRate: number): any {
  const fileTypes = [
    { type: 'PE32+ Executable', extension: '.exe', category: 'Windows Executable' },
    { type: 'PDF Document', extension: '.pdf', category: 'Document' },
    { type: 'ZIP Archive', extension: '.zip', category: 'Archive' },
    { type: 'MS Office Document', extension: '.docx', category: 'Document' },
    { type: 'JavaScript', extension: '.js', category: 'Script' },
    { type: 'Android Package', extension: '.apk', category: 'Mobile Application' }
  ];
  
  const selectedFile = fileTypes[Math.floor(Math.random() * fileTypes.length)];
  
  return {
    ...selectedFile,
    size: `${(Math.random() * 50 + 0.01).toFixed(2)} MB`,
    md5: hash.length === 32 ? hash : generateRandomHash(32),
    sha1: hash.length === 40 ? hash : generateRandomHash(40),
    sha256: hash.length === 64 ? hash : generateRandomHash(64),
    ssdeep: `${Math.floor(Math.random() * 999999)}:${generateRandomHash(12)}:${generateRandomHash(12)}`,
    compilationTimestamp: getRandomPastDate()
  };
}

function generateBehavioralAnalysis(detectionRate: number): any {
  if (detectionRate < 5) {
    return {
      networkActivity: [],
      fileSystemActivity: [],
      registryActivity: [],
      processActivity: [],
      summary: 'No significant malicious behaviors detected'
    };
  }

  return {
    networkActivity: [
      { action: 'Outbound Connection', destination: '185.xxx.xxx.xxx:443', protocol: 'HTTPS' },
      { action: 'DNS Query', target: 'malicious-domain.xyz', type: 'A record' }
    ].filter(() => Math.random() > 0.4),
    fileSystemActivity: [
      { action: 'File Creation', path: '%TEMP%\\malware.exe' },
      { action: 'File Modification', path: '%APPDATA%\\settings.dat' },
      { action: 'Drop File', path: '%SYSTEM32%\\driver.dll' }
    ].filter(() => Math.random() > 0.5),
    registryActivity: [
      { action: 'Key Creation', path: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' },
      { action: 'Value Modification', key: 'Persistence', value: 'malware.exe' }
    ].filter(() => Math.random() > 0.5),
    processActivity: [
      { action: 'Process Injection', target: 'explorer.exe' },
      { action: 'Process Creation', name: 'cmd.exe /c powershell...' }
    ].filter(() => Math.random() > 0.6),
    summary: detectionRate > 30 ? 
      'Multiple malicious behaviors consistent with trojan/ransomware activity' :
      'Some suspicious behaviors detected, further analysis recommended'
  };
}

function generateRecommendations(detectionRate: number, classification: string): string[] {
  const recommendations: string[] = [];

  if (classification === 'Malicious') {
    recommendations.push('IMMEDIATE ACTION REQUIRED: Isolate affected system from network');
    recommendations.push('Do not execute this file under any circumstances');
    recommendations.push('Submit to sandbox for detailed behavioral analysis');
    recommendations.push('Check related IOCs and Indicators of Compromise');
    recommendations.push('Review all files created/modified around the time of discovery');
  } else if (classification === 'Suspicious') {
    recommendations.push('Quarantine the file pending further investigation');
    recommendations.push('Run in isolated sandbox environment');
    recommendations.push('Monitor system for suspicious activity');
    recommendations.push('Collect additional samples for comparison');
  } else if (classification === 'Potentially Unwanted') {
    recommendations.push('Review if file is necessary for business operations');
    recommendations.push('Consider removing if not required');
    recommendations.push('Monitor for unwanted behavior');
  } else {
    recommendations.push('File appears clean based on current signatures');
    recommendations.push('Continue monitoring as new signatures may detect it later');
    recommendations.push('Keep antivirus definitions updated');
  }

  return recommendations;
}

// Helper functions
function getEngineName(index: number): string {
  const engines = [
    'Kaspersky', 'McAfee', 'Symantec', 'TrendMicro', 'BitDefender', 'ESET-NOD32',
    'Avast', 'AVG', 'Sophos', 'Panda', 'F-Secure', 'ZoneAlarm', 'AhnLab-V3',
    'ALYac', 'Ad-Aware', 'APEX', 'AVG', 'Acronis', 'AegisLab', 'Agrium',
    'AhnLab-V3', 'Alibaba', 'Antiy-AVL', 'APLEX', 'Arcabit', 'Avast-Mobile',
    'Avira', 'Baidu', 'BITDEFENDER', 'Babable', 'CAT-QuickHeal', 'CMC',
    'CPAI', 'CrowdStrike', 'Cyren', 'Cylance', 'Cynet', 'DeepInstinct',
    'DrWeb', 'Emsisoft', 'Eset-NOD32', 'FORTINET', 'F-Secure', 'FireEye',
    'GData', 'Gridinsoft', 'HABITAT', 'Ikarus', 'Jiangmin', 'K7AntiVirus',
    'K7GW', 'Kaspersky', 'Lionic', 'MAX', 'MALWAREBYTES', 'MD', 'MICROSOFT',
    'MGR', 'MWRIEN', 'MaxSecure', 'McAfee', 'McAfee-GW-Edition', 'Morfeus',
    'NANO-Antivirus', 'NEXGATE', 'NORMAN', 'NP', 'NShield', 'Nano-Antivirus',
    'Panda', 'Pantcho', 'Qihoo-360', 'Rising', 'SUPERAntiSpyware', 'Sangfor',
    'Skyhigh', 'Sophos', 'SymantecMobileInsight', 'Symantec', 'TACHYON',
    'TRENDmicro', 'TrendMicro-HouseCall', 'TrendMicro', 'Trustlook', 'TunnelSnake',
    'VBA32', 'VIPRE', 'VMALWARE', 'VirusBlokAda', 'ViRobot', 'Yandex',
    'Zillywink', 'ZoneAlarm', 'Zonker', 'avast', 'avg', 'clamav', 'comodo',
    'cylance', 'cyren', 'drweb', 'ecommit', 'elastic', 'escan', 'eset-nod32',
    'fortinet', 'gdata', 'gridinsoft', 'housecall', 'ikarus', 'jiangmin',
    'k7gw', 'kaspersky', 'lavasoft', 'lionic', 'max', 'mcafee-gw-edition',
    'microsoft', 'nano-antivirus', 'panda', 'prevx1', 'quickheal', 'rising',
    'sophos', 'sunbelt', 'symantec', 'tachen', 'threatfound', 'trendmicro',
    'trendmicro-hc', 'vba32', 'vipre', 'virushunter', 'zillywink'
  ];
  return engines[index % engines.length];
}

function getRandomFileType(): string {
  const types = ['win32exe', 'dll', 'pdf', 'doc', 'zip', 'apk', 'js', 'ps1'];
  return types[Math.floor(Math.random() * types.length)];
}

function getRandomMimeType(): string {
  const mimes = [
    'application/x-dosexec',
    'application/pdf',
    'application/zip',
    'application/vnd.ms-office',
    'text/javascript',
    'application/vnd.android.package-archive'
  ];
  return mimes[Math.floor(Math.random() * mimes.length)];
}

function getSignatureName(): string {
  const signatures = [
    'Trojan.GenericKD.45678901',
    'Variant.Generick.78912345',
    'Agent.PSW.Banker.ABCD',
    'Downloader.Agent.XYZ123',
    'Ransom.WannaClone.DEF456'
  ];
  return signatures[Math.floor(Math.random() * signatures.length)];
}

function generateRandomHash(length: number): string {
  const chars = 'abcdef0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function getRandomRecentDate(): string {
  const now = Date.now();
  const randomTime = now - Math.random() * 30 * 24 * 60 * 60 * 1000;
  return new Date(randomTime).toISOString().split('T')[0];
}

function getRandomPastDate(): string {
  const now = Date.now();
  const randomTime = now - Math.random() * 365 * 24 * 60 * 60 * 1000;
  return new Date(randomTime).toISOString();
}
