// In-memory data store for Vercel serverless compatibility
// This replaces Prisma/SQLite which doesn't work on Vercel

export interface IOC {
  id: string;
  type: string;
  value: string;
  description: string;
  severity: string;
  confidence: number;
  status: string;
  source: string;
  tags: string[];
  firstSeen: string;
  lastUpdated: string;
  rawResponse?: string;
}

export interface Analysis {
  id: string;
  iocId: string;
  source: string;
  sourceType: string;
  rawData: string;
  summary?: string;
  findings: string[];
  verified: boolean;
  timestamp: string;
}

export interface Alert {
  id: string;
  iocId?: string;
  title: string;
  description: string;
  severity: string;
  type: string;
  status: string;
  createdAt: string;
}

// In-memory storage
let iocs: IOC[] = [];
let analyses: Analysis[] = [];
let alerts: Alert[] = [];

// Initialize with sample IOCs for demo
const sampleIOCs: IOC[] = [
  {
    id: 'ioc-001',
    type: 'IP',
    value: '185.220.101.34',
    description: 'Known Tor exit node - Berlin, Germany',
    severity: 'MEDIUM',
    confidence: 92,
    status: 'SUSPICIOUS',
    source: 'ip-api.com',
    tags: ['tor', 'exit-node', 'proxy'],
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString()
  },
  {
    id: 'ioc-002',
    type: 'DOMAIN',
    value: 'evil.com',
    description: 'Known malicious domain - phishing infrastructure',
    severity: 'HIGH',
    confidence: 95,
    status: 'MALICIOUS',
    source: 'ThreatIntel',
    tags: ['phishing', 'malware', 'c2'],
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString()
  },
  {
    id: 'ioc-003',
    type: 'HASH',
    value: '44d88612fea8a8f36de82e1278abb02f',
    description: 'MD5 test hash - EICAR test file',
    severity: 'LOW',
    confidence: 100,
    status: 'BENIGN',
    source: 'VirusTotal',
    tags: ['test', 'eicar'],
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString()
  },
  {
    id: 'ioc-004',
    type: 'CVE',
    value: 'CVE-2024-3400',
    description: 'PAN-OS Command Injection Vulnerability - Critical RCE in GlobalProtect',
    severity: 'CRITICAL',
    confidence: 98,
    status: 'MALICIOUS',
    source: 'NIST-NVD',
    tags: ['rce', 'palo-alto', 'vpn', 'critical'],
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString()
  },
  {
    id: 'ioc-005',
    type: 'URL',
    value: 'https://phishing-bank.com/login',
    description: 'Active phishing site targeting bank customers',
    severity: 'CRITICAL',
    confidence: 99,
    status: 'MALICIOUS',
    source: 'PhishTank',
    tags: ['phishing', 'banking', 'credential-theft'],
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString()
  }
];

// Initialize store
if (iocs.length === 0) {
  iocs = [...sampleIOCs];
  
  // Add some sample alerts
  alerts = [
    {
      id: 'alert-001',
      iocId: 'ioc-004',
      title: 'Critical CVE Detected: CVE-2024-3400',
      description: 'PAN-OS Command Injection vulnerability being actively exploited',
      severity: 'CRITICAL',
      type: 'VULNERABILITY_FOUND',
      status: 'ACTIVE',
      createdAt: new Date(Date.now() - 3600000).toISOString()
    },
    {
      id: 'alert-002',
      iocId: 'ioc-005',
      title: 'Active Phishing Campaign',
      description: 'New phishing site detected targeting financial sector',
      severity: 'CRITICAL',
      type: 'IOC_DETECTED',
      status: 'ACTIVE',
      createdAt: new Date(Date.now() - 7200000).toISOString()
    },
    {
      id: 'alert-003',
      title: 'Threat Intelligence Update',
      description: 'New IOCs added from threat feed analysis',
      severity: 'HIGH',
      type: 'THREAT_FEED_MATCH',
      status: 'ACTIVE',
      createdAt: new Date(Date.now() - 10800000).toISOString()
    }
  ];
}

// Generate unique ID
export function generateId(prefix: string = 'id'): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// IOC Operations
export async function getIOCs(filters?: {
  type?: string;
  status?: string;
  severity?: string;
  search?: string;
  page?: number;
  limit?: number;
}): Promise<{ data: IOC[]; total: number; page: number; limit: number; totalPages: number }> {
  let filtered = [...iocs];
  
  if (filters?.type) {
    filtered = filtered.filter(i => i.type === filters.type.toUpperCase());
  }
  if (filters?.status) {
    filtered = filtered.filter(i => i.status === filters.status.toUpperCase());
  }
  if (filters?.severity) {
    filtered = filtered.filter(i => i.severity === filters.severity.toUpperCase());
  }
  if (filters?.search) {
    const searchLower = filters.search.toLowerCase();
    filtered = filtered.filter(i => 
      i.value.toLowerCase().includes(searchLower) ||
      (i.description && i.description.toLowerCase().includes(searchLower)) ||
      (i.source && i.source.toLowerCase().includes(searchLower))
    );
  }
  
  const page = filters?.page || 1;
  const limit = filters?.limit || 50;
  const total = filtered.length;
  const totalPages = Math.ceil(total / limit);
  const start = (page - 1) * limit;
  
  return {
    data: filtered.slice(start, start + limit),
    total,
    page,
    limit,
    totalPages
  };
}

export async function getIOCById(id: string): Promise<IOC | null> {
  return iocs.find(i => i.id === id) || null;
}

export async function getIOCByValue(value: string): Promise<IOC | null> {
  return iocs.find(i => i.value === value) || null;
}

export async function createIOC(data: {
  type: string;
  value: string;
  description?: string;
  severity?: string;
  confidence?: number;
  source?: string;
  tags?: string[];
}): Promise<IOC> {
  // Check if exists
  const existing = iocs.find(i => i.value === data.value);
  if (existing) {
    throw new Error('IOC already exists');
  }
  
  const newIOC: IOC = {
    id: generateId('ioc'),
    type: data.type.toUpperCase(),
    value: data.value,
    description: data.description || `${data.type}: ${data.value}`,
    severity: (data.severity || 'MEDIUM').toUpperCase(),
    confidence: data.confidence || 50,
    status: 'UNKNOWN',
    source: data.source || 'manual',
    tags: data.tags || [],
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString()
  };
  
  iocs.unshift(newIOC);
  
  // Create alert for new IOC
  await createAlert({
    iocId: newIOC.id,
    title: `New ${data.type} Added: ${data.value}`,
    description: data.description || `Manually added indicator of compromise`,
    severity: (data.severity || 'MEDIUM').toUpperCase(),
    type: 'IOC_DETECTED'
  });
  
  return newIOC;
}

export async function updateIOC(id: string, data: {
  description?: string;
  severity?: string;
  status?: string;
  confidence?: number;
  tags?: string[];
}): Promise<IOC | null> {
  const index = iocs.findIndex(i => i.id === id);
  if (index === -1) return null;
  
  iocs[index] = {
    ...iocs[index],
    ...data,
    lastUpdated: new Date().toISOString()
  };
  
  return iocs[index];
}

export async function deleteIOC(id: string): Promise<boolean> {
  const index = iocs.findIndex(i => i.id === id);
  if (index === -1) return false;
  
  iocs.splice(index, 1);
  // Also clean up related records
  analyses = analyses.filter(a => a.iocId !== id);
  alerts = alerts.filter(a => a.iocId !== id);
  
  return true;
}

export async function upsertIOC(data: {
  type: string;
  value: string;
  description?: string;
  severity?: string;
  confidence?: number;
  status?: string;
  source?: string;
  rawResponse?: string;
  tags?: string[];
}): Promise<IOC> {
  const existing = iocs.find(i => i.value === data.value);
  
  if (existing) {
    const index = iocs.indexOf(existing);
    iocs[index] = {
      ...existing,
      ...(data.description && { description: data.description }),
      ...(data.severity && { severity: data.severity }),
      ...(data.confidence && { confidence: data.confidence }),
      ...(data.status && { status: data.status }),
      ...(data.source && { source: data.source }),
      ...(data.rawResponse && { rawResponse: data.rawResponse }),
      ...(data.tags && { tags: data.tags }),
      lastUpdated: new Date().toISOString()
    };
    return iocs[index];
  } else {
    return createIOC(data);
  }
}

// Analysis Operations
export async function createAnalysis(data: {
  iocId: string;
  source: string;
  sourceType: string;
  rawData: string;
  summary?: string;
  findings?: string[];
  verified?: boolean;
}): Promise<Analysis> {
  const newAnalysis: Analysis = {
    id: generateId('analysis'),
    ...data,
    findings: data.findings || [],
    verified: data.verified || false,
    timestamp: new Date().toISOString()
  };
  
  analyses.unshift(newAnalysis);
  return newAnalysis;
}

export async function getAnalysesByIOC(iocId: string): Promise<Analysis[]> {
  return analyses.filter(a => a.iocId === iocId).slice(0, 3);
}

// Alert Operations
export async function createAlert(data: {
  iocId?: string;
  title: string;
  description: string;
  severity: string;
  type: string;
}): Promise<Alert> {
  const newAlert: Alert = {
    id: generateId('alert'),
    ...data,
    status: 'ACTIVE',
    createdAt: new Date().toISOString()
  };
  
  alerts.unshift(newAlert);
  return newAlert;
}

export async function getAlerts(options?: { iocId?: string; status?: string }): Promise<Alert[]> {
  let filtered = [...alerts];
  
  if (options?.iocId) {
    filtered = filtered.filter(a => a.iocId === options.iocId);
  }
  if (options?.status) {
    filtered = filtered.filter(a => a.status === options.status);
  }
  
  return filtered.slice(0, 5);
}

// Stats
export function getStoreStats() {
  return {
    totalIOCs: iocs.length,
    totalAnalyses: analyses.length,
    totalAlerts: alerts.filter(a => a.status === 'ACTIVE').length,
    severityBreakdown: {
      CRITICAL: iocs.filter(i => i.severity === 'CRITICAL').length,
      HIGH: iocs.filter(i => i.severity === 'HIGH').length,
      MEDIUM: iocs.filter(i => i.severity === 'MEDIUM').length,
      LOW: iocs.filter(i => i.severity === 'LOW').length,
      INFO: iocs.filter(i => i.severity === 'INFO').length
    },
    typeBreakdown: {
      IP: iocs.filter(i => i.type === 'IP').length,
      DOMAIN: iocs.filter(i => i.type === 'DOMAIN').length,
      URL: iocs.filter(i => i.type === 'URL').length,
      HASH: iocs.filter(i => i.type === 'HASH').length,
      CVE: iocs.filter(i => i.type === 'CVE').length,
      EMAIL: iocs.filter(i => i.type === 'EMAIL').length
    }
  };
}
