'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { 
  Search, Globe, Shield, Bug, FileText, Download, Upload, 
  Trash2, Edit3, Plus, Eye, AlertTriangle, CheckCircle, XCircle,
  Activity, Database, Cpu, Lock, Unlock, RefreshCw, ExternalLink,
  Copy, Filter, ChevronDown, ChevronRight, Zap, Target, Radar,
  Fingerprint, Mail, Hash, Server, Clock, MapPin, Wifi,
  BarChart3, PieChart as PieChartIcon, TrendingUp, Users, Key, Terminal,
  Save, X, Loader2, Check, Info, AlertCircle, ArrowRight, Ban, WifiOff,
  Play, Pause, Camera, FileSearch, Smartphone, Globe2, Skull, EyeOff,
  FolderOpen, DownloadCloud, UploadCloud, FileCode, LockOpen, ShieldAlert,
  Network, MessageSquare, ShieldUser, Radio, Presentation
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
  LineChart, Line
} from 'recharts';

// ==================== TYPES ====================
type TabType = 'dashboard' | 'ip' | 'domain' | 'url' | 'hash' | 'cve' | 'ai' | 'darkweb' | 'threats' | 'mobile' | 'forensics' | 'iocs' | 'export' | 'reports' | 'sources' | 'brand' | 'sandbox' | 'dnsdump' | 'social' | 'exec' | 'fakeapp';
type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
type IOCStatus = 'UNKNOWN' | 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';

interface IOC {
  id: string;
  type: string;
  value: string;
  description: string;
  severity: Severity;
  confidence: number;
  status: IOCStatus;
  source: string;
  tags: string[];
  firstSeen: string;
  lastUpdated: string;
}

interface TimelineEvent {
  time: string;
  event: string;
  type: 'threat' | 'ioc' | 'analysis' | 'system' | 'alert';
  severity?: Severity;
}

interface APIResponse {
  success: boolean;
  source?: string;
  timestamp?: string;
  fetchedLive?: boolean;
  data?: any;
  error?: string;
  details?: string;
  message?: string;
  [key: string]: any;
}

// ==================== CONSTANTS ====================
const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  INFO: '#3b82f6'
};

const STATUS_COLORS: Record<IOCStatus, string> = {
  UNKNOWN: '#6b7280',
  BENIGN: '#22c55e',
  SUSPICIOUS: '#f97316',
  MALICIOUS: '#dc2626'
};

const CHART_COLORS = ['#dc2626', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899'];

// Live Threat Timeline Data Generator
const generateTimelineData = (): TimelineEvent[] => {
  const events: TimelineEvent[] = [];
  const now = new Date();
  
  const threatTypes = [
    { event: 'New malware sample detected in wild', type: 'threat' as const, severity: 'HIGH' as Severity },
    { event: 'Suspicious IP address flagged by sensors', type: 'ioc' as const, severity: 'MEDIUM' as Severity },
    { event: 'Domain resolution change detected', type: 'analysis' as const, severity: 'LOW' as Severity },
    { event: 'Threat feed update received (CISA)', type: 'system' as const },
    { event: 'Critical CVE published to NVD', type: 'alert' as const, severity: 'CRITICAL' as Severity },
    { event: 'Phishing campaign targeting finance sector', type: 'threat' as const, severity: 'HIGH' as Severity },
    { event: 'IOC added to watchlist', type: 'ioc' as const, severity: 'MEDIUM' as Severity },
    { event: 'Dark web marketplace activity spike', type: 'threat' as const, severity: 'HIGH' as Severity },
    { event: 'SSL certificate expiration warning', type: 'alert' as const, severity: 'LOW' as Severity },
    { event: 'Botnet C2 communication detected', type: 'threat' as const, severity: 'CRITICAL' as Severity },
    { event: 'Data breach notification received', type: 'alert' as const, severity: 'CRITICAL' as Severity },
    { event: 'Zero-day exploit being traded', type: 'threat' as const, severity: 'CRITICAL' as Severity }
  ];
  
  for (let i = 0; i < 20; i++) {
    const timeOffset = Math.floor(Math.random() * 60);
    const threat = threatTypes[Math.floor(Math.random() * threatTypes.length)];
    events.push({
      time: new Date(now.getTime() - timeOffset * 60000).toLocaleTimeString(),
      ...threat
    });
  }
  
  return events.sort((a, b) => new Date(`2000/01/01 ${b.time}`).getTime() - new Date(`2000/01/01 ${a.time}`).getTime());
};

// ==================== MAIN COMPONENT ====================
export default function OSINTPlatform() {
  // Core State
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [loading, setLoading] = useState(false);
  const [apiData, setApiData] = useState<APIResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [selectedIOC, setSelectedIOC] = useState<IOC | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [modalType, setModalType] = useState<'detail' | 'edit' | 'add'>('detail');
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);
  
  // Input State
  const [inputValue, setInputValue] = useState('');
  const [formData, setFormData] = useState({
    type: 'IP',
    value: '',
    description: '',
    severity: 'MEDIUM',
    status: 'UNKNOWN',
    tags: [] as string[]
  });
  
  // Timeline State
  const [timelineData, setTimelineData] = useState<TimelineEvent[]>(generateTimelineData());
  const [timelineRunning, setTimelineRunning] = useState(true);
  const timelineInterval = useRef<NodeJS.Timeout | null>(null);
  
  // Report Config State
  const [reportConfig, setReportConfig] = useState({
    title: '',
    modules: [] as string[],
    format: 'PDF',
    includeIOCs: true,
    includeThreats: true,
    includeTimeline: true,
    executiveSummary: true,
    recommendations: true
  });

  // New source form state
  const [newSource, setNewSource] = useState({
    name: '',
    type: 'CUSTOM',
    method: 'GET',
    endpoint: '',
    apiKeyEnv: '',
    description: ''
  });
  
  // Forensics Results
  const [forensicsHistory, setForensicsHistory] = useState<any[]>([]);
  const [selectedForensics, setSelectedForensics] = useState<any>(null);

  // Generated Reports History
  const [reports, setReports] = useState<any[]>([]);

  // Intelligence Sources
  const [sources, setSources] = useState<any[]>([]);
  const [sourceHealth, setSourceHealth] = useState<any[]>([]);

  // Initialize and load data
  useEffect(() => {
    loadIOCs();
    loadForensicsHistory();
  }, []);

  // Timeline auto-refresh
  useEffect(() => {
    if (timelineRunning) {
      timelineInterval.current = setInterval(() => {
        setTimelineData(prev => {
          const newEvent: TimelineEvent = {
            time: new Date().toLocaleTimeString(),
            event: [
              'Threat intelligence feed updated',
              'New IOC detected by automated systems',
              'Network anomaly flagged for review',
              'Security scan completed',
              'Threat actor activity monitored'
            ][Math.floor(Math.random() * 5)],
            type: ['threat', 'ioc', 'analysis', 'system'][Math.floor(Math.random() * 4)] as any
          };
          return [newEvent, ...prev.slice(0, 49)];
        });
      }, 5000);
    } else if (timelineInterval.current) {
      clearInterval(timelineInterval.current);
    }
    
    return () => {
      if (timelineInterval.current) {
        clearInterval(timelineInterval.current);
      }
    };
  }, [timelineRunning]);

  // Clear feedback after delay
  useEffect(() => {
    if (actionFeedback) {
      const timer = setTimeout(() => setActionFeedback(null), 4000);
      return () => clearTimeout(timer);
    }
  }, [actionFeedback]);

  // Load IOCs on tab change
  useEffect(() => {
    if (['iocs', 'dashboard', 'export', 'reports'].includes(activeTab)) {
      loadIOCs();
    }
    if (activeTab === 'reports') loadReports();
    if (activeTab === 'sources') loadSources();
  }, [activeTab]);

  // ==================== API FUNCTIONS ====================
  const showFeedback = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
    setActionFeedback(`${type.toUpperCase()}: ${message}`);
  };

  const callAPI = async (endpoint: string, options?: RequestInit): Promise<APIResponse> => {
    setLoading(true);
    setError(null);
    showFeedback('Connecting to API...', 'info');
    
    try {
      const response = await fetch(endpoint, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...options?.headers
        }
      });
      
      const data = await response.json();
      setApiData(data);
      
      if (!data.success) {
        setError(data.error || data.details || data.message || 'Unknown error');
        showFeedback(`Error: ${data.error || data.message || 'API returned error'}`, 'error');
      } else {
        showFeedback(`Success! Data from ${data.source || 'API'}`, 'success');
        
        if (options?.method === 'POST' || options?.method === 'DELETE' || options?.method === 'PATCH') {
          setTimeout(() => loadIOCs(), 500);
        }
      }
      
      return data;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Network error';
      setError(errorMsg);
      showFeedback(`Network Error: ${errorMsg}`, 'error');
      return { success: false, error: errorMsg };
    } finally {
      setLoading(false);
    }
  };

  const loadIOCs = async () => {
    try {
      const params = new URLSearchParams();
      if (searchQuery) params.set('search', searchQuery);
      
      const response = await fetch(`/api/osint/iocs?${params}`);
      const result = await response.json();
      
      if (result.success) {
        setIocs(result.data || []);
      }
    } catch (err) {
      console.error('Load IOCs error:', err);
    }
  };

  const loadForensicsHistory = async () => {
    try {
      const response = await fetch('/api/osint/forensics?action=list');
      const result = await response.json();
      if (result.success) {
        setForensicsHistory(result.data || []);
      }
    } catch (err) {
      console.error('Load forensics history error:', err);
    }
  };

  // ==================== HANDLER FUNCTIONS ====================
  
  // IP Intelligence Handler
  const handleIPRecon = async () => {
    if (!inputValue) {
      showFeedback('Enter an IP address', 'error');
      return;
    }
    showFeedback(`Analyzing IP: ${inputValue}...`, 'info');
    await callAPI(`/api/osint/ip?ip=${encodeURIComponent(inputValue)}`);
  };

  // Domain Analysis Handler
  const handleDomainRecon = async () => {
    if (!inputValue) {
      showFeedback('Enter a domain', 'error');
      return;
    }
    showFeedback(`Resolving domain: ${inputValue}...`, 'info');
    await callAPI(`/api/osint/domain?domain=${encodeURIComponent(inputValue)}`);
  };

  // URL Scanner Handler
  const handleURLAnalysis = async () => {
    if (!inputValue) {
      showFeedback('Enter a URL', 'error');
      return;
    }
    showFeedback(`Scanning URL: ${inputValue}...`, 'info');
    await callAPI(`/api/osint/url?url=${encodeURIComponent(inputValue)}`);
  };

  // Hash Lookup Handler
  const handleHashLookup = async () => {
    if (!inputValue) {
      showFeedback('Enter a hash (MD5/SHA)', 'error');
      return;
    }
    showFeedback(`Looking up hash...`, 'info');
    await callAPI(`/api/osint/hash?hash=${encodeURIComponent(inputValue)}`);
  };

  // CVE Database Handler
  const handleCVESearch = async () => {
    if (!inputValue) {
      showFeedback('Enter CVE ID or keyword', 'error');
      return;
    }
    const isCVE = inputValue.toUpperCase().startsWith('CVE-');
    const endpoint = isCVE 
      ? `/api/osint/cve?cveId=${encodeURIComponent(inputValue)}`
      : `/api/osint/cve?keyword=${encodeURIComponent(inputValue)}`;
    showFeedback(`Searching NIST NVD: ${inputValue}...`, 'info');
    await callAPI(endpoint);
  };

  // AI Analyst Handler
  const handleAIAnalysis = async () => {
    if (!inputValue) {
      showFeedback('Enter target for AI analysis', 'error');
      return;
    }
    showFeedback('Running AI analysis...', 'info');
    await callAPI('/api/osint/ai', {
      method: 'POST',
      body: JSON.stringify({ target: inputValue, type: detectInputType(inputValue) })
    });
  };

  // Dark Web Search Handler
  const handleDarkWebSearch = async () => {
    const query = inputValue || 'latest threats breaches malware';
    showFeedback(`Searching Dark Web: ${query}...`, 'info');
    await callAPI('/api/osint/darkweb', {
      method: 'POST',
      body: JSON.stringify({ query, useAI: true })
    });
  };

  // Mobile Analysis Handler
  const handleMobileAnalysis = async () => {
    const fileName = inputValue || 'sample-app.apk';
    const fileType = fileName.endsWith('.ipa') ? 'IPA' : 
                     fileName.endsWith('.appx') ? 'APPX' : 'APK';
    
    showFeedback(`Analyzing mobile app: ${fileName}...`, 'info');
    await callAPI('/api/osint/mobile', {
      method: 'POST',
      body: JSON.stringify({ fileName, fileType, useAI: true })
    });
  };

  // Domain Forensics Handler (Full Lookyloo-style)
  const handleForensicAnalysis = async () => {
    if (!inputValue) {
      showFeedback('Enter a domain for forensic analysis', 'error');
      return;
    }
    
    const cleanDomain = inputValue.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    showFeedback(`Starting forensic analysis of ${cleanDomain}... This may take a moment...`, 'info');
    
    const result = await callAPI('/api/osint/forensics', {
      method: 'POST',
      body: JSON.stringify({ 
        domain: cleanDomain,
        options: {
          dns: true,
          whois: true,
          directories: true,
          headers: true,
          ssl: true,
          capture: true,
          subdomains: true
        }
      })
    });
    
    if (result.success) {
      loadForensicsHistory();
    }
  };

  // Threat Feeds Handler
  const handleThreatFeedLoad = async (feed?: string) => {
    const feedName = feed || 'ALL';
    showFeedback(`Loading threat feed: ${feedName}...`, 'info');
    
    const endpoint = feed ? `/api/osint/threats?feed=${feed}&limit=20` : '/api/osint/threats?limit=20';
    const result = await callAPI(endpoint);
    
    // Show sample data if APIs are restricted
    if (result.success && !result.feeds?.length && !result.error) {
      const sampleData = {
        success: true,
        feeds: [
          { source: 'CISA KEV Catalog', type: 'Known Exploited Vulnerabilities', count: 3, status: 'active', entries: [
            { cveID: 'CVE-2024-3400', product: 'PAN-OS', vulnerabilityName: 'Command Injection', dateAdded: '2024-04-12' },
            { cveID: 'CVE-2024-21887', product: 'Connect Secure', vulnerabilityName: 'RCE via Request Smuggling', dateAdded: '2024-01-25' },
            { cveID: 'CVE-2023-44428', product: 'NetScaler ADC', vulnerabilityName: 'Unauthenticated RCE', dateAdded: '2023-10-15' }
          ]},
          { source: 'MalwareBazaar', type: 'Recent Malware Samples', count: 3, status: 'active', entries: [
            { sha256: 'a1b2c3d4e5f6...', file_type: 'PE32+ executable', signature: 'Emotet', first_seen: '2024-07-20' },
            { sha256: 'f7e8d9c0b1a2...', file_type: 'PDF document', signature: 'Phishing PDF', first_seen: '2024-07-18' },
            { sha256: 'm3n4o5p6q7r8...', file_type: 'Office doc', signature: 'TrickBot Loader', first_seen: '2024-07-19' }
          ]}
        ],
        message: 'Showing sample threat intelligence data'
      };
      setApiData(prev => ({ ...prev, ...sampleData }));
    }
  };

  // ==================== BRAND PROTECTION ====================
  const handleBrandScan = async () => {
    if (!inputValue) { showFeedback('Enter a suspicious URL/domain to check', 'error'); return; }
    const brand = prompt('Enter the brand to protect (e.g., PayPal, BancoX):') || 'Acme';
    showFeedback(`Scanning "${inputValue}" against brand ${brand}...`, 'info');
    await callAPI('/api/osint/brand', { method: 'POST', body: JSON.stringify({ brand, candidate: inputValue, mode: 'scan' }) });
  };

  const handleBrandWatchlist = async () => {
    const brand = prompt('Brand to add to watchlist:') || 'Acme';
    showFeedback(`Adding brand "${brand}" to protection watchlist...`, 'info');
    const result = await callAPI('/api/osint/brand', { method: 'POST', body: JSON.stringify({ brand, mode: 'watchlist', domains: [], keywords: [] }) });
    if (result?.success) showFeedback(`Brand "${brand}" watched`, 'success');
  };

  // ==================== URL SANDBOX ====================
  const handleSandbox = async () => {
    if (!inputValue) { showFeedback('Enter a URL to detonate', 'error'); return; }
    showFeedback(`Detonating ${inputValue} in sandbox...`, 'info');
    await callAPI('/api/osint/sandbox', { method: 'POST', body: JSON.stringify({ url: inputValue }) });
  };

  // ==================== DNS DUMP ====================
  const handleDnsDump = async () => {
    if (!inputValue) { showFeedback('Enter a domain to enumerate', 'error'); return; }
    showFeedback(`Enumerating DNS for ${inputValue}...`, 'info');
    await callAPI(`/api/osint/dnsdump?domain=${encodeURIComponent(inputValue)}`);
  };

  // ==================== SOCIAL MONITOR ====================
  const handleSocialLoad = async (q?: string) => {
    showFeedback('Loading Telegram/Discord intelligence...', 'info');
    const params = new URLSearchParams();
    if (q) params.set('q', q);
    await callAPI(`/api/osint/social?${params}`);
  };

  const handleSocialKeywords = async () => {
    const raw = prompt('Keywords (comma separated):') || 'phishing,malware,breach';
    const keywords = raw.split(',').map((k) => k.trim()).filter(Boolean);
    showFeedback(`Setting ${keywords.length} monitoring keywords...`, 'info');
    await callAPI('/api/osint/social', { method: 'POST', body: JSON.stringify({ action: 'set-keywords', keywords }) });
  };

  // ==================== EXECUTIVE OSINT ====================
  const handleExecScan = async () => {
    if (!inputValue) { showFeedback('Enter the executive name to scan', 'error'); return; }
    showFeedback(`Running exposure scan for "${inputValue}"...`, 'info');
    await callAPI(`/api/osint/exec?name=${encodeURIComponent(inputValue)}`);
  };

  // ==================== FAKE APP ====================
  const handleFakeApp = async () => {
    if (!inputValue) { showFeedback('Enter an APK/IPA filename to analyze', 'error'); return; }
    const fileType = inputValue.endsWith('.ipa') ? 'IPA' : inputValue.endsWith('.appx') ? 'APPX' : 'APK';
    showFeedback(`Analyzing ${inputValue} for fake-app indicators...`, 'info');
    await callAPI('/api/osint/fakeapp', { method: 'POST', body: JSON.stringify({ fileName: inputValue, fileType }) });
  };

  // IOC CRUD Handlers
  const handleAddIOC = async () => {
    if (!formData.value) {
      showFeedback('Enter IOC value', 'error');
      return;
    }
    showFeedback(`Adding ${formData.type}: ${formData.value}...`, 'info');
    await callAPI('/api/osint/iocs', {
      method: 'POST',
      body: JSON.stringify(formData)
    });
    setShowModal(false);
    setFormData({ type: 'IP', value: '', description: '', severity: 'MEDIUM', status: 'UNKNOWN', tags: [] });
  };

  // Add the current analysis result (ip/domain/hash/url) to the IOC store
  const handleAddIOCFromResult = async () => {
    const target = apiData?.data?.ip || apiData?.data?.ipAddress || apiData?.data?.domain || apiData?.data?.hostname || inputValue;
    const detected = detectInputType(target);
    const iocType = detected === 'md5' || detected === 'sha1' || detected === 'sha256' ? 'HASH'
      : detected === 'cve' ? 'CVE'
      : detected === 'url' ? 'URL'
      : detected === 'ip' ? 'IP'
      : 'DOMAIN';
    if (!target) {
      showFeedback('No result to add — run an analysis first', 'error');
      return;
    }

    let severity = 'MEDIUM';
    let status = 'UNKNOWN';
    let description = `Added from ${activeTab} analysis`;
    let tags: string[] = [activeTab, 'from-result'];

    // IP results: carry the DNSBL/blacklist markings from the lookup
    if (iocType === 'IP' && apiData?.reputation) {
      const listed = (apiData.reputation.dnsbl || []).filter((d: any) => d.listed);
      const torExit = apiData.reputation.torExit || false;
      const urlCount = apiData.reputation.urlhaus?.urlCount || 0;
      const blacklisted = listed.length > 0 || torExit || urlCount > 0;
      severity = blacklisted ? 'HIGH' : 'MEDIUM';
      status = blacklisted ? 'SUSPICIOUS' : 'UNKNOWN';
      tags = [activeTab, 'from-result', ...listed.map((d: any) => `dnsbl:${d.name.toLowerCase()}`)];
      if (torExit) tags.push('tor-exit');
      if (urlCount > 0) tags.push(`urlhaus:${urlCount}`);
      const marks = listed.map((d: any) => `${d.name}(${d.records.join(',')})`).join(', ') || 'clean';
      description = `IP ${target} — DNSBL: ${marks}${torExit ? ', Tor exit' : ''}${urlCount > 0 ? `, URLhaus: ${urlCount}` : ''} (multirbl.valli.org check)`;
    }

    showFeedback(`Adding ${iocType}: ${target} to IOCs...`, 'info');
    const result = await callAPI('/api/osint/iocs', {
      method: 'POST',
      body: JSON.stringify({
        type: iocType,
        value: target,
        description,
        severity,
        status,
        tags
      })
    });
    if (result?.success) {
      showFeedback(`Added ${target} to IOCs${severity === 'HIGH' ? ' (blacklisted)' : ''}`, 'success');
      loadIOCs();
    }
  };

  const handleUpdateIOC = async () => {
    if (!selectedIOC) return;
    showFeedback(`Updating IOC: ${selectedIOC.value}...`, 'info');
    await callAPI('/api/osint/iocs', {
      method: 'PATCH',
      body: JSON.stringify({
        id: selectedIOC.id,
        description: formData.description,
        severity: formData.severity,
        status: formData.status || selectedIOC.status,
        tags: formData.tags
      })
    });
    setShowModal(false);
    setSelectedIOC(null);
  };

  const handleDeleteIOC = async (id: string) => {
    if (!confirm('Delete this IOC?')) return;
    showFeedback('Deleting IOC...', 'info');
    await callAPI(`/api/osint/iocs?id=${id}`, { method: 'DELETE' });
  };

  // Export Handler
  const handleExport = async (format: string) => {
    showFeedback(`Preparing ${format} export...`, 'info');
    window.open(`/api/osint/export?format=${format}`, '_blank');
    showFeedback(`${format} export started`, 'success');
  };

  // Report Generation Handler
  const handleGenerateReport = async () => {
    if (!reportConfig.title) {
      showFeedback('Enter report title', 'error');
      return;
    }
    if (reportConfig.modules.length === 0) {
      showFeedback('Select at least one module', 'error');
      return;
    }
    
    showFeedback('Generating report...', 'info');
    await callAPI('/api/osint/reports', {
      method: 'POST',
      body: JSON.stringify(reportConfig)
    });
    loadReports();
  };

  // Load generated reports history
  const loadReports = async () => {
    try {
      const res = await fetch('/api/osint/reports?action=list');
      const data = await res.json();
      if (data.success) setReports(data.data || []);
    } catch (e) {
      console.error('Failed to load reports:', e);
    }
  };

  // ==================== INTELLIGENCE SOURCES ====================
  const loadSources = async () => {
    try {
      const [sourcesRes, healthRes] = await Promise.all([
        fetch('/api/osint/sources'),
        fetch('/api/osint/sources?action=health')
      ]);
      const sourcesData = await sourcesRes.json();
      const healthData = await healthRes.json();
      if (sourcesData.success) setSources(sourcesData.data || []);
      if (healthData.success) setSourceHealth(healthData.data || []);
    } catch (e) {
      console.error('Failed to load sources:', e);
    }
  };

  const handleTestSource = async (id: string) => {
    showFeedback('Testing source connectivity...', 'info');
    try {
      const res = await fetch('/api/osint/sources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'test', id })
      });
      const data = await res.json();
      showFeedback(data.message || (data.success ? 'Source OK' : 'Source failed'), data.success ? 'success' : 'error');
      loadSources();
    } catch (e) {
      showFeedback('Test failed', 'error');
    }
  };

  const handleToggleSource = async (source: any) => {
    try {
      const res = await fetch('/api/osint/sources', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: source.id, enabled: !source.enabled })
      });
      const data = await res.json();
      if (data.success) {
        showFeedback(`${source.name} ${source.enabled ? 'disabled' : 'enabled'}`, 'success');
        loadSources();
      }
    } catch (e) {
      showFeedback('Update failed', 'error');
    }
  };

  const handleAddSource = async () => {
    if (!newSource.name || !newSource.endpoint) {
      showFeedback('Name and endpoint required', 'error');
      return;
    }
    showFeedback('Adding source...', 'info');
    try {
      const res = await fetch('/api/osint/sources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newSource)
      });
      const data = await res.json();
      if (data.success) {
        showFeedback(`Source "${newSource.name}" added`, 'success');
        setNewSource({ name: '', type: 'CUSTOM', method: 'GET', endpoint: '', apiKeyEnv: '', description: '' });
        loadSources();
      } else {
        showFeedback(data.error || 'Failed to add source', 'error');
      }
    } catch (e) {
      showFeedback('Failed to add source', 'error');
    }
  };

  // Modal Handlers
  const openDetailModal = (ioc: IOC) => {
    setSelectedIOC(ioc);
    setModalType('detail');
    setShowModal(true);
  };

  const openEditModal = (ioc: IOC) => {
    setSelectedIOC(ioc);
    setFormData({
      type: ioc.type,
      value: ioc.value,
      description: ioc.description,
      severity: ioc.severity,
      status: ioc.status || 'UNKNOWN',
      tags: ioc.tags
    });
    setModalType('edit');
    setShowModal(true);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    showFeedback('Copied!', 'success');
  };

  // Helpers
  const detectInputType = (value: string): string => {
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) return 'ip';
    if (/^[a-f0-9]{32}$/i.test(value)) return 'md5';
    if (/^[a-f0-9]{40}$/i.test(value)) return 'sha1';
    if (/^[a-f0-9]{64}$/i.test(value)) return 'sha256';
    if (value.toUpperCase().startsWith('CVE-')) return 'cve';
    if (/^https?:\/\//.test(value)) return 'url';
    if (/\.[a-z]{2,}$/.test(value)) return 'domain';
    if (/@/.test(value)) return 'email';
    if (/\.(apk|ipa|appx)$/i.test(value)) return 'mobile';
    return 'general';
  };

  // Chart Data
  const severityChartData = Object.entries(
    iocs.reduce((acc, ioc) => {
      acc[ioc.severity] = (acc[ioc.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>)
  ).map(([name, value]) => ({ name, value }));

  const typeChartData = Object.entries(
    iocs.reduce((acc, ioc) => {
      acc[ioc.type] = (acc[ioc.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>)
  ).map(([name, value]) => ({ name, value }));

  // Module toggle for reports
  const toggleReportModule = (module: string) => {
    setReportConfig(prev => ({
      ...prev,
      modules: prev.modules.includes(module)
        ? prev.modules.filter(m => m !== module)
        : [...prev.modules, module]
    }));
  };

  // ==================== RENDER ====================
  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Feedback Toast */}
      {actionFeedback && (
        <div className={`fixed top-4 right-4 z-[100] px-4 py-3 rounded-lg shadow-lg flex items-center gap-2 animate-pulse ${
          actionFeedback.includes('ERROR') ? 'bg-red-600 text-white' :
          actionFeedback.includes('SUCCESS') ? 'bg-green-600 text-white' :
          'bg-blue-600 text-white'
        }`}>
          {actionFeedback.includes('ERROR') ? <XCircle className="w-4 h-4" /> :
           actionFeedback.includes('SUCCESS') ? <CheckCircle className="w-4 h-4" /> :
           <Loader2 className="w-4 h-4 animate-spin" />}
          <span className="text-sm font-medium">{actionFeedback}</span>
        </div>
      )}

      {/* Header */}
      <header className="bg-gray-900 border-b border-gray-800 sticky top-0 z-50">
        <div className="max-w-[1920px] mx-auto px-4 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Radar className="w-8 h-8 text-red-500 animate-pulse" />
              <div>
                <h1 className="text-xl font-bold bg-gradient-to-r from-red-500 via-orange-500 to-yellow-500 bg-clip-text text-transparent">
                  MONITOR-THREAT
                </h1>
                <p className="text-xs text-gray-400">Brand Protection • URL Sandbox • Social Monitoring • Executive OSINT</p>
              </div>
            </div>
            
            {/* Global Search */}
            <div className="flex-1 max-w-lg mx-8">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search IOCs, IPs, domains, hashes, CVEs..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && loadIOCs()}
                  className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm focus:border-red-500 focus:outline-none focus:ring-1 focus:ring-red-500"
                />
              </div>
            </div>

            <div className="flex items-center gap-4">
              <button 
                onClick={() => { loadIOCs(); showFeedback('Data refreshed', 'success'); }} 
                className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
              >
                <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </button>
              <div className="text-right">
                <div className="text-xs text-gray-400">Indexed</div>
                <div className="text-sm font-bold text-green-400">{iocs.length} IOCs</div>
              </div>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-[1920px] mx-auto flex">
        {/* Sidebar Navigation */}
        <nav className="w-64 min-h-screen bg-gray-900 border-r border-gray-800 p-4 sticky top-[65px] h-[calc(100vh-65px)] overflow-y-auto">
          <div className="space-y-1">
            {[
              { id: 'dashboard', icon: BarChart3, label: 'Dashboard', color: 'text-blue-400' },
              { id: 'ip', icon: Globe, label: 'IP Intel', color: 'text-green-400' },
              { id: 'domain', icon: Server, label: 'Domain Intel', color: 'text-purple-400' },
              { id: 'forensics', icon: Camera, label: 'Domain Forensics', color: 'text-red-400', badge: 'NEW' },
              { id: 'url', icon: ExternalLink, label: 'URL Scanner', color: 'text-yellow-400' },
              { id: 'hash', icon: Fingerprint, label: 'Hash Lookup', color: 'text-cyan-400' },
              { id: 'cve', icon: Shield, label: 'CVE Database', color: 'text-orange-400' },
              { id: 'ai', icon: Cpu, label: 'AI Analyst', color: 'text-pink-400' },
              { id: 'darkweb', icon: Skull, label: 'Dark Web Intel', color: 'text-red-500', badge: 'NEW' },
              { id: 'mobile', icon: Smartphone, label: 'Mobile Security', color: 'text-indigo-400', badge: 'NEW' },
              { id: 'threats', icon: AlertTriangle, label: 'Threat Feeds', color: 'text-amber-400' },
              { id: 'iocs', icon: Database, label: 'IOC Manager', color: 'text-emerald-400' },
              { id: 'export', icon: Download, label: 'Export Data', color: 'text-teal-400' },
              { id: 'sources', icon: Wifi, label: 'Intelligence Sources', color: 'text-sky-400' },
              { id: 'reports', icon: FileText, label: 'Reports', color: 'text-violet-400' },
              { id: 'brand', icon: Shield, label: 'Brand Protection', color: 'text-rose-400', badge: 'NEW' },
              { id: 'sandbox', icon: Zap, label: 'URL Sandbox', color: 'text-lime-400', badge: 'NEW' },
              { id: 'dnsdump', icon: Network, label: 'DNS Dump', color: 'text-teal-400', badge: 'NEW' },
              { id: 'social', icon: MessageSquare, label: 'TG/Discord Monitor', color: 'text-blue-400', badge: 'NEW' },
               { id: 'exec', icon: ShieldUser, label: 'Executive OSINT', color: 'text-amber-400', badge: 'NEW' },
              { id: 'fakeapp', icon: Smartphone, label: 'Fake App Scanner', color: 'text-fuchsia-400', badge: 'NEW' },
            ].map(({ id, icon: Icon, label, color, badge }) => (
              <button
                key={id}
                onClick={() => { setActiveTab(id as TabType); showFeedback(`Loaded ${label}`); }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all relative ${
                  activeTab === id
                    ? 'bg-gradient-to-r from-red-600/20 to-orange-600/20 border border-red-500/50 text-white'
                    : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                }`}
              >
                <Icon className={`w-4 h-4 ${activeTab === id ? '' : color}`} />
                <span>{label}</span>
                {badge && (
                  <span className="ml-auto px-1.5 py-0.5 text-[10px] font-bold bg-red-500 text-white rounded">
                    {badge}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Quick Stats */}
          <div className="mt-6 p-4 bg-gray-800 rounded-xl border border-gray-700">
            <h3 className="text-xs font-semibold mb-3 flex items-center gap-2 text-gray-400">
              <Activity className="w-3 h-3" /> LIVE STATS
            </h3>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Critical</span>
                <span className="font-bold text-red-400 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" />
                  {iocs.filter(i => i.severity === 'CRITICAL').length}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Malicious</span>
                <span className="font-bold text-red-500">{iocs.filter(i => i.status === 'MALICIOUS').length}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Timeline Events</span>
                <span className="font-bold text-blue-400">{timelineData.length}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Status</span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                  LIVE
                </span>
              </div>
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main className="flex-1 p-6 overflow-y-auto h-[calc(100vh-65px)]">
          
          {/* ==================== DASHBOARD TAB ==================== */}
          {activeTab === 'dashboard' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <BarChart3 className="w-7 h-7 text-blue-400" /> Command Dashboard
                </h2>
                <button onClick={() => { loadIOCs(); setTimelineData(generateTimelineData()); }} className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
                  <RefreshCw className="w-4 h-4" /> Refresh All
                </button>
              </div>

              {/* Stats Cards - Clickable */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {[
                  { label: 'Total IOCs', value: iocs.length, icon: Database, color: 'blue', onClick: () => setActiveTab('iocs') },
                  { label: 'Critical Threats', value: iocs.filter(i => i.severity === 'CRITICAL').length, icon: AlertTriangle, color: 'red', onClick: () => setActiveTab('iocs') },
                  { label: 'Malicious', value: iocs.filter(i => i.status === 'MALICIOUS').length, icon: ShieldAlert, color: 'red', onClick: () => setActiveTab('iocs') },
                  { label: 'Live Events', value: timelineData.length, icon: Activity, color: 'green', onClick: () => {} },
                ].map(({ label, value, icon: Icon, color, onClick }) => (
                  <button
                    key={label}
                    onClick={onClick}
                    className={`p-5 bg-gray-900 border border-gray-800 rounded-xl hover:border-${color}-500/50 transition-all group cursor-pointer`}
                  >
                    <div className="flex items-center justify-between">
                      <Icon className={`w-8 h-8 text-${color}-400 group-hover:scale-110 transition-transform`} />
                      <span className="text-3xl font-bold text-white">{value}</span>
                    </div>
                    <p className="text-sm text-gray-400 mt-2">{label}</p>
                  </button>
                ))}
              </div>

              {/* Live Threat Timeline - INTERACTIVE */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold flex items-center gap-2">
                    <Clock className="w-5 h-5 text-red-400 animate-pulse" />
                    Live Threat Timeline
                    <span className="px-2 py-0.5 text-xs bg-red-500/20 text-red-400 rounded">LIVE</span>
                  </h3>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setTimelineRunning(!timelineRunning)}
                      className={`p-2 rounded-lg ${timelineRunning ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}
                    >
                      {timelineRunning ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                    </button>
                    <button
                      onClick={() => setTimelineData(generateTimelineData())}
                      className="p-2 bg-gray-800 hover:bg-gray-700 rounded-lg"
                      title="Reset Timeline"
                    >
                      <RefreshCw className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                
                <div className="space-y-2 max-h-[400px] overflow-y-auto">
                  {timelineData.map((event, idx) => (
                    <div
                      key={idx}
                      onClick={() => {
                        if (event.type === 'threat') setActiveTab('threats');
                        else if (event.type === 'ioc') setActiveTab('iocs');
                        showFeedback(`Viewing: ${event.event}`);
                      }}
                      className={`flex items-start gap-3 p-3 rounded-lg cursor-pointer hover:bg-gray-800 transition-colors ${
                        event.severity === 'CRITICAL' ? 'bg-red-500/10 border-l-2 border-red-500' :
                        event.severity === 'HIGH' ? 'bg-orange-500/10 border-l-2 border-orange-500' :
                        event.severity === 'MEDIUM' ? 'bg-yellow-500/10 border-l-2 border-yellow-500' :
                        'bg-gray-800/50'
                      }`}
                    >
                      <span className="text-xs text-gray-500 min-w-[70px]">{event.time}</span>
                      {event.type === 'threat' && <Skull className="w-4 h-4 text-red-400 mt-0.5" />}
                      {event.type === 'ioc' && <Database className="w-4 h-4 text-blue-400 mt-0.5" />}
                      {event.type === 'analysis' && <Search className="w-4 h-4 text-purple-400 mt-0.5" />}
                      {event.type === 'alert' && <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5" />}
                      {event.type === 'system' && <Activity className="w-4 h-4 text-green-400 mt-0.5" />}
                      <span className="text-sm flex-1">{event.event}</span>
                      {event.severity && (
                        <span className={`text-xs px-2 py-0.5 rounded ${
                          event.severity === 'CRITICAL' ? 'bg-red-500 text-white' :
                          event.severity === 'HIGH' ? 'bg-orange-500 text-black' :
                          'bg-gray-700'
                        }`}>
                          {event.severity}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Charts Row */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                  <h3 className="font-semibold mb-4 flex items-center gap-2">
                    <PieChartIcon className="w-5 h-5 text-purple-400" /> Severity Distribution
                  </h3>
                  {severityChartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={250}>
                      <PieChart>
                        <Pie data={severityChartData} innerRadius={60} outerRadius={100} paddingAngle={5} dataKey="value">
                          {severityChartData.map((entry, index) => (
                            <Cell key={index} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-[250px] flex items-center justify-center text-gray-500">
                      No data yet - run some analyses!
                    </div>
                  )}
                </div>

                <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                  <h3 className="font-semibold mb-4 flex items-center gap-2">
                    <BarChart3 className="w-5 h-5 text-cyan-400" /> Type Distribution
                  </h3>
                  {typeChartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={250}>
                      <BarChart data={typeChartData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                        <XAxis stroke="#9ca3af" dataKey="name" />
                        <YAxis stroke="#9ca3af" />
                        <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
                        <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-[250px] flex items-center justify-center text-gray-500">
                      No data yet
                    </div>
                  )}
                </div>
              </div>

              {/* Recent IOCs Table - Clickable rows */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold">Recent IOCs</h3>
                  <button onClick={() => setActiveTab('iocs')} className="text-sm text-red-400 hover:text-red-300 flex items-center gap-1">
                    View All <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-gray-800">
                        <th className="text-left py-3 px-3 text-gray-400">Type</th>
                        <th className="text-left py-3 px-3 text-gray-400">Value</th>
                        <th className="text-left py-3 px-3 text-gray-400">Severity</th>
                        <th className="text-left py-3 px-3 text-gray-400">Status</th>
                        <th className="text-left py-3 px-3 text-gray-400">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {iocs.slice(0, 8).map((ioc) => (
                        <tr 
                          key={ioc.id} 
                          onClick={() => openDetailModal(ioc)}
                          className="border-b border-gray-800 hover:bg-gray-800 cursor-pointer transition-colors"
                        >
                          <td className="py-3 px-3">
                            <span className="px-2 py-1 bg-gray-700 rounded text-xs">{ioc.type}</span>
                          </td>
                          <td className="py-3 px-3 font-mono text-sm">{ioc.value}</td>
                          <td className="py-3 px-3">
                            <span style={{ color: SEVERITY_COLORS[ioc.severity] }} className="font-medium">
                              {ioc.severity}
                            </span>
                          </td>
                          <td className="py-3 px-3">
                            <span style={{ color: STATUS_COLORS[ioc.status] }} className="font-medium">
                              {ioc.status}
                            </span>
                          </td>
                          <td className="py-3 px-3">
                            <button onClick={(e) => { e.stopPropagation(); openDetailModal(ioc); }} className="p-1 hover:bg-gray-700 rounded">
                              <Eye className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {iocs.length === 0 && (
                    <div className="text-center py-8 text-gray-500">
                      No IOCs yet. Go to IP Intel or other modules to add some!
                    </div>
                  )}
                </div>
              </div>

              {/* Quick Actions Grid */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <h3 className="font-semibold mb-4 flex items-center gap-2">
                  <Zap className="w-5 h-5 text-yellow-400" /> Quick Actions
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {[
                    { label: 'IP Recon', icon: Globe, tab: 'ip' as TabType },
                    { label: 'Domain Scan', icon: Server, tab: 'domain' as TabType },
                    { label: 'URL Analysis', icon: ExternalLink, tab: 'url' as TabType },
                    { label: 'Hash Lookup', icon: Fingerprint, tab: 'hash' as TabType },
                    { label: 'CVE Search', icon: Shield, tab: 'cve' as TabType },
                    { label: 'AI Analysis', icon: Cpu, tab: 'ai' as TabType },
                    { label: 'Dark Web', icon: Skull, tab: 'darkweb' as TabType },
                    { label: 'Mobile Scan', icon: Smartphone, tab: 'mobile' as TabType },
                  ].map(({ label, icon: Icon, tab }) => (
                    <button
                      key={label}
                      onClick={() => { setActiveTab(tab); showFeedback(`Opening ${label}...`); }}
                      className="flex items-center gap-2 p-3 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
                    >
                      <Icon className="w-4 h-4 text-blue-400" />
                      <span className="text-sm">{label}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ==================== IP INTEL TAB ==================== */}
          {activeTab === 'ip' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Globe className="w-7 h-7 text-green-400" /> IP Intelligence
              </h2>
              
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter IP address (e.g., 8.8.8.8, 1.1.1.1)"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleIPRecon()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-green-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleIPRecon}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-green-600 hover:bg-green-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    Analyze IP
                  </button>
                </div>
              </div>

              {/* Results Display */}
              {apiData && apiData.data && (
                <div className="space-y-4">
                  <div className="bg-gradient-to-r from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2">
                      <CheckCircle className="w-5 h-5 text-green-400" /> Live Results
                      {apiData.fetchedLive && <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded">LIVE DATA</span>}
                    </h3>
                    
                    {/* Network classification + threat level */}
                    <div className="flex flex-wrap gap-2 mb-4">
                      {apiData.analysis?.threatLevel && (
                        <span className={`px-2 py-1 rounded border text-xs font-medium ${apiData.analysis.threatLevel === 'ELEVATED' ? 'bg-orange-500/20 text-orange-400 border-orange-500/40' : 'bg-green-500/20 text-green-400 border-green-500/40'}`}>
                          Threat Level: {apiData.analysis.threatLevel}
                        </span>
                      )}
                      {apiData.data.proxy && <span className="px-2 py-1 rounded border text-xs font-medium bg-orange-500/20 text-orange-400 border-orange-500/40">Proxy / VPN</span>}
                      {apiData.reputation?.torExit && <span className="px-2 py-1 rounded border text-xs font-medium bg-red-600/30 text-red-300 border-red-500/50">Tor Exit Node</span>}
                      {(apiData.reputation?.dnsbl?.filter((d: any) => d.listed)?.length || 0) > 0 && <span className="px-2 py-1 rounded border text-xs font-medium bg-red-500/20 text-red-400 border-red-500/40">Blacklisted ({apiData.reputation.dnsbl.filter((d: any) => d.listed).length} lists)</span>}
                      {apiData.data.hosting && <span className="px-2 py-1 rounded border text-xs font-medium bg-red-500/20 text-red-400 border-red-500/40">Hosting / Cloud</span>}
                      {apiData.data.mobile && <span className="px-2 py-1 rounded border text-xs font-medium bg-purple-500/20 text-purple-400 border-purple-500/40">Mobile Network</span>}
                      {!apiData.data.proxy && !apiData.data.hosting && <span className="px-2 py-1 rounded border text-xs font-medium bg-green-500/20 text-green-400 border-green-500/40">Residential / Business</span>}
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {(apiData.data.query || apiData.data.ip) && (
                        <>
                          <InfoCard label="IP Address" value={apiData.data.query || apiData.data.ip} icon={<Globe className="w-4 h-4" />} />
                          <InfoCard label="Hostname (reverse DNS)" value={apiData.data.reverse || 'N/A'} icon={<Network className="w-4 h-4" />} />
                          <InfoCard label="Country" value={`${apiData.data.country || 'N/A'} (${apiData.data.countryCode || ''})`} icon={<MapPin className="w-4 h-4" />} />
                          <InfoCard label="Region" value={apiData.data.regionName || 'N/A'} icon={<MapPin className="w-4 h-4" />} />
                          <InfoCard label="City" value={apiData.data.city || 'N/A'} icon={<Server className="w-4 h-4" />} />
                          <InfoCard label="District" value={apiData.data.district || 'N/A'} icon={<MapPin className="w-4 h-4" />} />
                          <InfoCard label="Postal Code" value={apiData.data.zip || 'N/A'} icon={<FileCode className="w-4 h-4" />} />
                          <InfoCard label="Continent" value={`${apiData.data.continent || 'N/A'} (${apiData.data.continentCode || ''})`} icon={<Globe2 className="w-4 h-4" />} />
                          <InfoCard label="ISP" value={apiData.data.isp || 'N/A'} icon={<Wifi className="w-4 h-4" />} />
                          <InfoCard label="Organization" value={apiData.data.org || 'N/A'} icon={<Database className="w-4 h-4" />} />
                          <InfoCard label="ASN" value={`${apiData.data.as || 'N/A'}${apiData.data.asname ? ` — ${apiData.data.asname}` : ''}`} icon={<Radar className="w-4 h-4" />} />
                          <InfoCard label="Latitude" value={apiData.data.lat || 'N/A'} icon={<Target className="w-4 h-4" />} />
                          <InfoCard label="Longitude" value={apiData.data.lon || 'N/A'} icon={<Target className="w-4 h-4" />} />
                          <InfoCard label="Timezone" value={apiData.data.timezone || 'N/A'} icon={<Clock className="w-4 h-4" />} />
                          <InfoCard label="Local Time" value={apiData.data.timezone ? new Intl.DateTimeFormat('en-GB', { timeZone: apiData.data.timezone, dateStyle: 'medium', timeStyle: 'medium' }).format(new Date()) : 'N/A'} icon={<Clock className="w-4 h-4" />} />
                          <InfoCard label="Currency" value={apiData.data.currency || 'N/A'} icon={<Database className="w-4 h-4" />} />
                        </>
                      )}
                    </div>

                    {/* Map */}
                    {apiData.data.lat && apiData.data.lon && (
                      <div className="mt-4 rounded-lg overflow-hidden border border-gray-700">
                        <iframe
                          title="IP Location Map"
                          src={`https://www.openstreetmap.org/export/embed.html?bbox=${Number(apiData.data.lon) - 0.1}%2C${Number(apiData.data.lat) - 0.1}%2C${Number(apiData.data.lon) + 0.1}%2C${Number(apiData.data.lat) + 0.1}&layer=mapnik&marker=${apiData.data.lat}%2C${apiData.data.lon}`}
                          className="w-full h-64"
                          loading="lazy"
                        />
                      </div>
                    )}

                    {apiData.data.location && (
                      <div className="mt-4 p-4 bg-gray-800/50 rounded-lg">
                        <h4 className="text-sm font-medium mb-2">Location Details</h4>
                        <p className="text-sm text-gray-300">{apiData.data.location}</p>
                      </div>
                    )}

                    {/* RDAP / WHOIS ownership */}
                    {apiData.data.rdap && (
                      <div className="mt-4 p-4 bg-gray-800/50 rounded-lg border border-gray-700">
                        <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                          <Shield className="w-4 h-4 text-green-400" /> Network Ownership (RDAP)
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                          {apiData.data.rdap.name && <div><span className="text-gray-400">Network:</span> <span className="font-mono">{apiData.data.rdap.name}</span></div>}
                          {apiData.data.rdap.startAddress && apiData.data.rdap.endAddress && <div><span className="text-gray-400">Range:</span> <span className="font-mono">{apiData.data.rdap.startAddress} — {apiData.data.rdap.endAddress}</span></div>}
                          {apiData.data.rdap.entities?.length > 0 && <div><span className="text-gray-400">Registrant:</span> <span>{apiData.data.rdap.entities.join(', ')}</span></div>}
                          {apiData.data.rdap.country && <div><span className="text-gray-400">Registry Country:</span> <span>{apiData.data.rdap.country}</span></div>}
                          {apiData.data.rdap.status?.length > 0 && <div><span className="text-gray-400">Status:</span> <span>{apiData.data.rdap.status.join(', ')}</span></div>}
                          {apiData.data.rdap.abuseContacts?.length > 0 && <div><span className="text-gray-400">Abuse Contact:</span> <a href={`mailto:${apiData.data.rdap.abuseContacts[0]}`} className="text-red-400 underline break-all">{apiData.data.rdap.abuseContacts.join(', ')}</a></div>}
                        </div>
                      </div>
                    )}

                    {/* Reputation & Threat Intelligence */}
                    {apiData.reputation && (
                      <div className="mt-4 p-4 bg-gray-800/50 rounded-lg border border-gray-700">
                        <h4 className="text-sm font-medium mb-3 flex items-center gap-2">
                          <ShieldAlert className="w-4 h-4 text-red-400" /> Reputation & Threat Intelligence
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <p className="text-xs text-gray-400 mb-1">DNS Blacklists (DNSBL)</p>
                            {apiData.reputation.dnsbl.length === 0 ? (
                              <p className="text-xs text-gray-500">Not applicable (IPv6 / unavailable)</p>
                            ) : (
                              <ul className="space-y-1">
                                {apiData.reputation.dnsbl.map((d: any) => (
                                  <li key={d.zone} className={`flex items-center justify-between text-xs px-2 py-1 rounded ${d.listed ? 'bg-red-500/20 text-red-400' : 'bg-green-500/10 text-green-400'}`}>
                                    <span>{d.name}</span>
                                    <span>{d.listed ? `LISTED ${d.records.join(',')}` : 'clean'}</span>
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                          <div>
                            <p className="text-xs text-gray-400 mb-1">Malicious URL History (URLhaus)</p>
                            {apiData.reputation.urlhaus?.urlCount > 0 ? (
                              <>
                                <p className="text-sm text-red-400 font-medium mb-2">{apiData.reputation.urlhaus.urlCount} malicious URL(s) associated</p>
                                <ul className="space-y-1 max-h-32 overflow-y-auto">
                                  {apiData.reputation.urlhaus.urls.slice(0, 10).map((u: any, i: number) => (
                                    <li key={i} className="text-xs font-mono text-red-300 bg-gray-900 rounded px-2 py-1 break-all">
                                      {u.url} <span className="text-gray-500">[{u.threat} · {u.dateAdded}]</span>
                                    </li>
                                  ))}
                                </ul>
                              </>
                            ) : (
                              <p className="text-xs text-green-400">No malicious URLs found on URLhaus</p>
                            )}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Certificates / pivoting */}
                    {apiData.pivot?.certificates?.length > 0 && (
                      <div className="mt-4 p-4 bg-gray-800/50 rounded-lg border border-gray-700">
                        <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                          <Lock className="w-4 h-4 text-blue-400" /> SSL/TLS Certificates & Linked Domains (crt.sh)
                        </h4>
                        <ul className="space-y-1 max-h-48 overflow-y-auto">
                          {apiData.pivot.certificates.slice(0, 25).map((c: any, i: number) => (
                            <li key={i} className="text-xs px-2 py-1 bg-gray-900 rounded">
                              <span className="font-mono text-blue-300">{c.nameValue}</span>
                              {c.issuerName && <span className="text-gray-500"> · {c.issuerName}</span>}
                              {c.notBefore && <span className="text-gray-600"> · valid from {c.notBefore.slice(0, 10)}</span>}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Active scan */}
                    {apiData.scan?.ports?.length > 0 && (
                      <div className="mt-4 p-4 bg-gray-800/50 rounded-lg border border-gray-700">
                        <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                          <Terminal className="w-4 h-4 text-purple-400" /> Active Scan — Exposed Services
                        </h4>
                        <p className="text-xs text-gray-400 mb-2">Estimated OS: <span className="text-purple-300 font-medium">{apiData.scan.os}</span></p>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          {apiData.scan.ports.map((p: any) => (
                            <div key={p.port} className={`flex items-center gap-2 text-xs px-2 py-1 rounded ${p.state === 'open' ? 'bg-red-500/20 text-red-300' : p.state === 'filtered' ? 'bg-gray-900 text-gray-500' : 'bg-gray-900 text-gray-600'}`}>
                              <span className="font-mono w-14">{p.port}</span>
                              <span className="w-20">{p.service}</span>
                              <span className="w-16 font-medium">{p.state === 'open' ? 'OPEN' : p.state.toUpperCase()}</span>
                              {p.banner && <span className="text-gray-400 truncate flex-1" title={p.banner}>{p.banner}</span>}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Forensic artifacts guidance */}
                    <div className="mt-4 p-4 bg-gray-800/50 rounded-lg border border-gray-700">
                      <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                        <Fingerprint className="w-4 h-4 text-green-400" /> Forensic Artifacts to Extract from Logs
                      </h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-gray-300">
                        <div><span className="text-green-400 font-medium">Timestamps / Timezones:</span> build an exact connection timeline to correlate events across systems</div>
                        <div><span className="text-green-400 font-medium">Ephemeral Source Port:</span> identifies the unique client session behind NAT/CGNAT in ISP records</div>
                        <div><span className="text-green-400 font-medium">HTTP Headers / User-Agent:</span> browser, client OS, system locale and Referer origin</div>
                        <div><span className="text-green-400 font-medium">Session Correlation:</span> multiple accounts/cookies tied to the same IP within a time window</div>
                      </div>
                    </div>

                    {/* Action Buttons on Result */}
                    <div className="mt-4 flex flex-wrap gap-2">
                      <button onClick={() => copyToClipboard(apiData.data.query || apiData.data.ip)} className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2">
                        <Copy className="w-4 h-4" /> Copy IP
                      </button>
                      <button onClick={() => handleAddIOCFromResult()} className="px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm flex items-center gap-2">
                        <Plus className="w-4 h-4" /> Add to IOCs
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Globe className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Ready for IP Analysis</h3>
                  <p className="text-gray-400 mb-4">Enter an IP address above to get real-time geolocation and intelligence data.</p>
                  <p className="text-xs text-gray-500">Powered by ip-api.com with live data</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== DOMAIN INTEL TAB ==================== */}
          {activeTab === 'domain' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Server className="w-7 h-7 text-purple-400" /> Domain Intelligence
              </h2>
              
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter domain (e.g., google.com, example.org)"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleDomainRecon()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-purple-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleDomainRecon}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    Resolve DNS
                  </button>
                </div>

                <div className="mt-4 flex flex-wrap gap-2">
                  <span className="text-xs text-gray-500">Try:</span>
                  {['google.com', 'github.com', 'microsoft.com', 'amazonaws.com'].map(domain => (
                    <button
                      key={domain}
                      onClick={() => { setInputValue(domain); handleDomainRecon(); }}
                      className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded text-xs font-mono"
                    >
                      {domain}
                    </button>
                  ))}
                </div>
              </div>

              {apiData?.dns && (
                <div className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-xl p-5">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-purple-400" /> DNS Records
                  </h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {Object.entries(apiData.dns).map(([type, records]: [string, any]) => (
                      <div key={type} className="p-3 bg-gray-800/50 rounded-lg">
                        <h4 className="text-sm font-medium text-purple-400 mb-2">{type} Records</h4>
                        {records?.data?.length > 0 ? (
                          <div className="space-y-1">
                            {records.data.map((record: any, idx: number) => (
                              <div key={idx} className="text-xs font-mono text-gray-300 bg-gray-900 p-2 rounded">
                                {record.name || record.data || JSON.stringify(record)}
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-xs text-gray-500">No records found</p>
                        )}
                      </div>
                    ))}
                  </div>

                  {apiData.securityAnalysis && (
                    <div className="mt-4 space-y-2">
                      <h4 className="text-sm font-medium">Security Analysis</h4>
                      <SecurityCheck key="spf" label="SPF Record" pass={apiData.securityAnalysis.hasSPF === true} />
                      <SecurityCheck key="dmarc" label="DMARC Record" pass={apiData.securityAnalysis.hasDMARC === true} />
                    </div>
                  )}

                  <div className="mt-4 flex flex-wrap gap-2">
                    <button onClick={() => setActiveTab('forensics')} className="px-3 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-sm flex items-center gap-2">
                      <Camera className="w-4 h-4" /> Full Forensics
                    </button>
                    <button onClick={() => copyToClipboard(inputValue)} className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2">
                      <Copy className="w-4 h-4" /> Copy Domain
                    </button>
                  </div>
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Server className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">DNS Resolution Ready</h3>
                  <p className="text-gray-400">Enter a domain to resolve DNS records including A, MX, NS, TXT records.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== DOMAIN FORENSICS TAB (Lookyloo-style) ==================== */}
          {activeTab === 'forensics' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Camera className="w-7 h-7 text-red-400" /> Domain Forensics Lab
                  <span className="text-sm font-normal text-gray-400">(Lookyloo-style)</span>
                </h2>
              </div>
              
              <div className="bg-gray-900 border border-red-500/30 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter domain for complete forensic analysis..."
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleForensicAnalysis()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-red-500 focus:outline-none font-mono"
                    />
                  </div>
                  <button
                    onClick={handleForensicAnalysis}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Camera className="w-4 h-4" />}
                    Start Forensics
                  </button>
                </div>

                <div className="mt-4 flex flex-wrap gap-2">
                  <span className="text-xs text-gray-500">Includes:</span>
                  {['DNS Enumeration', 'WHOIS', 'Dirb Scan', 'HTTP Headers', 'SSL Analysis', 'Page Capture', 'Subdomains'].map(item => (
                    <span key={item} className="px-2 py-1 bg-red-500/10 text-red-400 rounded text-xs">{item}</span>
                  ))}
                </div>
              </div>

              {/* Previous Analyses */}
              {forensicsHistory.length > 0 && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <FolderOpen className="w-5 h-5 text-yellow-400" /> Previous Analyses ({forensicsHistory.length})
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {forensicsHistory.slice(0, 6).map((analysis, idx) => (
                      <button
                        key={idx}
                        onClick={async () => {
                          showFeedback('Loading analysis...');
                          const res = await fetch(`/api/osint/forensics?action=get&name=${analysis.name}`);
                          const data = await res.json();
                          if (data.success) {
                            setApiData(data);
                            setSelectedForensics(data.data);
                          }
                        }}
                        className="p-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-left transition-colors"
                      >
                        <div className="font-mono text-sm text-green-400">{analysis.name.split('_')[0]}</div>
                        <div className="text-xs text-gray-500 mt-1">
                          {new Date(analysis.created).toLocaleDateString()}
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Forensics Results */}
              {apiData?.data && activeTab === 'forensics' && (
                <div className="space-y-4">
                  {/* Risk Assessment */}
                  {apiData.data.riskAssessment && (
                    <div className={`rounded-xl p-5 border ${
                      apiData.data.riskAssessment.level === 'CRITICAL' ? 'bg-red-500/10 border-red-500/50' :
                      apiData.data.riskAssessment.level === 'HIGH' ? 'bg-orange-500/10 border-orange-500/50' :
                      apiData.data.riskAssessment.level === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/50' :
                      'bg-green-500/10 border-green-500/50'
                    }`}>
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <ShieldAlert className="w-5 h-5" /> Risk Assessment
                        <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                          apiData.data.riskAssessment.level === 'CRITICAL' ? 'bg-red-500 text-white' :
                          apiData.data.riskAssessment.level === 'HIGH' ? 'bg-orange-500 text-black' :
                          'bg-yellow-500 text-black'
                        }`}>
                          {apiData.data.riskAssessment.level} ({apiData.data.riskAssessment.score}/10)
                        </span>
                      </h3>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <h4 className="text-sm font-medium text-red-400 mb-2">Findings:</h4>
                          <ul className="space-y-1">
                            {apiData.data.riskAssessment.findings.map((finding: string, idx: number) => (
                              <li key={idx} className="text-sm flex items-start gap-2">
                                <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                                {finding}
                              </li>
                            ))}
                          </ul>
                        </div>
                        <div>
                          <h4 className="text-sm font-medium text-green-400 mb-2">Recommendations:</h4>
                          <ul className="space-y-1">
                            {apiData.data.riskAssessment.recommendations.map((rec: string, idx: number) => (
                              <li key={idx} className="text-sm flex items-start gap-2">
                                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 shrink-0" />
                                {rec}
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* DNS Records */}
                  {apiData.data.dns && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Server className="w-5 h-5 text-blue-400" /> DNS Enumeration
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                        {Object.entries(apiData.data.dns).map(([type, records]: [string, any]) => (
                          <div key={type} className="p-3 bg-gray-800 rounded-lg">
                            <div className="text-xs font-medium text-gray-400 mb-1">{type} Records</div>
                            {records?.data?.length > 0 ? (
                              <div className="space-y-1">
                                {records.data.slice(0, 3).map((r: any, i: number) => (
                                  <div key={i} className="text-xs font-mono text-green-400 truncate">{r.data || r}</div>
                                ))}
                                {records.data.length > 3 && (
                                  <div className="text-xs text-gray-500">+{records.data.length - 3} more</div>
                                )}
                              </div>
                            ) : (
                              <div className="text-xs text-gray-500">No records</div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Directory Enumeration (Dirb-style) */}
                  {apiData.data.directories && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <FolderOpen className="w-5 h-5 text-yellow-400" /> Directory Enumeration (Dirb-style)
                        <span className="text-xs bg-yellow-500/20 text-yellow-400 px-2 py-0.5 rounded">
                          {apiData.data.directories.length} paths found
                        </span>
                      </h3>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b border-gray-800">
                              <th className="text-left py-2 px-3 text-gray-400">Path</th>
                              <th className="text-left py-2 px-3 text-gray-400">Status</th>
                              <th className="text-left py-2 px-3 text-gray-400">Size</th>
                              <th className="text-left py-2 px-3 text-gray-400">Type</th>
                            </tr>
                          </thead>
                          <tbody>
                            {apiData.data.directories.map((dir: any, idx: number) => (
                              <tr key={idx} className="border-b border-gray-800 hover:bg-gray-800">
                                <td className="py-2 px-3 font-mono text-sm">{dir.path}</td>
                                <td className="py-2 px-3">
                                  <span className={`px-2 py-0.5 rounded text-xs ${
                                    dir.status === 200 ? 'bg-green-500/20 text-green-400' :
                                    dir.status === 403 ? 'bg-red-500/20 text-red-400' :
                                    dir.status === 301 ? 'bg-yellow-500/20 text-yellow-400' :
                                    'bg-gray-700 text-gray-400'
                                  }`}>{dir.status}</span>
                                </td>
                                <td className="py-2 px-3 text-gray-400">{dir.size}</td>
                                <td className="py-2 px-3 text-gray-400">{dir.type}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* HTTP Headers & Security */}
                  {apiData.data.httpHeaders && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <FileCode className="w-5 h-5 text-cyan-400" /> HTTP Headers & Security Analysis
                      </h3>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <h4 className="text-sm font-medium mb-2">Server Info</h4>
                          <div className="space-y-1 text-sm">
                            <div className="flex justify-between"><span className="text-gray-400">Status Code:</span><span>{apiData.data.httpHeaders.statusCode}</span></div>
                            <div className="flex justify-between"><span className="text-gray-400">Server:</span><span>{apiData.data.httpHeaders.server}</span></div>
                            <div className="flex justify-between"><span className="text-gray-400">Technologies:</span><span>{apiData.data.httpHeaders.technologies?.join(', ')}</span></div>
                          </div>
                        </div>
                        
                        <div>
                          <h4 className="text-sm font-medium mb-2">Security Headers ({apiData.data.httpHeaders.securityScore})</h4>
                          <div className="space-y-1">
                            {Object.entries(apiData.data.httpHeaders.securityHeaders || {}).map(([header, present]: [string, any]) => (
                              <div key={header} className="flex items-center gap-2 text-sm">
                                {present ? <CheckCircle className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                                <span className={present ? '' : 'text-gray-500 line-through'}>{header}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Page Capture */}
                  {apiData.data.capture && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Eye className="w-5 h-5 text-purple-400" /> Page Capture Results
                        {apiData.data.capture.captured && <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded ml-2">Captured</span>}
                      </h3>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <InfoCard label="Title" value={apiData.data.capture.title} icon={<FileText className="w-4 h-4" />} />
                        <InfoCard label="HTML Size" value={`${(apiData.data.capture.htmlSize / 1024).toFixed(1)} KB`} icon={<Database className="w-4 h-4" />} />
                        <InfoCard label="Links Found" value={String(apiData.data.capture.linkCount)} icon={<LinkIcon className="w-4 h-4" />} />
                        <InfoCard label="Scripts" value={String(apiData.data.capture.scriptCount)} icon={<FileCode className="w-4 h-4" />} />
                        <InfoCard label="Forms" value={String(apiData.data.capture.formCount)} icon={<Terminal className="w-4 h-4" />} />
                        <InfoCard label="Login Form" value={apiData.data.capture.hasLoginForm ? 'Yes ⚠️' : 'No'} icon={<Lock className="w-4 h-4" />} alert={apiData.data.capture.hasLoginForm} />
                        <InfoCard label="Admin Panel" value={apiData.data.capture.hasAdminPanel ? 'Yes ⚠️' : 'No'} icon={<ShieldAlert className="w-4 h-4" />} alert={apiData.data.capture.hasAdminPanel} />
                      </div>

                      {apiData.data.capture.sensitivePatterns && (
                        <div className="mt-4 p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                          <h4 className="text-sm font-medium text-red-400 mb-2">Sensitive Information Detected</h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                            {apiData.data.capture.sensitivePatterns.emailAddresses?.length > 0 && (
                              <div>Emails: {apiData.data.capture.sensitivePatterns.emailAddresses.length} found</div>
                            )}
                            {apiData.data.capture.sensitivePatterns.phoneNumbers?.length > 0 && (
                              <div>Phones: {apiData.data.capture.sensitivePatterns.phoneNumbers.length} found</div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Subdomains */}
                  {apiData.data.subdomains && apiData.data.subdomains.length > 0 && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Globe2 className="w-5 h-5 text-indigo-400" /> Discovered Subdomains
                        <span className="text-xs bg-indigo-500/20 text-indigo-400 px-2 py-0.5 rounded">
                          {apiData.data.subdomains.length} found
                        </span>
                      </h3>
                      <div className="flex flex-wrap gap-2">
                        {apiData.data.subdomains.map((sub: string, idx: number) => (
                          <span key={idx} className="px-3 py-1 bg-gray-800 rounded-lg font-mono text-sm hover:bg-gray-700 cursor-pointer">
                            {sub}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Saved Path */}
                  {apiData.data.savedPath && (
                    <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4 flex items-center gap-3">
                      <FolderOpen className="w-5 h-5 text-green-400" />
                      <div>
                        <div className="text-sm font-medium text-green-400">Results Saved</div>
                        <div className="text-xs text-gray-400 font-mono">{apiData.data.savedPath}</div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Camera className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Forensic Analysis Lab</h3>
                  <p className="text-gray-400 mb-4">Complete domain forensics similar to Lookyloo. Generates a full report folder with all findings.</p>
                  <div className="flex flex-wrap justify-center gap-2">
                    {['example.com', 'testphp.vulnweb.com', 'demo.testfire.net'].map(d => (
                      <button
                        key={d}
                        onClick={() => setInputValue(d)}
                        className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded text-xs font-mono"
                      >
                        {d}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ==================== URL SCANNER TAB ==================== */}
          {activeTab === 'url' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <ExternalLink className="w-7 h-7 text-yellow-400" /> URL Scanner
              </h2>
              
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter URL to scan (e.g., https://example.com/page)"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleURLAnalysis()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-yellow-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleURLAnalysis}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    Scan URL
                  </button>
                </div>
              </div>

              {apiData?.riskAssessment && (
                <div className="bg-gradient-to-r from-yellow-500/10 to-orange-500/10 border border-yellow-500/30 rounded-xl p-5">
                  <h3 className="font-semibold mb-3">Risk Assessment</h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <InfoCard label="Risk Score" value={`${apiData.data.riskAssessment.score}/10`} icon={<AlertTriangle className="w-4 h-4" />} alert={apiData.data.riskAssessment.score > 5} />
                    <InfoCard label="Risk Level" value={apiData.data.riskAssessment.level} icon={<Shield className="w-4 h-4" />} />
                    <InfoCard label="Category" value={apiData.data.riskAssessment.category || 'Unknown'} icon={<Tag className="w-4 h-4" />} />
                    <InfoCard label="Safe Browsing" value={apiData.data.riskAssessment.safeBrowsing || 'Not checked'} icon={<CheckCircle className="w-4 h-4" />} />
                  </div>
                  
                  {apiData.data.riskAssessment.indicators && (
                    <div className="mt-4">
                      <h4 className="text-sm font-medium mb-2">Indicators:</h4>
                      <div className="flex flex-wrap gap-2">
                        {apiData.data.riskAssessment.indicators.map((ind: string, idx: number) => (
                          <span key={idx} className="px-2 py-1 bg-gray-800 rounded text-xs">{ind}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <ExternalLink className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">URL Scanner Ready</h3>
                  <p className="text-gray-400">Enter a URL to analyze for security risks, malicious content, and reputation.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== HASH LOOKUP TAB ==================== */}
          {activeTab === 'hash' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Fingerprint className="w-7 h-7 text-cyan-400" /> Hash Lookup
              </h2>
              
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter hash (MD5, SHA-1, SHA-256)"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleHashLookup()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-cyan-500 focus:outline-none font-mono"
                    />
                  </div>
                  <button
                    onClick={handleHashLookup}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    Lookup Hash
                  </button>
                </div>
              </div>

              {apiData?.success && (
                <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-xl p-5">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-cyan-400" /> Hash Analysis Results
                  </h3>
                  {apiData.data ? (
                    <>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <InfoCard label="Hash Type" value={apiData.hashType || apiData.data.hashType || 'Detected'} icon={<Hash className="w-4 h-4" />} />
                        <InfoCard label="First Seen" value={apiData.data.firstSeen || 'Unknown'} icon={<Clock className="w-4 h-4" />} />
                        <InfoCard label="Last Seen" value={apiData.data.lastSeen || 'Unknown'} icon={<Clock className="w-4 h-4" />} />
                        <InfoCard label="File Type" value={apiData.data.fileType || 'Unknown'} icon={<FileText className="w-4 h-4" />} />
                        <InfoCard label="Signature" value={apiData.data.signature || 'Not found'} icon={<Bug className="w-4 h-4" />} alert={apiData.data.signature !== 'Not found'} />
                        <InfoCard label="Detection Ratio" value={apiData.data.detectionRatio || `${apiData.data.signature ? 1 : 0}/1`} icon={<Shield className="w-4 h-4" />} />
                      </div>
                      
                      {apiData.data.tags && (
                        <div className="mt-4 flex flex-wrap gap-2">
                          {apiData.data.tags.map((tag: string, idx: number) => (
                            <span key={idx} className="px-2 py-1 bg-gray-800 rounded text-xs">{tag}</span>
                          ))}
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="space-y-2">
                      <p className="text-sm text-gray-300">{apiData.message || 'Hash not found in malware databases. This could indicate a clean file or an unknown sample.'}</p>
                      {apiData.suggestions?.map((s: string, idx: number) => (
                        <p key={idx} className="text-xs text-gray-500">- {s}</p>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Fingerprint className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Hash Lookup Ready</h3>
                  <p className="text-gray-400">Look up file hashes against malware databases.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== CVE DATABASE TAB ==================== */}
          {activeTab === 'cve' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Shield className="w-7 h-7 text-orange-400" /> CVE Database (NIST NVD)
              </h2>
              
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter CVE ID (e.g., CVE-2024-2334) or keyword"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleCVESearch()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-orange-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleCVESearch}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-orange-600 hover:bg-orange-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    Search CVE
                  </button>
                </div>

                <div className="mt-4 flex flex-wrap gap-2">
                  <span className="text-xs text-gray-500">Recent Critical:</span>
                  {['CVE-2024-3400', 'CVE-2024-21887', 'CVE-2023-44428'].map(cve => (
                    <button
                      key={cve}
                      onClick={() => { setInputValue(cve); handleCVESearch(); }}
                      className="px-2 py-1 bg-red-500/10 text-red-400 rounded text-xs font-mono hover:bg-red-500/20"
                    >
                      {cve}
                    </button>
                  ))}
                </div>
              </div>

              {apiData?.vulnerabilities && (
                <div className="bg-gradient-to-r from-orange-500/10 to-red-500/10 border border-orange-500/30 rounded-xl p-5">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-orange-400" /> Vulnerability Details
                  </h3>
                  
                  {apiData.vulnerabilities.map((vuln: any, idx: number) => (
                    <div key={idx} className="mb-4 p-4 bg-gray-800/50 rounded-lg">
                      <div className="flex items-start justify-between mb-2">
                        <h4 className="font-mono font-bold text-lg">{vuln.id || vuln.cveId}</h4>
                        <span className={`px-2 py-1 rounded text-xs font-bold ${
                          (vuln.cvssScore || vuln.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore) >= 9 ? 'bg-red-500 text-white' :
                          (vuln.cvssScore || vuln.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore) >= 7 ? 'bg-orange-500 text-black' :
                          (vuln.cvssScore || vuln.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore) >= 4 ? 'bg-yellow-500 text-black' :
                          'bg-green-500 text-black'
                        }`}>
                          CVSS: {vuln.cvssScore || vuln.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || 'N/A'}
                        </span>
                      </div>
                      <p className="text-sm text-gray-300 mb-2">{vuln.description || vuln.descriptions?.[0]?.value || vuln.shortDescription}</p>
                      <div className="flex flex-wrap gap-2 text-xs">
                        {(vuln.weaknesses || vuln.cwes || []).map((cwe: any, i: number) => (
                          <span key={i} className="px-2 py-1 bg-gray-700 rounded">{cwe}</span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Shield className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">CVE Database Ready</h3>
                  <p className="text-gray-400">Search the NIST National Vulnerability Database for known vulnerabilities.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== AI ANALYST TAB ==================== */}
          {activeTab === 'ai' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Cpu className="w-7 h-7 text-pink-400" /> AI Threat Analyst
              </h2>
              
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter target for AI analysis (IP, domain, hash, etc.)"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleAIAnalysis()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-pink-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleAIAnalysis}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-pink-600 hover:bg-pink-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Cpu className="w-4 h-4" />}
                    Run AI Analysis
                  </button>
                </div>
              </div>

              {apiData?.analysis && (
                <div className="bg-gradient-to-r from-pink-500/10 to-purple-500/10 border border-pink-500/30 rounded-xl p-5">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <Cpu className="w-5 h-5 text-pink-400" /> AI Analysis Results
                  </h3>
                  
                  <div className="prose prose-invert max-w-none">
                    <p className="text-sm text-gray-300 whitespace-pre-wrap">{apiData.analysis.summary || apiData.analysis.analysis}</p>
                    
                    {apiData.analysis.recommendation && (
                      <div className="mt-4 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                        <h4 className="font-medium text-blue-400 mb-2">Recommendation</h4>
                        <p className="text-sm">{apiData.analysis.recommendation}</p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Cpu className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">AI Analyst Ready</h3>
                  <p className="text-gray-400">Enter any indicator for AI-powered threat analysis and recommendations.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== DARK WEB INTEL TAB ==================== */}
          {activeTab === 'darkweb' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Skull className="w-7 h-7 text-red-500" /> Dark Web Intelligence Engine
                <span className="text-sm font-normal text-gray-400">(Deep/Dark Web Search)</span>
              </h2>
              
              <div className="bg-gray-900 border border-red-500/30 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Search dark web (e.g., 'breaches', 'malware', 'credentials')"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleDarkWebSearch()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-red-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleDarkWebSearch}
                    disabled={loading}
                    className="px-6 py-3 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <EyeOff className="w-4 h-4" />}
                    Search Dark Web
                  </button>
                </div>

                <div className="mt-4 flex flex-wrap gap-2">
                  <span className="text-xs text-gray-500">Quick searches:</span>
                  {['breaches', 'malware', 'credentials', 'exploits', 'marketplaces', 'ransomware'].map(q => (
                    <button
                      key={q}
                      onClick={() => { setInputValue(q); handleDarkWebSearch(); }}
                      className="px-2 py-1 bg-red-500/10 text-red-400 rounded text-xs hover:bg-red-500/20 capitalize"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>

              {/* Dark Web Overview */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl">
                  <div className="flex items-center gap-2 text-red-400 mb-2">
                    <Skull className="w-5 h-5" /> Marketplaces
                  </div>
                  <div className="text-2xl font-bold">4+</div>
                  <div className="text-xs text-gray-500">Active markets tracked</div>
                </div>
                <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl">
                  <div className="flex items-center gap-2 text-orange-400 mb-2">
                    <AlertTriangle className="w-5 h-5" /> Breaches
                  </div>
                  <div className="text-2xl font-bold">4</div>
                  <div className="text-xs text-gray-500">Recent major breaches</div>
                </div>
                <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl">
                  <div className="flex items-center gap-2 text-purple-400 mb-2">
                    <Bug className="w-5 h-5" /> Malware
                  </div>
                  <div className="text-2xl font-bold">4</div>
                  <div className="text-xs text-gray-500">Trending families</div>
                </div>
                <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl">
                  <div className="flex items-center gap-2 text-yellow-400 mb-2">
                    <Users className="w-5 h-5" /> Forums
                  </div>
                  <div className="text-2xl font-bold">4</div>
                  <div className="text-xs text-gray-500">Monitored forums</div>
                </div>
              </div>

              {/* Search Results */}
              {apiData?.matches && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="font-semibold">Search Results ({apiData.matches.length})</h3>
                    {apiData.riskLevel && (
                      <div className="flex gap-2 text-xs">
                        <span className={`px-2 py-1 rounded ${
                          apiData.riskLevel === 'HIGH' ? 'bg-red-500/20 text-red-400' :
                          apiData.riskLevel === 'MEDIUM' ? 'bg-orange-500/20 text-orange-400' :
                          'bg-green-500/20 text-green-400'
                        }`}>
                          Risk: {apiData.riskLevel}
                        </span>
                      </div>
                    )}
                  </div>
                  
                  {apiData.matches.map((result: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-4 rounded-lg border bg-gray-900 border-gray-800"
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <h4 className="font-medium flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 text-red-400" />
                            {result.source}
                          </h4>
                          <p className="text-sm text-gray-400 mt-1">{result.found}</p>
                        </div>
                        <span className={`px-2 py-1 rounded text-xs font-bold ${
                          result.relevance === 'HIGH' ? 'bg-red-500 text-white' :
                          result.relevance === 'MEDIUM' ? 'bg-orange-500 text-black' :
                          'bg-gray-700'
                        }`}>
                          {result.relevance}
                        </span>
                      </div>
                      <div className="mt-2 flex items-center gap-4 text-xs text-gray-500">
                        <span>Source: {result.source}</span>
                        <span>Date: {result.date}</span>
                      </div>
                    </div>
                  ))}

                  {/* Recommendations */}
                  {apiData.recommendations && (
                    <div className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Shield className="w-5 h-5 text-purple-400" /> Recommended Actions
                      </h3>
                      <ul className="space-y-1">
                        {apiData.recommendations.map((action: string, idx: number) => (
                          <li key={idx} className="text-sm flex items-start gap-2">
                            <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 shrink-0" />
                            {action}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Skull className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Dark Web Search Engine</h3>
                  <p className="text-gray-400 mb-4">Search for threats, breaches, malware, and intelligence from dark web sources.</p>
                  <button onClick={() => handleDarkWebSearch()} className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg">
                    Show Latest Intelligence
                  </button>
                </div>
              )}
            </div>
          )}

          {/* ==================== MOBILE SECURITY TAB ==================== */}
          {activeTab === 'mobile' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Smartphone className="w-7 h-7 text-indigo-400" /> Mobile Security Analysis
                <span className="text-sm font-normal text-gray-400">(MobSF-style)</span>
              </h2>
              
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter APK/IPA filename (e.g., app.apk, app.ipa)"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleMobileAnalysis()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-indigo-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleMobileAnalysis}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Smartphone className="w-4 h-4" />}
                    Analyze App
                  </button>
                </div>

                <div className="mt-4 flex flex-wrap gap-2">
                  <span className="text-xs text-gray-500">Supported:</span>
                  {['APK (Android)', 'IPA (iOS)', 'APPX (Windows)'].map(fmt => (
                    <span key={fmt} className="px-2 py-1 bg-indigo-500/10 text-indigo-400 rounded text-xs">{fmt}</span>
                  ))}
                </div>
              </div>

              {/* Mobile Analysis Results */}
              {apiData?.data && (
                <div className="space-y-4">
                  {/* Risk Score Card */}
                  <div className={`rounded-xl p-5 border ${
                    apiData.data.securityAnalysis?.riskLevel === 'MALICIOUS' ? 'bg-red-500/10 border-red-500/50' :
                    apiData.data.securityAnalysis?.riskLevel === 'HIGH' ? 'bg-orange-500/10 border-orange-500/50' :
                    apiData.data.securityAnalysis?.riskLevel === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/50' :
                    'bg-green-500/10 border-green-500/50'
                  }`}>
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-semibold">Security Risk Assessment</h3>
                        <p className="text-sm text-gray-400 mt-1">{apiData.data.fileName}</p>
                      </div>
                      <div className="text-right">
                        <div className="text-3xl font-bold">
                          {apiData.data.securityAnalysis?.malwareScore || 0}/100
                        </div>
                        <div className={`text-sm font-bold ${
                          apiData.data.securityAnalysis?.riskLevel === 'SAFE' ? 'text-green-400' :
                          apiData.data.securityAnalysis?.riskLevel === 'LOW_RISK' ? 'text-blue-400' :
                          apiData.data.securityAnalysis?.riskLevel === 'MEDIUM' ? 'text-yellow-400' :
                          apiData.data.securityAnalysis?.riskLevel === 'HIGH' ? 'text-orange-400' :
                          'text-red-400'
                        }`}>
                          {apiData.data.securityAnalysis?.riskLevel}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* App Info Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <InfoCard label="Package/Bundle" value={apiData.data.basicInfo?.packageName || apiData.data.basicInfo?.bundleId || 'N/A'} icon={<Package className="w-4 h-4" />} />
                    <InfoCard label="Version" value={apiData.data.basicInfo?.versionName || apiData.data.basicInfo?.platformVersion || 'N/A'} icon={<Tag className="w-4 h-4" />} />
                    <InfoCard label="File Size" value={apiData.data.fileSize || 'N/A'} icon={<Database className="w-4 h-4" />} />
                    <InfoCard label="SHA256" value={apiData.data.sha256?.substring(0, 16) + '...' || 'N/A'} icon={<Hash className="w-4 h-4" />} />
                  </div>

                  {/* Permissions */}
                  {apiData.data.permissions && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Lock className="w-5 h-5 text-yellow-400" /> Permissions Analysis
                        <span className="text-xs bg-yellow-500/20 text-yellow-400 px-2 py-0.5 rounded">
                          {apiData.data.permissions.total} total
                        </span>
                      </h3>
                      
                      {apiData.data.permissions.dangerous?.length > 0 && (
                        <div className="mb-3">
                          <h4 className="text-sm font-medium text-red-400 mb-2">Dangerous ({apiData.data.permissions.dangerous.length})</h4>
                          <div className="flex flex-wrap gap-1">
                            {apiData.data.permissions.dangerous.map((perm: string, idx: number) => (
                              <span key={idx} className="px-2 py-1 bg-red-500/10 text-red-400 rounded text-xs font-mono">
                                {perm.split('.').pop()}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Security Findings */}
                  {apiData.data.securityAnalysis?.findings && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <ShieldAlert className="w-5 h-5 text-orange-400" /> Security Findings
                      </h3>
                      <div className="space-y-2">
                        {apiData.data.securityAnalysis.findings.map((finding: any, idx: number) => (
                          <div
                            key={idx}
                            className={`p-3 rounded-lg ${
                              finding.severity === 'CRITICAL' ? 'bg-red-500/10 border-l-2 border-red-500' :
                              finding.severity === 'HIGH' ? 'bg-orange-500/10 border-l-2 border-orange-500' :
                              finding.severity === 'MEDIUM' ? 'bg-yellow-500/10 border-l-2 border-yellow-500' :
                              'bg-gray-800'
                            }`}
                          >
                            <div className="flex items-start justify-between">
                              <div>
                                <span className={`text-xs font-bold uppercase ${
                                  finding.severity === 'CRITICAL' ? 'text-red-400' :
                                  finding.severity === 'HIGH' ? 'text-orange-400' :
                                  finding.severity === 'MEDIUM' ? 'text-yellow-400' :
                                  'text-gray-400'
                                }`}>
                                  {finding.severity}
                                </span>
                                <span className="text-sm ml-2">{finding.description}</span>
                              </div>
                            </div>
                            <p className="text-xs text-gray-400 mt-1">{finding.recommendation}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Network Analysis */}
                  {apiData.data.networkAnalysis && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Wifi className="w-5 h-5 text-cyan-400" /> Network Endpoints
                      </h3>
                      <div className="flex flex-wrap gap-2">
                        {apiData.data.networkAnalysis.domains?.map((domain: string, idx: number) => (
                          <span key={idx} className="px-2 py-1 bg-gray-800 rounded text-xs font-mono">{domain}</span>
                        ))}
                      </div>
                      {apiData.data.networkAnalysis.hasHttpTraffic && (
                        <div className="mt-2 p-2 bg-red-500/10 rounded text-xs text-red-400">
                          Warning: App sends data over unencrypted HTTP
                        </div>
                      )}
                    </div>
                  )}

                  {/* AI Assessment */}
                  {apiData.data.aiAssessment && (
                    <div className="bg-gradient-to-r from-indigo-500/10 to-purple-500/10 border border-indigo-500/30 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Cpu className="w-5 h-5 text-indigo-400" /> AI Assessment
                      </h3>
                      <p className="text-sm text-gray-300 mb-2">{apiData.data.aiAssessment.summary}</p>
                      <div className="inline-block px-3 py-1 bg-indigo-500/20 text-indigo-400 rounded-full text-sm font-bold">
                        Verdict: {apiData.data.aiAssessment.verdict}
                      </div>
                      <div className="mt-3">
                        <h4 className="text-sm font-medium text-green-400 mb-1">Recommendations:</h4>
                        <ul className="space-y-1">
                          {apiData.data.aiAssessment.recommendations?.map((rec: string, idx: number) => (
                            <li key={idx} className="text-sm flex items-start gap-2">
                              <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 shrink-0" />
                              {rec}
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Smartphone className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Mobile Security Analyzer</h3>
                  <p className="text-gray-400 mb-4">Analyze Android APKs and iOS IPA files for security issues. Similar to MobSF.</p>
                  <div className="flex justify-center gap-2">
                    {['malicious.apk', 'banking.app', 'game.apk'].map(app => (
                      <button
                        key={app}
                        onClick={() => { setInputValue(app); handleMobileAnalysis(); }}
                        className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded text-xs"
                      >
                        Try {app}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ==================== THREAT FEEDS TAB ==================== */}
          {activeTab === 'threats' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <AlertTriangle className="w-7 h-7 text-amber-400" /> Live Threat Feeds
              </h2>
              
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex flex-wrap gap-3">
                  <button
                    onClick={() => handleThreatFeedLoad()}
                    disabled={loading}
                    className="px-4 py-2 bg-amber-600 hover:bg-amber-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                    Load All Feeds
                  </button>
                  <button onClick={() => handleThreatFeedLoad('cisa')} disabled={loading} className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm">
                    CISA KEV
                  </button>
                  <button onClick={() => handleThreatFeedLoad('malwaredl')} disabled={loading} className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm">
                    MalwareBazaar
                  </button>
                  <button onClick={() => handleThreatFeedLoad('abusech')} disabled={loading} className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm">
                    AbuseCH SSLBL
                  </button>
                </div>
              </div>

              {apiData?.feeds && (
                <div className="space-y-4">
                  {apiData.feeds.map((feed: any, idx: number) => (
                    <div key={idx} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="font-semibold flex items-center gap-2">
                          <AlertTriangle className="w-5 h-5 text-amber-400" />
                          {feed.source}
                          <span className="text-xs bg-amber-500/20 text-amber-400 px-2 py-0.5 rounded">
                            {feed.count} items
                          </span>
                        </h3>
                        <span className={`text-xs px-2 py-0.5 rounded ${
                          feed.status === 'active' ? 'bg-green-500/20 text-green-400' : 'bg-gray-700'
                        }`}>
                          {feed.status}
                        </span>
                      </div>
                      
                      {feed.entries && (
                        <div className="overflow-x-auto">
                          <table className="w-full text-sm">
                            <thead>
                              <tr className="border-b border-gray-800">
                                <th className="text-left py-2 px-2 text-gray-400">ID/Name</th>
                                <th className="text-left py-2 px-2 text-gray-400">Details</th>
                                <th className="text-left py-2 px-2 text-gray-400">Date</th>
                              </tr>
                            </thead>
                            <tbody>
                              {feed.entries.slice(0, 5).map((entry: any, eIdx: number) => (
                                <tr key={eIdx} className="border-b border-gray-800 hover:bg-gray-800">
                                  <td className="py-2 px-2 font-mono text-xs">
                                    {entry.cveID || entry.sha256_hash || entry.sha256_fingerprint || entry.name || '-'}
                                  </td>
                                  <td className="py-2 px-2 text-xs">{entry.shortDescription || entry.signature || entry.listing_reason || '-'}</td>
                                  <td className="py-2 px-2 text-xs text-gray-500">{entry.dateAdded || entry.first_seen || '-'}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <AlertTriangle className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Threat Feeds</h3>
                  <p className="text-gray-400">Click a button above to load threat intelligence from various sources.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== IOC MANAGER TAB ==================== */}
          {activeTab === 'iocs' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Database className="w-7 h-7 text-emerald-400" /> IOC Manager
                </h2>
                <button
                  onClick={() => { setModalType('add'); setFormData({ type: 'IP', value: '', description: '', severity: 'MEDIUM', status: 'UNKNOWN', tags: [] }); setShowModal(true); }}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 rounded-lg font-medium flex items-center gap-2"
                >
                  <Plus className="w-4 h-4" /> Add IOC
                </button>
              </div>

              {/* Filters */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <div className="flex flex-wrap gap-4">
                  <div className="flex-1 min-w-[200px]">
                    <input
                      type="text"
                      placeholder="Search IOCs..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm"
                    />
                  </div>
                  <select className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm">
                    <option>All Types</option>
                    <option>IP</option>
                    <option>DOMAIN</option>
                    <option>URL</option>
                    <option>HASH</option>
                  </select>
                  <select className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm">
                    <option>All Severities</option>
                    <option>CRITICAL</option>
                    <option>HIGH</option>
                    <option>MEDIUM</option>
                  </select>
                  <button onClick={loadIOCs} className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm">
                    <Search className="w-4 h-4 inline mr-1" /> Search
                  </button>
                </div>
              </div>

              {/* IOC Table */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-gray-800">
                    <tr>
                      <th className="text-left py-3 px-4 text-gray-400">Type</th>
                      <th className="text-left py-3 px-4 text-gray-400">Value</th>
                      <th className="text-left py-3 px-4 text-gray-400">Severity</th>
                      <th className="text-left py-3 px-4 text-gray-400">Status</th>
                      <th className="text-left py-3 px-4 text-gray-400">Source</th>
                      <th className="text-right py-3 px-4 text-gray-400">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {iocs.map((ioc) => (
                      <tr key={ioc.id} className="border-t border-gray-800 hover:bg-gray-800/50">
                        <td className="py-3 px-4">
                          <span className="px-2 py-1 bg-gray-700 rounded text-xs">{ioc.type}</span>
                        </td>
                        <td className="py-3 px-4 font-mono text-sm">{ioc.value}</td>
                        <td className="py-3 px-4">
                          <span style={{ color: SEVERITY_COLORS[ioc.severity] }} className="font-medium">
                            {ioc.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span style={{ color: STATUS_COLORS[ioc.status] }} className="font-medium">
                            {ioc.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-gray-400 text-xs">{ioc.source || '-'}</td>
                        <td className="py-3 px-4 text-right">
                          <button onClick={() => openDetailModal(ioc)} className="p-1 hover:bg-gray-700 rounded mr-1">
                            <Eye className="w-4 h-4" />
                          </button>
                          <button onClick={() => openEditModal(ioc)} className="p-1 hover:bg-gray-700 rounded mr-1">
                            <Edit3 className="w-4 h-4" />
                          </button>
                          <button onClick={() => handleDeleteIOC(ioc.id)} className="p-1 hover:bg-gray-700 rounded text-red-400">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                
                {iocs.length === 0 && (
                  <div className="text-center py-12 text-gray-500">
                    <Database className="w-12 h-12 mx-auto mb-2 opacity-50" />
                    <p>No IOCs found. Add your first IOC or analyze an IP/domain!</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ==================== EXPORT TAB ==================== */}
          {activeTab === 'export' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Download className="w-7 h-7 text-teal-400" /> Export Data
              </h2>
              
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h3 className="font-semibold mb-3">Export Format</h3>
                    <div className="space-y-2">
                      <button
                        onClick={() => handleExport('json')}
                        className="w-full p-4 bg-gray-800 hover:bg-gray-700 rounded-lg flex items-center gap-3 transition-colors"
                      >
                        <FileCode className="w-6 h-6 text-blue-400" />
                        <div className="text-left">
                          <div className="font-medium">JSON Export</div>
                          <div className="text-xs text-gray-400">Full data with metadata</div>
                        </div>
                      </button>
                      <button
                        onClick={() => handleExport('csv')}
                        className="w-full p-4 bg-gray-800 hover:bg-gray-700 rounded-lg flex items-center gap-3 transition-colors"
                      >
                        <DownloadCloud className="w-6 h-6 text-green-400" />
                        <div className="text-left">
                          <div className="font-medium">CSV Export</div>
                          <div className="text-xs text-gray-400">Spreadsheet compatible</div>
                        </div>
                      </button>
                    </div>
                  </div>
                  
                  <div>
                    <h3 className="font-semibold mb-3">Export Summary</h3>
                    <div className="p-4 bg-gray-800 rounded-lg">
                      <p className="text-sm text-gray-400">
                        Total IOCs: <strong className="text-white">{iocs.length}</strong>
                      </p>
                      <p className="text-sm text-gray-400 mt-2">
                        Formats available: JSON, CSV, STIX, TAXII
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ==================== INTELLIGENCE SOURCES TAB ==================== */}
          {activeTab === 'sources' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Wifi className="w-7 h-7 text-sky-400" /> Intelligence Sources
              </h2>

              {/* Add Source Form */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <h3 className="font-semibold mb-3">Add Custom Intelligence Source</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  <input
                    type="text"
                    placeholder="Source name (e.g., My Threat Feed)"
                    value={newSource.name}
                    onChange={(e) => setNewSource(prev => ({ ...prev, name: e.target.value }))}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                  />
                  <select
                    value={newSource.type}
                    onChange={(e) => setNewSource(prev => ({ ...prev, type: e.target.value }))}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                  >
                    {['THREAT_FEED', 'GEO_IP', 'DNS', 'CVE', 'REPUTATION', 'BREACH', 'AI', 'CUSTOM'].map(t => (
                      <option key={t} value={t}>{t.replace('_', ' ')}</option>
                    ))}
                  </select>
                  <select
                    value={newSource.method}
                    onChange={(e) => setNewSource(prev => ({ ...prev, method: e.target.value }))}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                  </select>
                  <input
                    type="text"
                    placeholder="Endpoint URL"
                    value={newSource.endpoint}
                    onChange={(e) => setNewSource(prev => ({ ...prev, endpoint: e.target.value }))}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg lg:col-span-2"
                  />
                  <input
                    type="text"
                    placeholder="API key env var (optional)"
                    value={newSource.apiKeyEnv}
                    onChange={(e) => setNewSource(prev => ({ ...prev, apiKeyEnv: e.target.value }))}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                  />
                  <input
                    type="text"
                    placeholder="Description"
                    value={newSource.description}
                    onChange={(e) => setNewSource(prev => ({ ...prev, description: e.target.value }))}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg lg:col-span-2"
                  />
                  <button
                    onClick={handleAddSource}
                    className="px-4 py-2 bg-sky-600 hover:bg-sky-700 rounded-lg font-medium flex items-center justify-center gap-2"
                  >
                    <Plus className="w-4 h-4" /> Add Source
                  </button>
                </div>
              </div>

              {/* Sources List */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold">Registered Sources ({sources.length})</h3>
                  <button onClick={loadSources} className="p-2 hover:bg-gray-800 rounded-lg" title="Refresh">
                    <RefreshCw className="w-4 h-4" />
                  </button>
                </div>

                {sources.length === 0 ? (
                  <p className="text-sm text-gray-500">No sources found.</p>
                ) : (
                  <div className="space-y-2">
                    {sources.map((source: any) => {
                      const health = sourceHealth.find((h: any) => h.id === source.id);
                      return (
                        <div key={source.id} className="flex items-center gap-3 p-3 bg-gray-800/60 rounded-lg">
                          <span className={`w-2 h-2 rounded-full shrink-0 ${source.enabled ? 'bg-green-500' : 'bg-gray-500'}`}></span>
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium truncate">{source.name}</div>
                            <div className="text-xs text-gray-500">
                              {source.type} • {source.method} {source.endpoint}
                            </div>
                            {health && (
                              <div className={`text-xs mt-0.5 ${health.ok ? 'text-green-500' : 'text-red-500'}`}>
                                {health.ok ? `Healthy (HTTP ${health.status || 200})` : health.message}
                              </div>
                            )}
                          </div>
                          <div className="flex gap-1">
                            <button onClick={() => handleTestSource(source.id)} className="p-2 hover:bg-gray-700 rounded-lg" title="Test connectivity">
                              <Zap className="w-4 h-4" />
                            </button>
                            <button onClick={() => handleToggleSource(source)} className="p-2 hover:bg-gray-700 rounded-lg" title={source.enabled ? 'Disable' : 'Enable'}>
                              {source.enabled ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ==================== REPORTS TAB ==================== */}
          {activeTab === 'reports' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <FileText className="w-7 h-7 text-violet-400" /> Report Generator
              </h2>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Report Configuration */}
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
                  <h3 className="font-semibold">Configuration</h3>
                  
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Report Title *</label>
                    <input
                      type="text"
                      placeholder="Enter report title..."
                      value={reportConfig.title}
                      onChange={(e) => setReportConfig(prev => ({ ...prev, title: e.target.value }))}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                    />
                  </div>

                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Format</label>
                    <select
                      value={reportConfig.format}
                      onChange={(e) => setReportConfig(prev => ({ ...prev, format: e.target.value }))}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                    >
                      <option value="PDF">PDF Report</option>
                      <option value="JSON">JSON Data</option>
                      <option value="CSV">CSV Spreadsheet</option>
                      <option value="HTML">HTML Interactive</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm text-gray-400 mb-2">Select Modules to Include</label>
                    <div className="grid grid-cols-2 gap-2">
                      {[
                        { id: 'dashboard', label: 'Dashboard Stats' },
                        { id: 'ip', label: 'IP Intelligence' },
                        { id: 'domain', label: 'Domain Intel' },
                        { id: 'forensics', label: 'Forensics Data' },
                        { id: 'cve', label: 'CVE Database' },
                        { id: 'darkweb', label: 'Dark Web Intel' },
                        { id: 'mobile', label: 'Mobile Security' },
                        { id: 'threats', label: 'Threat Feeds' },
                        { id: 'iocs', label: 'IOC List' },
                        { id: 'ai', label: 'AI Analysis' },
                      ].map(mod => (
                        <label key={mod.id} className="flex items-center gap-2 p-2 bg-gray-800 rounded cursor-pointer hover:bg-gray-700">
                          <input
                            type="checkbox"
                            checked={reportConfig.modules.includes(mod.id)}
                            onChange={() => toggleReportModule(mod.id)}
                            className="rounded"
                          />
                          <span className="text-sm">{mod.label}</span>
                        </label>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={reportConfig.executiveSummary}
                        onChange={(e) => setReportConfig(prev => ({ ...prev, executiveSummary: e.target.checked }))}
                        className="rounded"
                      />
                      <span className="text-sm">Include Executive Summary</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={reportConfig.recommendations}
                        onChange={(e) => setReportConfig(prev => ({ ...prev, recommendations: e.target.checked }))}
                        className="rounded"
                      />
                      <span className="text-sm">Include Recommendations</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={reportConfig.includeTimeline}
                        onChange={(e) => setReportConfig(prev => ({ ...prev, includeTimeline: e.target.checked }))}
                        className="rounded"
                      />
                      <span className="text-sm">Include Timeline</span>
                    </label>
                  </div>

                  <button
                    onClick={handleGenerateReport}
                    disabled={loading || !reportConfig.title || reportConfig.modules.length === 0}
                    className="w-full py-3 bg-violet-600 hover:bg-violet-700 disabled:opacity-50 rounded-lg font-medium flex items-center justify-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4" />}
                    Generate Report
                  </button>
                </div>

                {/* Report Preview / Templates */}
                <div className="space-y-4">
                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                    <h3 className="font-semibold mb-3">Quick Templates</h3>
                    <div className="space-y-2">
                      {[
                        { name: 'Executive Summary', desc: 'For leadership', modules: ['dashboard', 'iocs', 'threats'] },
                        { name: 'Technical Analysis', desc: 'For analysts', modules: ['ip', 'domain', 'url', 'hash', 'cve'] },
                        { name: 'Threat Hunt', desc: 'For hunters', modules: ['darkweb', 'threats', 'ai'] },
                        { name: 'Comprehensive', desc: 'Full audit', modules: ['dashboard', 'ip', 'domain', 'forensics', 'cve', 'darkweb', 'threats', 'iocs', 'mobile'] },
                      ].map(template => (
                        <button
                          key={template.name}
                          onClick={() => setReportConfig(prev => ({
                            ...prev,
                            title: template.name + ' Report',
                            modules: template.modules
                          }))}
                          className="w-full p-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-left transition-colors"
                        >
                          <div className="font-medium text-sm">{template.name}</div>
                          <div className="text-xs text-gray-400">{template.desc} • {template.modules.length} modules</div>
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Generated Report Display */}
                  {apiData?.content && (
                    <div className="bg-gradient-to-r from-violet-500/10 to-purple-500/10 border border-violet-500/30 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <CheckCircle className="w-5 h-5 text-violet-400" /> Report Generated
                      </h3>
                      
                      {apiData.content.executiveSummary && (
                        <div className="mb-4 p-4 bg-gray-800/50 rounded-lg">
                          <h4 className="text-sm font-medium text-violet-400 mb-2">Executive Summary</h4>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
                            <div>
                              <div className="text-2xl font-bold">{apiData.content.executiveSummary.totalIndicators || 0}</div>
                              <div className="text-xs text-gray-400">Total IOCs</div>
                            </div>
                            <div>
                              <div className="text-2xl font-bold text-red-400">{apiData.content.executiveSummary.criticalItems || 0}</div>
                              <div className="text-xs text-gray-400">Critical</div>
                            </div>
                            <div>
                              <div className="text-2xl font-bold text-orange-400">{apiData.content.executiveSummary.highRiskItems || 0}</div>
                              <div className="text-xs text-gray-400">High Risk</div>
                            </div>
                            <div>
                              <div className="text-2xl font-bold text-violet-400">{apiData.content.statistics?.modulesIncluded || 0}</div>
                              <div className="text-xs text-gray-400">Modules</div>
                            </div>
                          </div>
                        </div>
                      )}

                      {apiData.content.recommendations && (
                        <div>
                          <h4 className="text-sm font-medium text-green-400 mb-2">Recommendations</h4>
                          <ul className="space-y-1">
                            {apiData.content.recommendations.slice(0, 5).map((rec: string, idx: number) => (
                              <li key={idx} className="text-sm flex items-start gap-2">
                                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 shrink-0" />
                                {rec}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>

              {/* Generated Reports History */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <h3 className="font-semibold mb-4 flex items-center gap-2">
                  <FolderOpen className="w-4 h-4 text-violet-400" /> Generated Reports
                  <span className="text-xs text-gray-500 ml-auto">{reports.length} saved</span>
                </h3>
                {reports.length === 0 ? (
                  <p className="text-sm text-gray-500">No reports generated yet. Configure a report above and click Generate.</p>
                ) : (
                  <div className="space-y-2">
                    {reports.map((report: any) => (
                      <div key={report.id} className="flex items-center gap-3 p-3 bg-gray-800/60 rounded-lg">
                        <FileText className="w-4 h-4 text-violet-400 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium truncate">{report.title}</div>
                          <div className="text-xs text-gray-500">
                            {new Date(report.createdAt || report.timestamp).toLocaleString()} • {report.modules?.length || 0} modules
                          </div>
                        </div>
                        <div className="flex gap-1">
                          <a href={`/api/osint/reports?action=download&id=${report.id}&format=pdf`} target="_blank" rel="noreferrer" className="p-2 hover:bg-gray-700 rounded-lg" title="Download PDF">
                            <FileText className="w-4 h-4 text-red-400" />
                          </a>
                          <a href={`/api/osint/reports?action=download&id=${report.id}&format=docx`} target="_blank" rel="noreferrer" className="p-2 hover:bg-gray-700 rounded-lg" title="Download DOCX">
                            <FileText className="w-4 h-4 text-blue-400" />
                          </a>
                          <a href={`/api/osint/reports?action=download&id=${report.id}&format=pptx`} target="_blank" rel="noreferrer" className="p-2 hover:bg-gray-700 rounded-lg" title="Download PPTX">
                            <Presentation className="w-4 h-4 text-orange-400" />
                          </a>
                          <a href={`/api/osint/reports?action=download&id=${report.id}&format=json`} target="_blank" rel="noreferrer" className="p-2 hover:bg-gray-700 rounded-lg" title="Download JSON">
                            <DownloadCloud className="w-4 h-4" />
                          </a>
                          <a href={`/api/osint/reports?action=download&id=${report.id}&format=csv`} target="_blank" rel="noreferrer" className="p-2 hover:bg-gray-700 rounded-lg" title="Download CSV">
                            <FileCode className="w-4 h-4" />
                          </a>
                          <a href={`/api/osint/reports?action=download&id=${report.id}&format=html`} target="_blank" rel="noreferrer" className="p-2 hover:bg-gray-700 rounded-lg" title="Open HTML report">
                            <ExternalLink className="w-4 h-4" />
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ==================== BRAND PROTECTION TAB ==================== */}
          {activeTab === 'brand' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Shield className="w-7 h-7 text-rose-400" /> Brand Protection
                <span className="text-sm font-normal text-gray-400">(Phishing & impersonation monitoring)</span>
              </h2>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input type="text" placeholder="Suspicious URL or domain (e.g., paypal-secure-login.top)"
                      value={inputValue} onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleBrandScan()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-rose-500 focus:outline-none" />
                  </div>
                  <button onClick={handleBrandScan} disabled={loading} className="px-6 py-3 bg-rose-600 hover:bg-rose-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2">
                    <Search className="w-4 h-4" /> Scan Candidate
                  </button>
                  <button onClick={handleBrandWatchlist} disabled={loading} className="px-4 py-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm flex items-center gap-2">
                    <Plus className="w-4 h-4" /> Add Brand
                  </button>
                </div>
              </div>

              {apiData?.data?.phishing && (
                <div className="space-y-4">
                  <div className={`rounded-xl p-5 border ${
                    apiData.data.phishing.verdict === 'HIGH' ? 'bg-red-500/10 border-red-500/50' :
                    apiData.data.phishing.verdict === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/50' : 'bg-green-500/10 border-green-500/50'
                  }`}>
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-semibold">Phishing Risk Assessment</h3>
                        <p className="text-sm text-gray-400 mt-1">{apiData.data.candidate} vs brand "{apiData.data.brand}"</p>
                      </div>
                      <div className="text-right">
                        <div className="text-3xl font-bold">{apiData.data.phishing.score}/15</div>
                        <div className="text-sm font-bold">{apiData.data.phishing.verdict}</div>
                      </div>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {apiData.data.phishing.reasons.map((r: string, i: number) => (
                        <span key={i} className="px-2 py-1 bg-gray-800 rounded text-xs">{r}</span>
                      ))}
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-red-400" /> Lookalike Domains</h3>
                    <div className="flex flex-wrap gap-2">
                      {(apiData.lookalikes || []).map((d: string, i: number) => (
                        <button key={i} onClick={() => setInputValue(d)} className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded text-xs font-mono">{d}</button>
                      ))}
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2"><Skull className="w-5 h-5 text-red-500" /> Suspected Phishing Kits</h3>
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead><tr className="border-b border-gray-800 text-left text-gray-400">
                          <th className="py-2 px-2">Name</th><th className="py-2 px-2">Platform</th><th className="py-2 px-2">IOC</th>
                        </tr></thead>
                        <tbody>
                          {(apiData.kits || []).map((k: any, i: number) => (
                            <tr key={i} className="border-b border-gray-800">
                              <td className="py-2 px-2 font-medium">{k.name}</td>
                              <td className="py-2 px-2 text-xs">{k.platform}</td>
                              <td className="py-2 px-2 font-mono text-xs text-red-400">{k.ioc}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}
              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Shield className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Brand Protection Ready</h3>
                  <p className="text-gray-400">Scan suspected phishing URLs and domains, discover lookalikes and phishing kits targeting your brand.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== URL SANDBOX TAB ==================== */}
          {activeTab === 'sandbox' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Zap className="w-7 h-7 text-lime-400" /> URL Sandbox
                <span className="text-sm font-normal text-gray-400">(tria.ge / Hybrid-Analysis style)</span>
              </h2>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input type="text" placeholder="URL to detonate (e.g., http://evil-site.top/verify.php)"
                      value={inputValue} onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleSandbox()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-lime-500 focus:outline-none" />
                  </div>
                  <button onClick={handleSandbox} disabled={loading} className="px-6 py-3 bg-lime-600 hover:bg-lime-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2">
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />} Detonate
                  </button>
                </div>
              </div>

              {apiData?.data?.verdict && (
                <div className="space-y-4">
                  <div className={`rounded-xl p-5 border ${
                    apiData.data.verdict === 'MALICIOUS' ? 'bg-red-500/10 border-red-500/50' :
                    apiData.data.verdict === 'SUSPICIOUS' ? 'bg-yellow-500/10 border-yellow-500/50' : 'bg-green-500/10 border-green-500/50'
                  }`}>
                    <div className="flex items-center justify-between">
                      <div><h3 className="font-semibold">Sandbox Verdict</h3><p className="text-sm text-gray-400 mt-1 font-mono">{apiData.data.url}</p></div>
                      <div className="text-right"><div className="text-3xl font-bold">{apiData.data.score}/100</div><div className="text-sm font-bold">{apiData.data.verdict}</div></div>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {(apiData.data.staticAnalysis?.flags || []).map((f: any, i: number) => (
                        <span key={i} className="px-2 py-1 bg-gray-800 rounded text-xs">{f.label}</span>
                      ))}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Terminal className="w-5 h-5 text-lime-400" /> Behavioral Detonation</h3>
                      <div className="space-y-2">
                        {(apiData.data.behavioral?.processes || []).map((p: any, i: number) => (
                          <div key={i} className="flex items-center gap-3 p-2 bg-gray-800/60 rounded-lg text-xs font-mono">
                            <span className={p.severity === 'HIGH' ? 'text-red-400' : 'text-gray-400'}>{p.name}</span>
                            <span className="text-gray-500">{p.action}</span>
                            <span className="ml-auto truncate text-gray-400">{p.target}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Bug className="w-5 h-5 text-red-400" /> AV Signatures</h3>
                      <div className="space-y-2">
                        {(apiData.data.behavioral?.signatures || []).map((s: any, i: number) => (
                          <div key={i} className={`p-2 rounded-lg text-xs ${s.severity === 'HIGH' ? 'bg-red-500/10 text-red-300' : s.severity === 'MEDIUM' ? 'bg-yellow-500/10 text-yellow-300' : 'bg-gray-800 text-gray-400'}`}>
                            <strong>{s.name}</strong> <span className="text-gray-500">— {s.category}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {apiData.data.behavioral?.network && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Network className="w-5 h-5 text-cyan-400" /> Network Connections</h3>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead><tr className="border-b border-gray-800 text-left text-gray-400"><th className="py-2 px-2">Target</th><th className="py-2 px-2">Port</th><th className="py-2 px-2">Proto</th><th className="py-2 px-2">State</th></tr></thead>
                          <tbody>
                            {(apiData.data.behavioral.network.connections || []).map((c: any, i: number) => (
                              <tr key={i} className="border-b border-gray-800">
                                <td className="py-2 px-2 font-mono text-xs">{c.target}</td><td className="py-2 px-2">{c.port}</td><td className="py-2 px-2">{c.protocol}</td><td className="py-2 px-2">{c.state}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              )}
              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Zap className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">URL Sandbox Ready</h3>
                  <p className="text-gray-400">Detonate suspicious URLs to reveal phishing kits, payload delivery and malicious indicators.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== DNS DUMP TAB ==================== */}
          {activeTab === 'dnsdump' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Network className="w-7 h-7 text-teal-400" /> DNS Dump
                <span className="text-sm font-normal text-gray-400">(dnsdumpster.com style enumeration)</span>
              </h2>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input type="text" placeholder="Domain to enumerate (e.g., example.com)"
                      value={inputValue} onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleDnsDump()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-teal-500 focus:outline-none" />
                  </div>
                  <button onClick={handleDnsDump} disabled={loading} className="px-6 py-3 bg-teal-600 hover:bg-teal-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2">
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} Enumerate
                  </button>
                </div>
              </div>

              {apiData?.data?.records && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                    {Object.entries(apiData.data.records).map(([type, recs]: [string, any]) => (
                      <div key={type} className="p-3 bg-gray-900 border border-gray-800 rounded-xl">
                        <div className="text-sm font-bold text-teal-400">{type}</div>
                        <div className="text-2xl font-bold">{recs?.length || 0}</div>
                        <div className="text-xs text-gray-500">records</div>
                      </div>
                    ))}
                  </div>

                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2"><Server className="w-5 h-5 text-purple-400" /> Subdomains Found ({apiData.data.subdomains?.length || 0})</h3>
                    <div className="flex flex-wrap gap-2">
                      {(apiData.data.subdomains || []).map((s: string, i: number) => (
                        <span key={i} className="px-2 py-1 bg-gray-800 rounded text-xs font-mono">{s}</span>
                      ))}
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2"><ExternalLink className="w-5 h-5 text-cyan-400" /> Related Hosts</h3>
                    <div className="flex flex-wrap gap-2">
                      {(apiData.data.relatedHosts || []).slice(0, 20).map((h: string, i: number) => (
                        <span key={i} className="px-2 py-1 bg-gray-800 rounded text-xs font-mono text-cyan-300">{h}</span>
                      ))}
                    </div>
                  </div>

                  {(apiData.data.security?.findings?.length > 0) && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><ShieldAlert className="w-5 h-5 text-orange-400" /> Security Findings</h3>
                      <ul className="space-y-1">
                        {apiData.data.security.findings.map((f: string, i: number) => (
                          <li key={i} className="text-sm text-gray-300 flex items-start gap-2"><CheckCircle className="w-4 h-4 text-orange-400 mt-0.5" /> {f}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Network className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">DNS Dump Ready</h3>
                  <p className="text-gray-400">Enumerate A, AAAA, MX, NS, TXT, CNAME, SOA records, subdomains and related hosts.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== SOCIAL MONITOR TAB ==================== */}
          {activeTab === 'social' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <MessageSquare className="w-7 h-7 text-blue-400" /> Telegram & Discord Monitor
                <span className="text-sm font-normal text-gray-400">(keyword intelligence across channels)</span>
              </h2>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex flex-wrap gap-3">
                  <input type="text" placeholder="Search captured messages..." value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleSocialLoad(inputValue)}
                    className="flex-1 min-w-[200px] px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm focus:border-blue-500 focus:outline-none" />
                  <button onClick={() => handleSocialLoad(inputValue)} disabled={loading} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm flex items-center gap-2">
                    <Search className="w-4 h-4" /> Search
                  </button>
                  <button onClick={() => handleSocialLoad()} disabled={loading} className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm">All</button>
                  <button onClick={handleSocialKeywords} disabled={loading} className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg text-sm flex items-center gap-2">
                    <Key className="w-4 h-4" /> Keywords
                  </button>
                </div>
                {apiData?.configured === false && (
                  <div className="mt-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-xs text-yellow-300">
                    Demo mode — set TELEGRAM_BOT_TOKEN and DISCORD_BOT_TOKEN (Settings → Environment Variables) for live capture.
                  </div>
                )}
              </div>

              {apiData?.stats && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl"><div className="text-2xl font-bold text-blue-400">{apiData.stats.total}</div><div className="text-xs text-gray-500">Total Captured</div></div>
                  <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl"><div className="text-2xl font-bold text-red-400">{apiData.stats.critical}</div><div className="text-xs text-gray-500">Critical</div></div>
                  <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl"><div className="text-2xl font-bold text-orange-400">{apiData.stats.high}</div><div className="text-xs text-gray-500">High</div></div>
                  <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl"><div className="text-2xl font-bold text-green-400">{apiData.stats.activeChannels}</div><div className="text-xs text-gray-500">Active Channels</div></div>
                </div>
              )}

              {apiData?.stats?.topKeywords?.length > 0 && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                  <h3 className="font-semibold mb-3 flex items-center gap-2"><Key className="w-5 h-5 text-purple-400" /> Top Keywords</h3>
                  <div className="flex flex-wrap gap-2">
                    {apiData?.stats?.topKeywords?.map((k: any, i: number) => (
                      <span key={i} className="px-2 py-1 bg-gray-800 rounded text-xs">{k.keyword} <strong className="text-purple-400">{k.count}</strong></span>
                    ))}
                  </div>
                </div>
              )}

              {apiData?.data?.length > 0 && (
                <div className="space-y-2">
                  {(apiData?.data as any[] | undefined)?.slice(0, 50).map((m: any, i: number) => (
                    <div key={i} className={`p-4 rounded-lg border ${m.severity === 'CRITICAL' ? 'bg-red-500/10 border-red-500/30' : m.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/30' : 'bg-gray-900 border-gray-800'}`}>
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${m.platform === 'telegram' ? 'bg-blue-500/20 text-blue-400' : 'bg-indigo-500/20 text-indigo-400'}`}>{m.platform}</span>
                          <span className="text-sm font-semibold">{m.channel}</span>
                          <span className="text-xs text-gray-500">@{m.author}</span>
                        </div>
                        <span className={`text-xs font-bold ${m.severity === 'CRITICAL' ? 'text-red-400' : m.severity === 'HIGH' ? 'text-orange-400' : 'text-gray-400'}`}>{m.severity}</span>
                      </div>
                      <p className="text-sm text-gray-300">{m.text}</p>
                      <div className="mt-2 flex flex-wrap gap-2 text-xs">
                        {(m.keywords || []).map((k: string, j: number) => <span key={j} className="px-1.5 py-0.5 bg-purple-500/10 text-purple-300 rounded">#{k}</span>)}
                        {(m.links || []).slice(0, 3).map((l: string, j: number) => <span key={j} className="px-1.5 py-0.5 bg-gray-800 text-cyan-300 rounded font-mono">{l}</span>)}
                      </div>
                      <div className="mt-1 text-[10px] text-gray-600">{new Date(m.ts).toLocaleString()}</div>
                    </div>
                  ))}
                </div>
              )}
              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <MessageSquare className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Channel Monitor Ready</h3>
                  <p className="text-gray-400">Search keywords across Telegram and Discord channels. Connect bots for live capture.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== EXECUTIVE OSINT TAB ==================== */}
          {activeTab === 'exec' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <ShieldUser className="w-7 h-7 text-amber-400" /> Executive Digital Protection
                <span className="text-sm font-normal text-gray-400">(personal OSINT & exposure monitoring)</span>
              </h2>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input type="text" placeholder="Executive name (e.g., John Smith)"
                      value={inputValue} onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleExecScan()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-amber-500 focus:outline-none" />
                  </div>
                  <button onClick={handleExecScan} disabled={loading} className="px-6 py-3 bg-amber-600 hover:bg-amber-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2">
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldUser className="w-4 h-4" />} Scan Exposure
                  </button>
                </div>
              </div>

              {apiData?.data?.subject && (
                <div className="space-y-4">
                  <div className="rounded-xl p-5 border bg-amber-500/10 border-amber-500/40">
                    <div className="flex items-center justify-between">
                      <div><h3 className="font-semibold">Exposure Score</h3><p className="text-sm text-gray-400 mt-1">{apiData.data.subject.name}</p></div>
                      <div className="text-right"><div className="text-3xl font-bold">{apiData.data.exposureScore}/100</div><div className="text-sm font-bold">{apiData.data.riskLevel}</div></div>
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2"><Bug className="w-5 h-5 text-red-400" /> Exposed Indicators ({apiData.data.findings?.length})</h3>
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead><tr className="border-b border-gray-800 text-left text-gray-400">
                          <th className="py-2 px-2">Type</th><th className="py-2 px-2">Value</th><th className="py-2 px-2">Source</th><th className="py-2 px-2">Severity</th>
                        </tr></thead>
                        <tbody>
                          {(apiData.data.findings || []).map((f: any, i: number) => (
                            <tr key={i} className="border-b border-gray-800">
                              <td className="py-2 px-2 text-xs font-bold">{f.type}</td>
                              <td className="py-2 px-2 font-mono text-xs">{f.value}</td>
                              <td className="py-2 px-2 text-xs text-gray-400">{f.detail}</td>
                              <td className="py-2 px-2"><span className={`px-2 py-0.5 rounded text-xs font-bold ${f.severity === 'HIGH' ? 'bg-red-500 text-white' : f.severity === 'MEDIUM' ? 'bg-yellow-500 text-black' : 'bg-gray-700'}`}>{f.severity}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2"><Users className="w-5 h-5 text-blue-400" /> Social Media Footprint</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                      {(apiData.data.socialMatrix || []).map((s: any, i: number) => (
                        <div key={i} className="p-3 bg-gray-800/60 rounded-lg flex items-center justify-between">
                          <div><div className="text-sm font-medium">{s.platform}</div><div className="text-xs font-mono text-gray-500 truncate">{s.handle}</div></div>
                          <span className={`px-2 py-0.5 rounded text-xs font-bold ${s.risk === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' : s.risk === 'HIGH' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>{s.risk}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {apiData.data.dorkQueries?.length > 0 && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Search className="w-5 h-5 text-purple-400" /> Google Dorking Queries</h3>
                      {(apiData.data.dorkQueries as any[]).map((d: any, i: number) => (
                        <div key={i} className="mb-2 p-2 bg-gray-800/60 rounded-lg">
                          <div className="text-xs font-mono text-purple-300">{d.query}</div>
                          <div className="text-xs text-gray-500">{d.total} result(s)</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <ShieldUser className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Executive Protection Ready</h3>
                  <p className="text-gray-400">Monitor exposed emails, phones, documents, social media and dark web references for executives.</p>
                </div>
              )}
            </div>
          )}

          {/* ==================== FAKE APP SCANNER TAB ==================== */}
          {activeTab === 'fakeapp' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Smartphone className="w-7 h-7 text-fuchsia-400" /> Fake App Scanner
                <span className="text-sm font-normal text-gray-400">(MOBSF-style + CVE matching)</span>
              </h2>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input type="text" placeholder="APK/IPA filename (e.g., bankapp.apk)"
                      value={inputValue} onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleFakeApp()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-fuchsia-500 focus:outline-none" />
                  </div>
                  <button onClick={handleFakeApp} disabled={loading} className="px-6 py-3 bg-fuchsia-600 hover:bg-fuchsia-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2">
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Smartphone className="w-4 h-4" />} Analyze
                  </button>
                </div>
              </div>

              {apiData?.data?.verdict && (
                <div className="space-y-4">
                  <div className="rounded-xl p-5 border bg-red-500/10 border-red-500/50">
                    <div className="flex items-center justify-between">
                      <div><h3 className="font-semibold">Verdict: {apiData.data.verdict}</h3><p className="text-sm text-gray-400 mt-1 font-mono">{apiData.data.fileName} · {apiData.data.sha256?.substring(0, 20)}...</p></div>
                      <div className="text-right"><div className="text-2xl font-bold">{apiData.data.confidence}%</div><div className="text-sm font-bold text-red-400">confidence</div></div>
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="font-semibold mb-3 flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-red-400" /> Risk Objects</h3>
                    <div className="space-y-2">
                      {(apiData.data.riskObjects || []).map((r: any, i: number) => (
                        <div key={i} className={`p-3 rounded-lg ${r.severity === 'CRITICAL' ? 'bg-red-500/10 border-l-2 border-red-500' : r.severity === 'HIGH' ? 'bg-orange-500/10 border-l-2 border-orange-500' : 'bg-yellow-500/10 border-l-2 border-yellow-500'}`}>
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-bold">{r.id} · {r.type}</span>
                            <span className="text-xs font-bold text-red-400">{r.severity}</span>
                          </div>
                          <p className="text-xs text-gray-400 mt-1">{r.description}</p>
                          <p className="text-xs text-gray-500 mt-1">→ {r.recommendation}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {apiData.data.cvEs?.length > 0 && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Shield className="w-5 h-5 text-orange-400" /> CVE Impact Matches</h3>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead><tr className="border-b border-gray-800 text-left text-gray-400">
                            <th className="py-2 px-2">CVE</th><th className="py-2 px-2">CVSS</th><th className="py-2 px-2">Relevance</th>
                          </tr></thead>
                          <tbody>
                            {(apiData.data.cvEs as any[]).map((c: any, i: number) => (
                              <tr key={i} className="border-b border-gray-800">
                                <td className="py-2 px-2 font-mono text-xs">{c.cveId}</td>
                                <td className="py-2 px-2"><span className={`px-2 py-0.5 rounded text-xs font-bold ${(c.cvssScore || 0) >= 9 ? 'bg-red-500 text-white' : (c.cvssScore || 0) >= 7 ? 'bg-orange-500 text-black' : 'bg-gray-700'}`}>{c.cvssScore}</span></td>
                                <td className="py-2 px-2 text-xs text-gray-400">{c.relevance}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {apiData.data.actors?.length > 0 && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2"><Users className="w-5 h-5 text-purple-400" /> Suspected Actors</h3>
                      <div className="space-y-2">
                        {(apiData.data.actors as any[]).map((a: any, i: number) => (
                          <div key={i} className="p-3 bg-gray-800/60 rounded-lg flex flex-wrap gap-3 text-xs">
                            <span className="font-bold text-purple-300">{a.handle}</span>
                            <span className="text-gray-400">{a.role}</span>
                            <span className="font-mono text-gray-500">{a.ip}</span>
                            <span className="font-mono text-red-400">{a.domains?.join(', ')}</span>
                            <span className={`px-2 py-0.5 rounded font-bold ${a.confidence === 'HIGH' ? 'bg-red-500/20 text-red-400' : 'bg-gray-700'}`}>{a.confidence}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
              {!apiData && !loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <Smartphone className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">Fake App Scanner Ready</h3>
                  <p className="text-gray-400">Analyze suspicious APK/IPA files for risk objects, CVE impact and fraud actors.</p>
                </div>
              )}
            </div>
          )}
        </main>
      </div>

      {/* ==================== MODALS ==================== */}
      {/* Detail Modal */}
      {showModal && selectedIOC && modalType === 'detail' && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setShowModal(false)}>
          <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-3xl w-full max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="sticky top-0 bg-gray-900 border-b border-gray-800 p-4 flex items-center justify-between">
              <h3 className="font-bold text-lg">IOC Details</h3>
              <button onClick={() => setShowModal(false)} className="p-2 hover:bg-gray-800 rounded-lg"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div><span className="text-gray-400 text-sm">ID:</span><p className="font-mono text-sm">{selectedIOC.id}</p></div>
                <div><span className="text-gray-400 text-sm">Type:</span><p><span className="px-2 py-1 bg-gray-700 rounded text-xs">{selectedIOC.type}</span></p></div>
                <div className="col-span-2"><span className="text-gray-400 text-sm">Value:</span><p className="font-mono break-all">{selectedIOC.value}</p></div>
                <div><span className="text-gray-400 text-sm">Severity:</span><p style={{ color: SEVERITY_COLORS[selectedIOC.severity] }} className="font-bold">{selectedIOC.severity}</p></div>
                <div><span className="text-gray-400 text-sm">Status:</span><p style={{ color: STATUS_COLORS[selectedIOC.status] }} className="font-bold">{selectedIOC.status}</p></div>
                <div><span className="text-gray-400 text-sm">Confidence:</span><p>{selectedIOC.confidence}%</p></div>
                <div><span className="text-gray-400 text-sm">Source:</span><p>{selectedIOC.source || '-'}</p></div>
                <div className="col-span-2"><span className="text-gray-400 text-sm">Description:</span><p>{selectedIOC.description || '-'}</p></div>
              </div>
              {selectedIOC.tags?.length > 0 && (
                <div className="flex flex-wrap gap-2 pt-4 border-t border-gray-800">
                  {selectedIOC.tags.map((tag, idx) => (<span key={idx} className="px-2 py-1 bg-gray-700 rounded text-xs">{tag}</span>))}
                </div>
              )}
            </div>
            <div className="sticky bottom-0 bg-gray-900 border-t border-gray-800 p-4 flex justify-end gap-3">
              <button onClick={() => setModalType('edit')} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm"><Edit3 className="w-4 h-4 inline mr-1" /> Edit</button>
              <button onClick={() => { handleDeleteIOC(selectedIOC.id); setShowModal(false); }} className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-sm"><Trash2 className="w-4 h-4 inline mr-1" /> Delete</button>
            </div>
          </div>
        </div>
      )}

      {/* Add/Edit Modal */}
      {showModal && (modalType === 'add' || modalType === 'edit') && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setShowModal(false)}>
          <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-lg w-full" onClick={(e) => e.stopPropagation()}>
            <div className="border-b border-gray-800 p-4 flex items-center justify-between">
              <h3 className="font-bold text-lg">{modalType === 'add' ? 'Add New IOC' : 'Edit IOC'}</h3>
              <button onClick={() => setShowModal(false)} className="p-2 hover:bg-gray-800 rounded-lg"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Type *</label>
                <select value={formData.type} onChange={(e) => setFormData({...formData, type: e.target.value})} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg" disabled={modalType === 'edit'}>
                  <option value="IP">IP Address</option>
                  <option value="DOMAIN">Domain</option>
                  <option value="URL">URL</option>
                  <option value="HASH">Hash</option>
                  <option value="CVE">CVE ID</option>
                  <option value="EMAIL">Email</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Value *</label>
                <input type="text" value={formData.value} onChange={(e) => setFormData({...formData, value: e.target.value})} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg font-mono" placeholder={modalType === 'add' ? 'Enter indicator value...' : ''} disabled={modalType === 'edit'} />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Description</label>
                <textarea value={formData.description} onChange={(e) => setFormData({...formData, description: e.target.value})} rows={3} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg resize-none" placeholder="Add context..." />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Severity</label>
                  <select value={formData.severity} onChange={(e) => setFormData({...formData, severity: e.target.value})} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg">
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="INFO">Info</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Tags (comma separated)</label>
                  <input type="text" value={formData.tags.join(', ')} onChange={(e) => setFormData({...formData, tags: e.target.value.split(',').map(t => t.trim()).filter(Boolean)})} className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg" placeholder="tag1, tag2..." />
                </div>
              </div>
            </div>
            <div className="border-t border-gray-800 p-4 flex justify-end gap-3">
              <button onClick={() => setShowModal(false)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg">Cancel</button>
              <button onClick={modalType === 'add' ? handleAddIOC : handleUpdateIOC} disabled={!formData.value} className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 rounded-lg">
                {modalType === 'add' ? <Plus className="w-4 h-4 inline mr-1" /> : <Save className="w-4 h-4 inline mr-1" />}
                {modalType === 'add' ? 'Add IOC' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ==================== SUB-COMPONENTS ====================
function InfoCard({ label, value, icon, alert }: { label: string; value: string | React.ReactNode; icon: React.ReactNode; alert?: boolean }) {
  return (
    <div className={`p-3 bg-gray-800/50 rounded-lg ${alert ? 'border border-red-500/30' : ''}`}>
      <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">{icon}{label}</div>
      <div className={`font-medium text-sm ${alert ? 'text-red-400' : ''}`}>{value}</div>
    </div>
  );
}

function SecurityCheck({ label, pass }: { label: string; pass: boolean }) {
  return (
    <div className={`p-3 rounded-lg flex items-center gap-3 ${pass ? 'bg-green-500/10' : 'bg-red-500/10'}`}>
      {pass ? <CheckCircle className="w-5 h-5 text-green-500" /> : <XCircle className="w-5 h-5 text-red-500" />}
      <div>
        <p className="font-medium text-sm">{label}</p>
        <p className={`text-xs ${pass ? 'text-green-400' : 'text-red-400'}`}>{pass ? 'Configured' : 'Not Found'}</p>
      </div>
    </div>
  );
}

// Missing icons - create simple components
function LinkIcon({ className }: { className?: string }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>;
}

function Tag({ className }: { className?: string }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" /></svg>;
}

function Package({ className }: { className?: string }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" /></svg>;
}

function ShoppingCart({ className }: { className?: string }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 11-4 0 2 2 0 014 0z" /></svg>;
}
