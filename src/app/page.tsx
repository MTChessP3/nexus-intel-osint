'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { 
  Shield, Search, Globe, AlertTriangle, Activity, 
  MapPin, Server, Fingerprint, Bug, Link, Hash, Target,
  Brain, Cpu, TrendingUp, ChevronRight, Loader2, 
  Download, ExternalLink, Clock, FileText, BarChart3,
  Terminal, Eye, Lock, Zap, RefreshCw, X, Check,
  ArrowUpRight, ArrowDownRight, Minus, Info
} from 'lucide-react';

// ============================================
// TYPES - Professional Data Structures
// ============================================

interface IPAnalysis {
  query: string;
  geolocation: {
    country: string;
    countryCode: string;
    region: string;
    city: string;
    latitude: number;
    longitude: number;
    timezone: string;
    isp: string;
    org: string;
    asn: string;
  };
  network: {
    isp: string;
    org: string;
    asn: string;
    isProxy: boolean;
    isHosting: boolean;
    isMobile: boolean;
  };
  threat: {
    score: number;
    level: string;
    indicators: string[];
    recommendations: string[];
  };
  timestamp: string;
}

interface ThreatIntelligence {
  globalThreatLevel: {
    level: string;
    score: number;
    color: string;
    factors: Record<string, number>;
  };
  activeThreats: Array<{
    id: string;
    description: string;
    severity: string;
    cvssScore: number | null;
    published: string;
  }>;
  campaigns: Array<{
    id: string;
    name: string;
    status: string;
    severity: string;
    targetSectors: string[];
    indicators: number;
  }>;
  aptGroups: Array<{
    name: string;
    country: string;
    status: string;
    lastActivity: string;
  }>;
  statistics: {
    totalIOCs: number;
    threatsBySeverity: Record<string, number>;
    iocByType: Record<string, number>;
  };
}

interface CVEData {
  id: string;
  description: string;
  cvssScore: number | null;
  severity: string;
  published: string;
  status: string;
}

interface DomainAnalysis {
  domain: string;
  whois: Record<string, any>;
  dns: Record<string, string[]>;
  security: {
    sslGrade: string;
    hasMX: boolean;
    hasSPF: boolean;
    hasDMARC: boolean;
  };
  threatLevel: string;
}

interface AIAnalysis {
  query: string;
  summary: string;
  keyFindings: string[];
  riskAssessment: string;
  recommendations: string[];
  confidence: number;
  timestamp: string;
}

interface ReportData {
  title: string;
  generatedAt: string;
  executiveSummary: string;
  sections: Array<{
    title: string;
    content: string;
    data?: any;
  }>;
}

// ============================================
// MAIN APPLICATION COMPONENT
// ============================================

export default function NexusIntelOSINT() {
  // State Management
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [loadingMessage, setLoadingMessage] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Data States
  const [threatIntel, setThreatIntel] = useState<ThreatIntelligence | null>(null);
  const [ipAnalysis, setIpAnalysis] = useState<IPAnalysis | null>(null);
  const [cveResults, setCveResults] = useState<CVEData[]>([]);
  const [domainAnalysis, setDomainAnalysis] = useState<DomainAnalysis | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null);
  const [reportData, setReportData] = useState<ReportData | null>(null);

  // Input States
  const [ipInput, setIpInput] = useState<string>('8.8.8.8');
  const [domainInput, setDomainInput] = useState<string>('google.com');
  const [cveSearch, setCveSearch] = useState<string>('');
  const [aiQuery, setAiQuery] = useState<string>('');

  // ============================================
  // INITIALIZATION - Load Real Data on Mount
  // ============================================

  useEffect(() => {
    loadThreatIntelligence();
  }, []);

  // ============================================
  // API FUNCTIONS - All Return Real Data
  // ============================================

  const loadThreatIntelligence = async () => {
    setIsLoading(true);
    setLoadingMessage('Loading threat intelligence feed...');
    
    try {
      const response = await fetch('/api/osint/threats');
      const data = await response.json();
      
      if (data.success) {
        setThreatIntel(data.data);
        console.log('[NEXUS] ✅ Threat intelligence loaded:', data.data.globalThreatLevel?.level);
      } else {
        throw new Error(data.error || 'Failed to load threat intelligence');
      }
    } catch (err: any) {
      console.error('[NEXUS] ❌ Threat load error:', err.message);
      setError('Failed to connect to threat intelligence server');
    } finally {
      setIsLoading(false);
      setLoadingMessage('');
    }
  };

  const analyzeIPAddress = async (ip: string) => {
    if (!ip.trim()) return;
    
    setIsLoading(true);
    setLoadingMessage(`Analyzing IP address: ${ip}...`);
    setError(null);
    
    try {
      const response = await fetch('/api/osint/ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip.trim() })
      });
      
      const data = await response.json();
      
      if (data.success) {
        setIpAnalysis({
          ...data.data,
          timestamp: new Date().toISOString()
        });
        setSuccess(`IP ${data.data.query} analyzed successfully`);
        console.log('[NEXUS] ✅ IP Analysis complete:', data.data.threat.level);
      } else {
        throw new Error(data.error || 'IP analysis failed');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to analyze IP address');
    } finally {
      setIsLoading(false);
      setLoadingMessage('');
    }
  };

  const searchCVE = async (query: string) => {
    if (!query.trim()) return;
    
    setIsLoading(true);
    setLoadingMessage(`Searching CVE database for: ${query}...`);
    setError(null);
    
    try {
      const isCVEId = query.toUpperCase().startsWith('CVE-');
      const response = await fetch('/api/osint/cve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(isCVEId ? { cveId: query } : { keyword: query })
      });
      
      const data = await response.json();
      
      if (data.success) {
        const results = data.data.results || [data.data];
        setCveResults(results);
        setSuccess(`Found ${results.length} CVE(s) matching "${query}"`);
        console.log('[NEXUS] ✅ CVE Search complete:', results.length, 'results');
      } else {
        throw new Error(data.error || 'CVE search failed');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to search CVE database');
    } finally {
      setIsLoading(false);
      setLoadingMessage('');
    }
  };

  const analyzeDomain = async (domain: string) => {
    if (!domain.trim()) return;
    
    setIsLoading(true);
    setLoadingMessage(`Analyzing domain: ${domain}...`);
    setError(null);
    
    try {
      const response = await fetch('/api/osint/domain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() })
      });
      
      const data = await response.json();
      
      if (data.success) {
        setDomainAnalysis(data.data);
        setSuccess(`Domain ${data.data.domain} analyzed`);
        console.log('[NEXUS] ✅ Domain Analysis complete:', data.data.threatLevel);
      } else {
        throw new Error(data.error || 'Domain analysis failed');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to analyze domain');
    } finally {
      setIsLoading(false);
      setLoadingMessage('');
    }
  };

  const runAIAnalysis = async (query: string) => {
    if (!query.trim()) return;
    
    setIsLoading(true);
    setLoadingMessage('Running AI threat analysis...');
    setError(null);
    
    try {
      const response = await fetch('/api/osint/ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          query: query.trim(),
          context: threatIntel 
        })
      });
      
      const data = await response.json();
      
      if (data.success) {
        setAiAnalysis(data.data);
        setSuccess('AI analysis completed');
        console.log('[NEXUS] ✅ AI Analysis complete:', data.data.confidence, '% confidence');
      } else {
        throw new Error(data.error || 'AI analysis failed');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to run AI analysis');
    } finally {
      setIsLoading(false);
      setLoadingMessage('');
    }
  };

  const generateExecutiveReport = async () => {
    setIsLoading(true);
    setLoadingMessage('Generating executive report...');
    setError(null);
    
    try {
      const reportPayload = {
        reportType: 'executive',
        data: {
          threatData: threatIntel,
          ipResult: ipAnalysis,
          cveResults: cveResults,
          generatedAt: new Date().toISOString()
        }
      };
      
      const response = await fetch('/api/osint/reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reportPayload)
      });
      
      const data = await response.json();
      
      if (data.success) {
        setReportData(data.data.report);
        setSuccess('Executive report generated');
        setActiveTab('reports');
        console.log('[NEXUS] ✅ Report generated:', data.data.report.title);
      } else {
        throw new Error(data.error || 'Report generation failed');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to generate report');
    } finally {
      setIsLoading(false);
      setLoadingMessage('');
    }
  };

  // ============================================
  // HELPER FUNCTIONS
  // ============================================

  const getSeverityClass = (severity: string): string => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
      case 'CRÍTICO':
        return 'severity-critical';
      case 'HIGH':
      case 'ALTO':
        return 'severity-high';
      case 'MEDIUM':
      case 'MEDIO':
        return 'severity-medium';
      case 'LOW':
      case 'BAJO':
        return 'severity-low';
      default:
        return 'severity-low';
    }
  };

  const getStatusDotClass = (level: string): string => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL':
      case 'CRÍTICO':
        return 'status-critical';
      case 'HIGH':
      case 'ALTO':
      case 'ELEVADO':
        return 'status-high';
      case 'MEDIUM':
      case 'MEDIO':
      case 'MODERADO':
        return 'status-medium';
      default:
        return 'status-low';
    }
  };

  const formatTimestamp = (ts: string): string => {
    if (!ts) return 'N/A';
    return new Date(ts).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const clearNotifications = () => {
    setError(null);
    setSuccess(null);
  };

  // ============================================
  // RENDER: DASHBOARD TAB
  // ============================================

  const renderDashboard = () => (
    <div className="space-y-6">
      {/* Executive Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white tracking-tight">
            Threat Intelligence Dashboard
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            Real-time OSINT analysis · Last updated: {formatTimestamp(new Date().toISOString())}
          </p>
        </div>
        <button 
          onClick={loadThreatIntelligence}
          disabled={isLoading}
          className="btn-secondary"
        >
          <RefreshCw size={14} className={isLoading ? 'animate-spin' : ''} />
          Refresh Data
        </button>
      </div>

      {/* Key Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Global Threat Level */}
        <div className="executive-card">
          <div className="executive-card-body">
            <div className="flex items-center justify-between mb-3">
              <span className="metric-label">Global Threat Level</span>
              <span className={`status-dot ${getStatusDotClass(threatIntel?.globalThreatLevel?.level)}`} />
            </div>
            <div className="metric-value" style={{
              color: threatIntel?.globalThreatLevel?.color || '#ffffff'
            }}>
              {threatIntel?.globalThreatLevel?.level || '--'}
            </div>
            <div className="metric-change" style={{ color: '#71717a' }}>
              Score: {threatIntel?.globalThreatLevel?.score || 0}/100
            </div>
            <div className="progress-bar mt-3">
              <div 
                className={`progress-bar-fill ${getStatusDotClass(threatIntel?.globalThreatLevel?.level)}`}
                style={{ width: `${threatIntel?.globalThreatLevel?.score || 0}%` }}
              />
            </div>
          </div>
        </div>

        {/* Active IOCs */}
        <div className="executive-card">
          <div className="executive-card-body">
            <div className="flex items-center justify-between mb-3">
              <span className="metric-label">Monitored IOCs</span>
              <Fingerprint size={14} className="text-zinc-500" />
            </div>
            <div className="metric-value">
              {threatIntel?.statistics?.totalIOCs || 0}
            </div>
            <div className="metric-change" style={{ color: '#22c55e' }}>
              <ArrowDownRight size={12} />
              Active indicators
            </div>
          </div>
        </div>

        {/* Critical CVEs */}
        <div className="executive-card">
          <div className="executive-card-body">
            <div className="flex items-center justify-between mb-3">
              <span className="metric-label">Critical Vulnerabilities</span>
              <Bug size={14} className="text-red-500" />
            </div>
            <div className="metric-value text-red-400">
              {threatIntel?.statistics?.threatsBySeverity?.CRITICAL || 0}
            </div>
            <div className="metric-change" style={{ color: '#ef4444' }}>
              <ArrowUpRight size={12} />
              CVSS ≥ 9.0
            </div>
          </div>
        </div>

        {/* Active Campaigns */}
        <div className="executive-card">
          <div className="executive-card-body">
            <div className="flex items-center justify-between mb-3">
              <span className="metric-label">Active Campaigns</span>
              <Target size={14} className="text-orange-500" />
            </div>
            <div className="metric-value text-orange-400">
              {threatIntel?.campaigns?.filter((c: any) => c.status === 'ACTIVE').length || 0}
            </div>
            <div className="metric-change" style={{ color: '#f97316' }}>
              <Zap size={12} />
              Ongoing operations
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Critical Threats - Takes 2/3 width */}
        <div className="lg:col-span-2 executive-card">
          <div className="executive-card-header">
            <div className="flex items-center gap-2">
              <AlertTriangle size={14} className="text-yellow-500" />
              <span className="text-sm font-medium text-white">Recent Critical Vulnerabilities</span>
            </div>
            <button 
              onClick={() => setActiveTab('cve')}
              className="text-xs text-zinc-500 hover:text-white flex items-center gap-1 transition-colors"
            >
              View All <ChevronRight size={12} />
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>Description</th>
                  <th>Published</th>
                </tr>
              </thead>
              <tbody>
                {(threatIntel?.activeThreats || []).slice(0, 6).map((threat, idx) => (
                  <tr key={idx}>
                    <td className="font-mono text-white">{threat.id}</td>
                    <td>
                      <span className={`severity-badge ${getSeverityClass(threat.severity)}`}>
                        {threat.severity}
                      </span>
                    </td>
                    <td className="font-mono">{threat.cvssScore || 'N/A'}</td>
                    <td className="line-clamp-2 max-w-xs">{threat.description}</td>
                    <td className="text-zinc-500 text-xs">
                      {formatTimestamp(threat.published)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Active Campaigns Sidebar */}
        <div className="executive-card">
          <div className="executive-card-header">
            <div className="flex items-center gap-2">
              <Target size={14} className="text-orange-500" />
              <span className="text-sm font-medium text-white">Active Campaigns</span>
            </div>
          </div>
          <div className="space-y-3 p-4">
            {(threatIntel?.campaigns || [])
              .filter((c: any) => c.status === 'ACTIVE')
              .map((campaign: any, idx: number) => (
                <div key={idx} className="p-3 bg-black/30 border border-zinc-800/50 rounded">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-xs text-zinc-400">{campaign.id}</span>
                    <span className={`status-dot ${getStatusDotClass(campaign.severity)}`} />
                  </div>
                  <p className="text-sm font-medium text-white mb-1">{campaign.name}</p>
                  <p className="text-xs text-zinc-500 line-clamp-2">{campaign.description || campaign.targetSectors?.join(', ')}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-zinc-600">
                    <span>{campaign.indicators} IOCs</span>
                    <span>{campaign.targetSectors?.[0]}</span>
                  </div>
                </div>
              ))}
          </div>
        </div>
      </div>

      {/* Bottom Section: APT Groups & IOC Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* APT Groups Tracking */}
        <div className="executive-card">
          <div className="executive-card-header">
            <div className="flex items-center gap-2">
              <Brain size={14} className="text-purple-400" />
              <span className="text-sm font-medium text-white">APT Groups Tracked</span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Group</th>
                  <th>Origin</th>
                  <th>Status</th>
                  <th>Last Active</th>
                </tr>
              </thead>
              <tbody>
                {(threatIntel?.aptGroups || []).map((apt, idx) => (
                  <tr key={idx}>
                    <td className="font-medium text-white">{apt.name}</td>
                    <td className="text-zinc-400">{apt.country}</td>
                    <td>
                      <span className={`severity-badge ${apt.status === 'ACTIVE' ? 'severity-critical' : 'severity-low'}`}>
                        {apt.status}
                      </span>
                    </td>
                    <td className="text-zinc-500 text-xs">{apt.lastActivity}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* IOC Type Distribution */}
        <div className="executive-card">
          <div className="executive-card-header">
            <div className="flex items-center gap-2">
              <BarChart3 size={14} className="text-cyan-400" />
              <span className="text-sm font-medium text-white">IOC Distribution</span>
            </div>
          </div>
          <div className="p-4 space-y-4">
            {Object.entries(threatIntel?.statistics?.iocByType || {}).map(([type, count]: [string, any]) => {
              const total = Object.values(threatIntel?.statistics?.iocByType || {}).reduce((a: number, b: number) => a + b, 0) || 1;
              const percentage = ((count / total) * 100).toFixed(1);
              
              return (
                <div key={type}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-zinc-400 uppercase">{type}</span>
                    <span className="font-mono text-sm text-white">{count}</span>
                  </div>
                  <div className="progress-bar">
                    <div 
                      className="progress-bar-fill"
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
            
            <div className="pt-4 border-t border-zinc-800 grid grid-cols-2 gap-4">
              {Object.entries(threatIntel?.statistics?.threatsBySeverity || {}).map(([level, count]: [string, any]) => (
                <div key={level} className="text-center p-2 bg-black/30 rounded">
                  <p className="text-xs text-zinc-500 uppercase">{level}</p>
                  <p className="text-lg font-bold text-white">{count}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  // ============================================
  // RENDER: IP INTELLIGENCE TAB
  // ============================================

  const renderIPIntel = () => (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white tracking-tight">IP Intelligence</h1>
        <p className="text-sm text-zinc-500 mt-1">Geolocation, network analysis, and threat assessment</p>
      </div>

      {/* IP Input Section */}
      <div className="executive-card">
        <div className="p-4">
          <div className="flex gap-3">
            <input
              type="text"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && analyzeIPAddress(ipInput)}
              placeholder="Enter IP address (e.g., 8.8.8.8)"
              className="executive-input flex-1"
            />
            <button 
              onClick={() => analyzeIPAddress(ipInput)}
              disabled={isLoading}
              className="btn-primary"
            >
              {isLoading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
              Analyze
            </button>
          </div>
          
          {/* Quick Actions */}
          <div className="flex gap-2 mt-3">
            <span className="text-xs text-zinc-600">Quick test:</span>
            {['8.8.8.8', '1.1.1.1', '208.67.222.222'].map(ip => (
              <button
                key={ip}
                onClick={() => {
                  setIpInput(ip);
                  analyzeIPAddress(ip);
                }}
                className="text-xs font-mono text-zinc-500 hover:text-white transition-colors"
              >
                {ip}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* IP Results */}
      {ipAnalysis && (
        <div className="space-y-6">
          {/* Summary Card */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="executive-card">
              <div className="executive-card-body text-center">
                <p className="metric-label">Target IP</p>
                <p className="font-mono text-xl text-white mt-2">{ipAnalysis.query}</p>
                <span className={`severity-badge ${getSeverityClass(ipAnalysis.threat.level)} mt-3`}>
                  {ipAnalysis.threat.level} RISK
                </span>
              </div>
            </div>
            <div className="executive-card">
              <div className="executive-card-body text-center">
                <p className="metric-label">Location</p>
                <p className="text-lg text-white mt-2">{ipAnalysis.geolocation.city}</p>
                <p className="text-sm text-zinc-400">{ipAnalysis.geolocation.region}, {ipAnalysis.geolocation.country}</p>
              </div>
            </div>
            <div className="executive-card">
              <div className="executive-card-body text-center">
                <p className="metric-label">Network</p>
                <p className="text-lg text-white mt-2 truncate">{ipAnalysis.network.isp}</p>
                <p className="text-sm text-zinc-400 font-mono">{ipAnalysis.network.asn}</p>
              </div>
            </div>
          </div>

          {/* Detailed Analysis Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Geolocation Details */}
            <div className="executive-card">
              <div className="executive-card-header">
                <div className="flex items-center gap-2">
                  <MapPin size={14} className="text-green-400" />
                  <span className="text-sm font-medium text-white">Geolocation Data</span>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="data-table">
                  <tbody>
                    <tr><td className="text-zinc-500 w-40">Country</td><td className="text-white">{ipAnalysis.geolocation.country}</td></tr>
                    <tr><td className="text-zinc-500">Country Code</td><td className="font-mono text-white">{ipAnalysis.geolocation.countryCode}</td></tr>
                    <tr><td className="text-zinc-500">Region</td><td className="text-white">{ipAnalysis.geolocation.region}</td></tr>
                    <tr><td className="text-zinc-500">City</td><td className="text-white">{ipAnalysis.geolocation.city}</td></tr>
                    <tr><td className="text-zinc-500">Coordinates</td><td className="font-mono text-white">{ipAnalysis.geolocation.latitude}, {ipAnalysis.geolocation.longitude}</td></tr>
                    <tr><td className="text-zinc-500">Timezone</td><td className="text-white">{ipAnalysis.geolocation.timezone}</td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Network Details */}
            <div className="executive-card">
              <div className="executive-card-header">
                <div className="flex items-center gap-2">
                  <Server size={14} className="text-blue-400" />
                  <span className="text-sm font-medium text-white">Network Information</span>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="data-table">
                  <tbody>
                    <tr><td className="text-zinc-500 w-40">ISP</td><td className="text-white">{ipAnalysis.network.isp}</td></tr>
                    <tr><td className="text-zinc-500">Organization</td><td className="text-white">{ipAnalysis.network.org}</td></tr>
                    <tr><td className="text-zinc-500">ASN</td><td className="font-mono text-white">{ipAnalysis.network.asn}</td></tr>
                    <tr><td className="text-zinc-500">Proxy/VPN</td><td><span className={ipAnalysis.network.isProxy ? 'text-red-400' : 'text-green-400'}>{ipAnalysis.network.isProxy ? 'DETECTED' : 'None'}</span></td></tr>
                    <tr><td className="text-zinc-500">Hosting</td><td><span className={ipAnalysis.network.isHosting ? 'text-yellow-400' : 'text-green-400'}>{ipAnalysis.network.isHosting ? 'Data Center' : 'Residential'}</span></td></tr>
                    <tr><td className="text-zinc-500">Mobile</td><td><span className={ipAnalysis.network.isMobile ? 'text-blue-400' : 'text-zinc-400'}>{ipAnalysis.network.isMobile ? 'Yes' : 'No'}</span></td></tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Threat Assessment */}
          <div className="executive-card">
            <div className="executive-card-header">
              <div className="flex items-center gap-2">
                <Shield size={14} className="text-red-400" />
                <span className="text-sm font-medium text-white">Threat Assessment</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-sm text-zinc-400">Score:</span>
                <span className="font-mono text-lg" style={{
                  color: ipAnalysis.threat.score >= 60 ? '#ef4444' : ipAnalysis.threat.score >= 40 ? '#f97316' : '#22c55e'
                }}>
                  {ipAnalysis.threat.score}/100
                </span>
              </div>
            </div>
            <div className="p-4 space-y-4">
              <div className="progress-bar h-2">
                <div 
                  className={`progress-bar-fill ${ipAnalysis.threat.score >= 60 ? 'critical' : ipAnalysis.threat.score >= 40 ? 'high' : 'low'}`}
                  style={{ width: `${ipAnalysis.threat.score}%` }}
                />
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-3">Indicators</h4>
                  <ul className="space-y-2">
                    {ipAnalysis.threat.indicators.map((indicator, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-sm">
                        <span className={`status-dot ${indicator.includes('🔴') || indicator.includes('🚨') ? 'status-critical' : indicator.includes('⚠️') || indicator.includes('🟠') ? 'status-high' : 'status-medium'} mt-1.5`} />
                        <span className="text-zinc-300">{indicator.replace(/[🔴🟠🟡🟢⚠️🚨ℹ️📱✅🏠]/g, '').trim()}</span>
                      </li>
                    ))}
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-3">Recommendations</h4>
                  <ul className="space-y-2">
                    {ipAnalysis.threat.recommendations.map((rec, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-sm">
                        <Check size={14} className="text-green-400 mt-0.5 shrink-0" />
                        <span className="text-zinc-300">{rec.replace(/[🔴🟠🟡🟢⚠️🚨ℹ️📱✅🏠]/g, '').trim()}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  // ============================================
  // RENDER: CVE SEARCH TAB
  // ============================================

  const renderCVESearch = () => (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white tracking-tight">Vulnerability Database</h1>
        <p className="text-sm text-zinc-500 mt-1">Search NIST NVD for CVEs and security vulnerabilities</p>
      </div>

      {/* CVE Input */}
      <div className="executive-card">
        <div className="p-4">
          <div className="flex gap-3">
            <input
              type="text"
              value={cveSearch}
              onChange={(e) => setCveSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && searchCVE(cveSearch)}
              placeholder="Enter CVE-ID (e.g., CVE-2024-3400) or keyword..."
              className="executive-input flex-1"
            />
            <button 
              onClick={() => searchCVE(cveSearch)}
              disabled={isLoading}
              className="btn-primary"
            >
              {isLoading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
              Search
            </button>
          </div>
          
          <div className="flex gap-2 mt-3">
            <span className="text-xs text-zinc-600">Recent critical:</span>
            {['CVE-2024-3400', 'CVE-2024-3094', 'CVE-2024-21762'].map(cve => (
              <button
                key={cve}
                onClick={() => {
                  setCveSearch(cve);
                  searchCVE(cve);
                }}
                className="text-xs font-mono text-zinc-500 hover:text-white transition-colors"
              >
                {cve}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* CVE Results */}
      {(cveResults.length > 0) && (
        <div className="executive-card">
          <div className="executive-card-header">
            <div className="flex items-center gap-2">
              <Bug size={14} className="text-red-400" />
              <span className="text-sm font-medium text-white">Search Results ({cveResults.length})</span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>Description</th>
                  <th>Status</th>
                  <th>Published</th>
                </tr>
              </thead>
              <tbody>
                {cveResults.map((cve, idx) => (
                  <tr key={idx}>
                    <td className="font-mono text-white font-medium">{cve.id}</td>
                    <td>
                      <span className={`severity-badge ${getSeverityClass(cve.severity)}`}>
                        {cve.severity}
                      </span>
                    </td>
                    <td className="font-mono">
                      <span className={
                        cve.cvssScore >= 9 ? 'text-red-400' :
                        cve.cvssScore >= 7 ? 'text-orange-400' :
                        cve.cvssScore >= 4 ? 'text-yellow-400' : 'text-green-400'
                      }>
                        {cve.cvssScore || 'N/A'}
                      </span>
                    </td>
                    <td className="line-clamp-2 max-w-md">{cve.description}</td>
                    <td>
                      <span className="text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                        {cve.status || 'Analyzed'}
                      </span>
                    </td>
                    <td className="text-zinc-500 text-xs whitespace-nowrap">
                      {formatTimestamp(cve.published)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );

  // ============================================
  // RENDER: DOMAIN ANALYSIS TAB
  // ============================================

  const renderDomainAnalysis = () => (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white tracking-tight">Domain Intelligence</h1>
        <p className="text-sm text-zinc-500 mt-1">WHOIS, DNS records, and security assessment</p>
      </div>

      {/* Domain Input */}
      <div className="executive-card">
        <div className="p-4">
          <div className="flex gap-3">
            <input
              type="text"
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && analyzeDomain(domainInput)}
              placeholder="Enter domain (e.g., google.com)"
              className="executive-input flex-1"
            />
            <button 
              onClick={() => analyzeDomain(domainInput)}
              disabled={isLoading}
              className="btn-primary"
            >
              {isLoading ? <Loader2 size={16} className="animate-spin" /> : <Globe size={16} />}
              Analyze
            </button>
          </div>
        </div>
      </div>

      {/* Domain Results */}
      {domainAnalysis && (
        <div className="space-y-6">
          {/* Summary */}
          <div className="executive-card">
            <div className="p-4 flex items-center justify-between">
              <div>
                <p className="text-sm text-zinc-500">Analyzing</p>
                <p className="font-mono text-xl text-white">{domainAnalysis.domain}</p>
              </div>
              <span className={`severity-badge ${getSeverityClass(domainAnalysis.threatLevel)}`}>
                {domainAnalysis.threatLevel} RISK
              </span>
            </div>
          </div>

          {/* Security Overview */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'SSL Grade', value: domainAnalysis.security?.sslGrade || 'N/A', good: ['A', 'A+', 'A++'].includes(domainAnalysis.security?.sslGrade) },
              { label: 'MX Records', value: domainAnalysis.security?.hasMX ? 'Configured' : 'Missing', good: domainAnalysis.security?.hasMX },
              { label: 'SPF Record', value: domainAnalysis.security?.hasSPF ? 'Present' : 'Missing', good: domainAnalysis.security?.hasSPF },
              { label: 'DMARC', value: domainAnalysis.security?.hasDMARC ? 'Enabled' : 'Disabled', good: domainAnalysis.security?.hasDMARC },
            ].map((item, idx) => (
              <div key={idx} className="executive-card">
                <div className="executive-card-body text-center">
                  <p className="metric-label">{item.label}</p>
                  <p className={`text-lg font-medium mt-2 ${item.good ? 'text-green-400' : 'text-red-400'}`}>
                    {item.value}
                  </p>
                </div>
              </div>
            ))}
          </div>

          {/* DNS Records */}
          {domainAnalysis.dns && (
            <div className="executive-card">
              <div className="executive-card-header">
                <span className="text-sm font-medium text-white">DNS Records</span>
              </div>
              <div className="p-4 space-y-3">
                {Object.entries(domainAnalysis.dns).map(([type, records]: [string, any]) => (
                  <div key={type}>
                    <p className="text-xs font-semibold text-zinc-500 uppercase mb-1">{type}</p>
                    <div className="flex flex-wrap gap-2">
                      {(records || []).map((record: string, idx: number) => (
                        <code key={idx} className="px-2 py-1 bg-black/50 rounded text-xs font-mono text-zinc-300">
                          {record}
                        </code>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );

  // ============================================
  // RENDER: AI ANALYSIS TAB
  // ============================================

  const renderAIAnalysis = () => (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white tracking-tight">AI Threat Analyst</h1>
        <p className="text-sm text-zinc-500 mt-1">Powered by advanced AI models for deep threat analysis</p>
      </div>

      {/* AI Input */}
      <div className="executive-card">
        <div className="p-4">
          <div className="flex gap-3">
            <input
              type="text"
              value={aiQuery}
              onChange={(e) => setAiQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && runAIAnalysis(aiQuery)}
              placeholder="Ask about threats, vulnerabilities, APT groups, or IOC patterns..."
              className="executive-input flex-1"
            />
            <button 
              onClick={() => runAIAnalysis(aiQuery)}
              disabled={isLoading}
              className="btn-primary"
            >
              {isLoading ? <Loader2 size={16} className="animate-spin" /> : <Brain size={16} />}
              Analyze
            </button>
          </div>
          
          <div className="flex gap-2 mt-3 flex-wrap">
            <span className="text-xs text-zinc-600">Suggested queries:</span>
            {[
              'Analyze recent ransomware trends',
              'Explain APT29 tactics',
              'Assess cloud security risks',
              'Top CVEs this month'
            ].map(query => (
              <button
                key={query}
                onClick={() => {
                  setAiQuery(query);
                  runAIAnalysis(query);
                }}
                className="text-xs text-zinc-500 hover:text-white px-2 py-1 rounded border border-zinc-800 hover:border-zinc-600 transition-colors"
              >
                {query}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* AI Results */}
      {aiAnalysis && (
        <div className="analysis-panel">
          <div className="analysis-header">
            <div className="flex items-center gap-2">
              <Brain size={14} className="text-purple-400" />
              <span className="text-sm font-medium text-white">Analysis Results</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-zinc-500">Confidence:</span>
              <span className="font-mono text-sm text-green-400">{aiAnalysis.confidence}%</span>
            </div>
          </div>
          
          <div className="analysis-content space-y-6">
            {/* Summary */}
            <div>
              <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-2">Executive Summary</h3>
              <p className="leading-relaxed">{aiAnalysis.summary}</p>
            </div>

            {/* Risk Assessment */}
            <div>
              <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-2">Risk Assessment</h3>
              <div className="p-3 bg-black/50 rounded border-l-2 border-red-500">
                <p>{aiAnalysis.riskAssessment}</p>
              </div>
            </div>

            {/* Key Findings */}
            <div>
              <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-3">Key Findings</h3>
              <ul className="space-y-2">
                {aiAnalysis.keyFindings.map((finding, idx) => (
                  <li key={idx} className="flex items-start gap-3">
                    <span className="status-dot status-info mt-2" />
                    <span className="text-zinc-300">{finding}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Recommendations */}
            <div>
              <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-3">Recommendations</h3>
              <ul className="space-y-2">
                {aiAnalysis.recommendations.map((rec, idx) => (
                  <li key={idx} className="flex items-start gap-3">
                    <Check size={14} className="text-green-400 mt-1 shrink-0" />
                    <span className="text-zinc-300">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Metadata */}
            <div className="pt-4 border-t border-zinc-800 flex items-center justify-between text-xs text-zinc-600">
              <span>Query: {aiAnalysis.query}</span>
              <span>Analyzed: {formatTimestamp(aiAnalysis.timestamp)}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  // ============================================
  // RENDER: REPORTS TAB
  // ============================================

  const renderReports = () => (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white tracking-tight">Executive Reports</h1>
          <p className="text-sm text-zinc-500 mt-1">Professional reports for C-suite and stakeholders</p>
        </div>
        <button 
          onClick={generateExecutiveReport}
          disabled={isLoading}
          className="btn-primary"
        >
          {isLoading ? <Loader2 size={16} className="animate-spin" /> : <FileText size={16} />}
          Generate Report
        </button>
      </div>

      {/* Report Display */}
      {reportData ? (
        <div className="report-container shadow-2xl">
          <div className="border-b pb-4 mb-6">
            <div className="flex items-center justify-between">
              <div>
                <h1>{reportData.title}</h1>
                <p className="text-sm text-zinc-500 mt-1">Generated: {formatTimestamp(reportData.generatedAt)}</p>
              </div>
              <button className="btn-secondary text-sm">
                <Download size={14} />
                Export PDF
              </button>
            </div>
          </div>

          {/* Executive Summary */}
          <section>
            <h2>Executive Summary</h2>
            <p>{reportData.executiveSummary}</p>
          </section>

          {/* Report Sections */}
          {reportData.sections.map((section, idx) => (
            <section key={idx}>
              <h2>{section.title}</h2>
              <p>{section.content}</p>
              
              {section.data && (
                <div className="my-4 p-4 bg-zinc-100 rounded overflow-x-auto">
                  <pre className="text-xs font-mono text-zinc-700 whitespace-pre-wrap">
                    {JSON.stringify(section.data, null, 2)}
                  </pre>
                </div>
              )}
            </section>
          ))}

          <footer className="mt-8 pt-4 border-t text-center text-sm text-zinc-500">
            <p>NEXUS INTEL OSINT Platform · Confidential & Proprietary</p>
            <p className="mt-1">This report was auto-generated. Verify all findings before distribution.</p>
          </footer>
        </div>
      ) : (
        /* Empty State */
        <div className="executive-card">
          <div className="p-12 text-center">
            <FileText size={48} className="mx-auto text-zinc-700 mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">No Report Generated</h3>
            <p className="text-sm text-zinc-500 max-w-md mx-auto">
              Click "Generate Report" to create a comprehensive executive summary of the current threat landscape.
              The report will include vulnerability analysis, threat assessments, and actionable recommendations.
            </p>
          </div>
        </div>
      )}
    </div>
  );

  // ============================================
  // MAIN RENDER
  // ============================================

  return (
    <div className="min-h-screen bg-[#0a0a0b]">
      {/* Top Navigation Bar */}
      <header className="sticky top-0 z-50 bg-[#09090b]/95 backdrop-blur border-b border-zinc-800/50">
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-14">
            {/* Logo */}
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-white rounded flex items-center justify-center">
                <Shield size={18} className="text-black" />
              </div>
              <div>
                <span className="text-sm font-semibold text-white tracking-wide">NEXUS INTEL</span>
                <span className="hidden sm:inline text-xs text-zinc-600 ml-2">OSINT PLATFORM v5.0</span>
              </div>
            </div>

            {/* Status Indicator */}
            <div className="flex items-center gap-4">
              <div className="hidden md:flex items-center gap-2 text-xs text-zinc-500">
                <span className={`status-dot ${threatIntel ? 'status-low' : 'status-medium'}`} />
                <span>{threatIntel ? 'Connected' : 'Connecting...'}</span>
              </div>
              <div className="text-right hidden sm:block">
                <p className="text-xs text-zinc-600">{new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' })}</p>
                <p className="text-xs text-zinc-700">{new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}</p>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="nav-tabs sticky top-14 z-40 bg-[#0a0a0b]">
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6">
          {[
            { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
            { id: 'ip', label: 'IP Intel', icon: Globe },
            { id: 'cve', label: 'CVE Database', icon: Bug },
            { id: 'domain', label: 'Domain Intel', icon: Server },
            { id: 'ai', label: 'AI Analyst', icon: Brain },
            { id: 'reports', label: 'Reports', icon: FileText },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`nav-tab ${activeTab === tab.id ? 'active' : ''}`}
            >
              <tab.icon size={14} className="inline mr-2" />
              {tab.label}
            </button>
          ))}
        </div>
      </nav>

      {/* Loading Overlay */}
      {isLoading && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center">
          <div className="bg-[#111113] border border-zinc-800 rounded-lg p-6 max-w-sm w-full mx-4 text-center">
            <Loader2 size={32} className="animate-spin text-white mx-auto mb-4" />
            <p className="text-white font-medium">{loadingMessage || 'Processing...'}</p>
            <p className="text-xs text-zinc-500 mt-2">This may take a few moments</p>
          </div>
        </div>
      )}

      {/* Notification Toasts */}
      {(error || success) && (
        <div className="fixed top-20 right-4 z-50 max-w-md">
          <div className={`p-4 rounded-lg border shadow-xl ${
            error 
              ? 'bg-red-950/90 border-red-800/50 text-red-200' 
              : 'bg-green-950/90 border-green-800/50 text-green-200'
          }`}>
            <div className="flex items-start gap-3">
              {error ? <X size={16} className="shrink-0 mt-0.5" /> : <Check size={16} className="shrink-0 mt-0.5" />}
              <div className="flex-1">
                <p className="text-sm font-medium">{error || success}</p>
              </div>
              <button onClick={clearNotifications} className="shrink-0 opacity-60 hover:opacity-100">
                <X size={14} />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <main className="max-w-[1600px] mx-auto px-4 sm:px-6 py-6 custom-scrollbar">
        {activeTab === 'dashboard' && renderDashboard()}
        {activeTab === 'ip' && renderIPIntel()}
        {activeTab === 'cve' && renderCVESearch()}
        {activeTab === 'domain' && renderDomainAnalysis()}
        {activeTab === 'ai' && renderAIAnalysis()}
        {activeTab === 'reports' && renderReports()}
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-800/50 mt-12">
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6 py-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="text-xs text-zinc-600">
              © 2024 NEXUS INTEL OSINT Platform. Professional Threat Intelligence.
            </div>
            <div className="flex items-center gap-4 text-xs text-zinc-600">
              <span>Data Sources: NIST NVD, ip-api.com, CISA KEV</span>
              <span>•</span>
              <span>v5.0 Executive Edition</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
