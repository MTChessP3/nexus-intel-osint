'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { 
  Search, Globe, Shield, Bug, FileText, Download, Upload, 
  Trash2, Edit3, Plus, Eye, AlertTriangle, CheckCircle, XCircle,
  Activity, Database, Cpu, Lock, Unlock, RefreshCw, ExternalLink,
  Copy, Filter, ChevronDown, ChevronRight, Zap, Target, Radar,
  Fingerprint, Mail, Hash, Server, Clock, MapPin, Wifi,
  BarChart3, PieChart as PieChartIcon, TrendingUp, Users, Key, Terminal,
  Save, X, Loader2, Check, Info, AlertCircle, ArrowRight
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';

// ==================== TYPES ====================
type TabType = 'dashboard' | 'ip' | 'domain' | 'url' | 'hash' | 'cve' | 'ai' | 'threats' | 'iocs' | 'export' | 'reports';
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
  analyses?: any[];
  alerts?: any[];
}

interface APIResponse {
  success: boolean;
  source?: string;
  timestamp?: string;
  fetchedLive?: boolean;
  data?: any;
  error?: string;
  details?: string;
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

const CHART_COLORS = ['#dc2626', '#f97316', '#eab308', '#22c55e', '#3b82f6'];

// ==================== MAIN COMPONENT ====================
export default function OSINTPlatform() {
  // State
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [loading, setLoading] = useState(false);
  const [apiData, setApiData] = useState<APIResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [selectedIOC, setSelectedIOC] = useState<IOC | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [modalType, setModalType] = useState<'detail' | 'edit' | 'add' | 'raw'>('detail');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  
  // Form states
  const [inputValue, setInputValue] = useState('');
  const [formData, setFormData] = useState({
    type: 'IP',
    value: '',
    description: '',
    severity: 'MEDIUM',
    tags: [] as string[]
  });

  // Load IOCs on mount and tab change
  useEffect(() => {
    loadIOCs();
  }, [activeTab]);

  // ==================== API FUNCTIONS ====================
  const loadIOCs = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (searchQuery) params.set('search', searchQuery);
      if (filterSeverity !== 'all') params.set('severity', filterSeverity);
      if (filterType !== 'all') params.set('type', filterType);
      if (filterStatus !== 'all') params.set('status', filterStatus);
      
      const response = await fetch(`/api/osint/iocs?${params}`);
      const result = await response.json();
      
      if (result.success) {
        setIocs(result.data);
      }
    } catch (err) {
      console.error('Load IOCs error:', err);
    } finally {
      setLoading(false);
    }
  };

  const callAPI = async (endpoint: string, options?: RequestInit): Promise<APIResponse> => {
    setLoading(true);
    setError(null);
    setApiData(null);
    
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
        setError(data.error || data.details || 'Unknown error occurred');
      }
      
      // Reload IOCs after mutations
      if (options?.method === 'POST' || options?.method === 'DELETE') {
        setTimeout(() => loadIOCs(), 500);
      }
      
      return data;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Network error';
      setError(errorMsg);
      return { success: false, error: errorMsg };
    } finally {
      setLoading(false);
    }
  };

  // ==================== HANDLERS ====================
  const handleIPRecon = () => {
    if (!inputValue) return;
    callAPI(`/api/osint/ip?ip=${encodeURIComponent(inputValue)}`);
  };

  const handleDomainRecon = () => {
    if (!inputValue) return;
    callAPI(`/api/osint/domain?domain=${encodeURIComponent(inputValue)}`);
  };

  const handleURLAnalysis = () => {
    if (!inputValue) return;
    callAPI(`/api/osint/url?url=${encodeURIComponent(inputValue)}`);
  };

  const handleHashLookup = () => {
    if (!inputValue) return;
    callAPI(`/api/osint/hash?hash=${encodeURIComponent(inputValue)}`);
  };

  const handleCVESearch = () => {
    if (!inputValue) return;
    const isCVE = inputValue.toUpperCase().startsWith('CVE-');
    const endpoint = isCVE 
      ? `/api/osint/cve?cveId=${encodeURIComponent(inputValue)}`
      : `/api/osint/cve?keyword=${encodeURIComponent(inputValue)}`;
    callAPI(endpoint);
  };

  const handleAIAnalysis = async () => {
    if (!inputValue) return;
    const type = detectInputType(inputValue);
    await callAPI('/api/osint/ai', {
      method: 'POST',
      body: JSON.stringify({ target: inputValue, type })
    });
  };

  const handleThreatFeedLoad = (feed?: string) => {
    const endpoint = feed ? `/api/osint/threats?feed=${feed}&limit=20` : '/api/osint/threats?limit=20';
    callAPI(endpoint);
  };

  const handleAddIOC = async () => {
    if (!formData.value) return;
    await callAPI('/api/osint/iocs', {
      method: 'POST',
      body: JSON.stringify(formData)
    });
    setShowModal(false);
    setFormData({ type: 'IP', value: '', description: '', severity: 'MEDIUM', tags: [] });
  };

  const handleUpdateIOC = async () => {
    if (!selectedIOC) return;
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
    if (!confirm('Are you sure you want to delete this IOC?')) return;
    await callAPI(`/api/osint/iocs?id=${id}`, { method: 'DELETE' });
  };

  const handleExport = async (format: string) => {
    const params = new URLSearchParams({ format });
    if (filterType !== 'all') params.set('type', filterType);
    if (filterSeverity !== 'all') params.set('severity', filterSeverity);
    
    window.open(`/api/osint/export?${params}`, '_blank');
  };

  const handleGenerateReport = () => {
    callAPI('/api/osint/reports?type=executive');
  };

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
      tags: ioc.tags
    });
    setModalType('edit');
    setShowModal(true);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  // ==================== HELPERS ====================
  const detectInputType = (value: string): string => {
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) return 'ip';
    if (/^[a-f0-9]{32}$/i.test(value)) return 'hash'; // MD5
    if (/^[a-f0-9]{40}$/i.test(value)) return 'hash'; // SHA1
    if (/^[a-f0-9]{64}$/i.test(value)) return 'hash'; // SHA256
    if (value.toUpperCase().startsWith('CVE-')) return 'cve';
    if (/^https?:\/\//.test(value)) return 'url';
    if (/\.[a-z]{2,}$/.test(value)) return 'domain';
    if (/@/.test(value)) return 'email';
    return 'general';
  };

  // ==================== CHART DATA ====================
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

  // ==================== RENDER ====================
  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Header */}
      <header className="bg-gray-900 border-b border-gray-800 sticky top-0 z-50">
        <div className="max-w-[1800px] mx-auto px-4 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Radar className="w-8 h-8 text-red-500" />
              <div>
                <h1 className="text-xl font-bold bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent">
                  OSINT Threat Intelligence Platform v8.0
                </h1>
                <p className="text-xs text-gray-400">Real-time Open Source Intelligence</p>
              </div>
            </div>
            
            {/* Global Search */}
            <div className="flex-1 max-w-md mx-8">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search IOCs, IPs, domains, hashes..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && loadIOCs()}
                  className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm focus:border-red-500 focus:outline-none"
                />
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button onClick={() => loadIOCs()} className="p-2 hover:bg-gray-800 rounded-lg" title="Refresh">
                <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
              </button>
              <span className="text-xs text-gray-400">
                {iocs.length} IOCs indexed
              </span>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-[1800px] mx-auto flex">
        {/* Sidebar Navigation */}
        <nav className="w-64 min-h-screen bg-gray-900 border-r border-gray-800 p-4 sticky top-[65px] h-[calc(100vh-65px)] overflow-y-auto">
          <div className="space-y-1">
            {[
              { id: 'dashboard', icon: BarChart3, label: 'Dashboard' },
              { id: 'ip', icon: Globe, label: 'IP Reconnaissance' },
              { id: 'domain', icon: Server, label: 'Domain Analysis' },
              { id: 'url', icon: ExternalLink, label: 'URL Scanner' },
              { id: 'hash', icon: Fingerprint, label: 'Hash Lookup' },
              { id: 'cve', icon: Shield, label: 'CVE Database' },
              { id: 'ai', icon: Cpu, label: 'AI Analyst' },
              { id: 'threats', icon: AlertTriangle, label: 'Threat Feeds' },
              { id: 'iocs', icon: Database, label: 'IOC Manager' },
              { id: 'export', icon: Download, label: 'Export Data' },
              { id: 'reports', icon: FileText, label: 'Reports' },
            ].map(({ id, icon: Icon, label }) => (
              <button
                key={id}
                onClick={() => setActiveTab(id as TabType)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  activeTab === id
                    ? 'bg-red-600 text-white'
                    : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                }`}
              >
                <Icon className="w-4 h-4" />
                {label}
              </button>
            ))}
          </div>

          {/* Quick Stats */}
          <div className="mt-8 p-4 bg-gray-800 rounded-lg">
            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <Activity className="w-4 h-4 text-green-500" /> Live Stats
            </h3>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-gray-400">Critical</span>
                <span className="text-red-400 font-bold">{iocs.filter(i => i.severity === 'CRITICAL').length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Malicious</span>
                <span className="text-red-400 font-bold">{iocs.filter(i => i.status === 'MALICIOUS').length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Total Indexed</span>
                <span className="text-blue-400 font-bold">{iocs.length}</span>
              </div>
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main className="flex-1 p-6">
          {/* ==================== DASHBOARD TAB ==================== */}
          {activeTab === 'dashboard' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold">Intelligence Dashboard</h2>
                <button onClick={() => handleGenerateReport()} className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-sm font-medium">
                  <FileText className="w-4 h-4" /> Generate Report
                </button>
              </div>

              {/* KPI Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {[
                  { label: 'Total IOCs', value: iocs.length, icon: Database, color: 'blue' },
                  { label: 'Critical Alerts', value: iocs.filter(i => i.severity === 'CRITICAL').length, icon: AlertTriangle, color: 'red' },
                  { label: 'Malicious', value: iocs.filter(i => i.status === 'MALICIOUS').length, icon: Bug, color: 'red' },
                  { label: 'Sources Used', value: [...new Set(iocs.map(i => i.source).filter(Boolean))].length, icon: Globe, color: 'green' },
                ].map(({ label, value, icon: Icon, color }) => (
                  <div key={label} className={`bg-gray-900 border border-gray-800 rounded-xl p-5`}>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-gray-400 text-sm">{label}</p>
                        <p className={`text-3xl font-bold mt-1 text-${color}-400`}>{value}</p>
                      </div>
                      <div className={`p-3 rounded-lg bg-${color}-500/10`}>
                        <Icon className={`w-6 h-6 text-${color}-500`} />
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Charts Row */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                  <h3 className="font-semibold mb-4">Severity Distribution</h3>
                  <ResponsiveContainer width="100%" height={250}>
                    <PieChart>
                      <Pie
                        data={severityChartData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={100}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {severityChartData.map((_, index) => (
                          <Cell key={index} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </div>

                <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                  <h3 className="font-semibold mb-4">IOC Types</h3>
                  <ResponsiveContainer width="100%" height={250}>
                    <BarChart data={typeChartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis stroke="#9ca3af" dataKey="name" />
                      <YAxis stroke="#9ca3af" />
                      <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
                      <Bar dataKey="value" fill="#ef4444" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Recent IOCs Table */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold">Recently Added IOCs</h3>
                  <button onClick={() => setActiveTab('iocs')} className="text-sm text-red-400 hover:text-red-300">
                    View All →
                  </button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-gray-800">
                        <th className="text-left py-3 px-2 text-gray-400 font-medium">Type</th>
                        <th className="text-left py-3 px-2 text-gray-400 font-medium">Value</th>
                        <th className="text-left py-3 px-2 text-gray-400 font-medium">Severity</th>
                        <th className="text-left py-3 px-2 text-gray-400 font-medium">Status</th>
                        <th className="text-left py-3 px-2 text-gray-400 font-medium">Source</th>
                        <th className="text-left py-3 px-2 text-gray-400 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {iocs.slice(0, 10).map((ioc) => (
                        <tr key={ioc.id} className="border-b border-gray-800/50 hover:bg-gray-800/30 cursor-pointer" onClick={() => openDetailModal(ioc)}>
                          <td className="py-3 px-2">
                            <span className="px-2 py-1 bg-gray-800 rounded text-xs">{ioc.type}</span>
                          </td>
                          <td className="py-3 px-2 font-mono text-sm">{ioc.value.substring(0, 40)}{ioc.value.length > 40 ? '...' : ''}</td>
                          <td className="py-3 px-2">
                            <span style={{ color: SEVERITY_COLORS[ioc.severity] }} className="font-medium">
                              {ioc.severity}
                            </span>
                          </td>
                          <td className="py-3 px-2">
                            <span style={{ color: STATUS_COLORS[ioc.status] }} className="font-medium">
                              {ioc.status}
                            </span>
                          </td>
                          <td className="py-3 px-2 text-gray-400 text-xs">{ioc.source || '-'}</td>
                          <td className="py-3 px-2">
                            <button onClick={(e) => { e.stopPropagation(); openDetailModal(ioc); }} className="p-1 hover:bg-gray-700 rounded">
                              <Eye className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                      {iocs.length === 0 && (
                        <tr>
                          <td colSpan={6} className="py-8 text-center text-gray-500">
                            No IOCs yet. Start by running reconnaissance or adding manually.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ==================== IP RECONNAISSANCE TAB ==================== */}
          {activeTab === 'ip' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Globe className="w-7 h-7 text-blue-400" /> IP Reconnaissance
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
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-blue-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleIPRecon}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    Analyze IP
                  </button>
                  <button
                    onClick={() => {
                      setModalType('add');
                      setFormData({ ...formData, type: 'IP', value: inputValue });
                      setShowModal(true);
                    }}
                    className="px-4 py-3 bg-gray-700 hover:bg-gray-600 rounded-lg"
                    title="Add to IOC database"
                  >
                    <Plus className="w-4 h-4" />
                  </button>
                </div>
                
                <p className="mt-3 text-xs text-gray-500">
                  Real-time geolocation via ip-api.com • ISP detection • Proxy/VPN identification
                </p>
              </div>

              {/* Results */}
              {apiData?.success && apiData.data && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold flex items-center gap-2">
                      <CheckCircle className="w-5 h-5 text-green-500" /> Live Results
                    </h3>
                    <div className="flex items-center gap-2 text-xs text-gray-400">
                      <Clock className="w-3 h-3" /> {new Date(apiData.timestamp).toLocaleTimeString()}
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded">LIVE</span>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {apiData.data.status === 'success' ? (
                      <>
                        <InfoCard label="IP Address" value={apiData.data.query} icon={<Globe />} />
                        <InfoCard label="Country" value={`${apiData.data.country} (${apiData.data.countryCode})`} icon={<MapPin />} />
                        <InfoCard label="Region" value={`${apiData.data.regionName}, ${apiData.data.city}`} icon={<MapPin />} />
                        <InfoCard label="ISP" value={apiData.data.isp || 'N/A'} icon={<Wifi />} />
                        <InfoCard label="Organization" value={apiData.data.org || 'N/A'} icon={<Server />} />
                        <InfoCard label="AS Number" value={apiData.data.as || 'N/A'} icon={<Server />} />
                        <InfoCard label="Coordinates" value={apiData.data.lat ? `${apiData.data.lat}, ${apiData.data.lon}` : 'N/A'} icon={<MapPin />} />
                        <InfoCard label="Timezone" value={apiData.data.timezone || 'N/A'} icon={<Clock />} />
                        <InfoCard label="Proxy" value={apiData.data.proxy ? 'Yes ⚠️' : 'No ✓'} icon={<Shield />} alert={apiData.data.proxy} />
                        <InfoCard label="Hosting" value={apiData.data.hosting ? 'Yes ⚠️' : 'No ✓'} icon={<Server />} alert={apiData.data.hosting} />
                        <InfoCard label="Mobile" value={apiData.data.mobile ? 'Yes' : 'No'} icon={<Wifi />} />
                        <InfoCard label="Reverse DNS" value={apiData.data.reverse || 'N/A'} icon={<Globe />} />
                      </>
                    ) : (
                      <div className="col-span-full p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                        <AlertCircle className="inline w-5 h-5 text-yellow-500 mr-2" />
                        {apiData.data.message || 'IP lookup failed'}
                      </div>
                    )}
                  </div>

                  {/* Raw JSON View */}
                  <details className="mt-4">
                    <summary className="cursor-pointer text-sm text-gray-400 hover:text-white">View Raw JSON Response</summary>
                    <pre className="mt-2 p-4 bg-gray-950 rounded-lg overflow-x-auto text-xs">
                      {JSON.stringify(apiData.data, null, 2)}
                    </pre>
                  </details>
                </div>
              )}

              {error && (
                <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400">
                  <XCircle className="inline w-5 h-5 mr-2" />
                  {error}
                </div>
              )}
            </div>
          )}

          {/* ==================== DOMAIN ANALYSIS TAB ==================== */}
          {activeTab === 'domain' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Server className="w-7 h-7 text-purple-400" /> Domain Analysis
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
                    Analyze Domain
                  </button>
                  <button
                    onClick={() => {
                      setModalType('add');
                      setFormData({ ...formData, type: 'DOMAIN', value: inputValue });
                      setShowModal(true);
                    }}
                    className="px-4 py-3 bg-gray-700 hover:bg-gray-600 rounded-lg"
                  >
                    <Plus className="w-4 h-4" />
                  </button>
                </div>
                <p className="mt-3 text-xs text-gray-500">
                  Google DoH resolution • MX/NS/TXT records • SPF & DMARC analysis
                </p>
              </div>

              {apiData?.dns && (
                <div className="space-y-4">
                  {/* DNS Records */}
                  {(['A', 'MX', 'NS', 'TXT', 'AAAA'] as const).map((type) => (
                    <div key={type} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <span className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs">{type} Records</span>
                        {apiData.dns[type]?.Answer && (
                          <span className="text-xs text-gray-400">{apiData.dns[type].Answer.length} records</span>
                        )}
                      </h3>
                      
                      {apiData.dns[type]?.Answer ? (
                        <div className="space-y-2">
                          {apiData.dns[type].Answer.map((record: any, idx: number) => (
                            <div key={idx} className="flex items-center gap-3 p-2 bg-gray-800/50 rounded font-mono text-sm">
                              <span className="text-gray-400">{record.name}</span>
                              <ArrowRight className="w-3 h-3 text-gray-600" />
                              <span className="text-white">{record.data}</span>
                              <span className="ml-auto text-xs text-gray-500">TTL: {record.TTL}s</span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-gray-500 text-sm">No {type} records found</p>
                      )}
                    </div>
                  ))}

                  {/* Security Analysis */}
                  {apiData.securityAnalysis && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Lock className="w-5 h-5 text-yellow-500" /> Security Analysis
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <SecurityCheck label="SPF Record" pass={apiData.securityAnalysis.hasSPF} />
                        <SecurityCheck label="DMARC Record" pass={apiData.securityAnalysis.hasDMARC} />
                        <SecurityCheck label="Mail Servers" pass={!!apiData.securityAnalysis.findings.find(f => f.includes('Mail servers'))} />
                      </div>
                      <div className="mt-4 space-y-2">
                        {apiData.securityAnalysis.findings.map((finding: string, idx: number) => (
                          <div key={idx} className={`p-3 rounded-lg text-sm ${finding.includes('WARNING') ? 'bg-yellow-500/10 text-yellow-400' : 'bg-gray-800 text-gray-300'}`}>
                            {finding.includes('WARNING') && <AlertTriangle className="inline w-4 h-4 mr-2" />}
                            {finding}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {error && (
                <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400">
                  <XCircle className="inline w-5 h-5 mr-2" />
                  {error}
                </div>
              )}
            </div>
          )}

          {/* ==================== URL SCANNER TAB ==================== */}
          {activeTab === 'url' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <ExternalLink className="w-7 h-7 text-cyan-400" /> URL Scanner
              </h2>
              
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter URL (e.g., https://example.com/page)"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleURLAnalysis()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-cyan-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleURLAnalysis}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    Scan URL
                  </button>
                </div>
              </div>

              {apiData?.riskAssessment && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold">Risk Assessment</h3>
                    <span className={`px-3 py-1 rounded-full text-sm font-bold ${
                      apiData.riskAssessment.level === 'HIGH' ? 'bg-red-500/20 text-red-400' :
                      apiData.riskAssessment.level === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      Risk: {apiData.riskAssessment.level}
                    </span>
                  </div>
                  
                  <div className="mb-4">
                    <div className="flex justify-between text-sm mb-1">
                      <span>Risk Score</span>
                      <span>{apiData.riskAssessment.score}/100</span>
                    </div>
                    <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                      <div 
                        className={`h-full transition-all ${
                          apiData.riskAssessment.score >= 70 ? 'bg-red-500' :
                          apiData.riskAssessment.score >= 50 ? 'bg-yellow-500' : 'bg-green-500'
                        }`}
                        style={{ width: `${apiData.riskAssessment.score}%` }}
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    {apiData.riskAssessment.findings.map((finding: string, idx: number) => (
                      <div key={idx} className={`p-3 rounded text-sm ${
                        finding.includes('WARNING') || finding.includes('SUSPICIOUS') 
                          ? 'bg-red-500/10 text-red-300' 
                          : 'bg-gray-800 text-gray-300'
                      }`}>
                        {finding.includes('WARNING') || finding.includes('SUSPICIOUS') ? (
                          <AlertTriangle className="inline w-4 h-4 mr-2" />
                        ) : (
                          <Info className="inline w-4 h-4 mr-2" />
                        )}
                        {finding}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ==================== HASH LOOKUP TAB ==================== */}
          {activeTab === 'hash' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Fingerprint className="w-7 h-7 text-orange-400" /> Malware Hash Lookup
              </h2>
              
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter hash (MD5, SHA1, SHA256)"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleHashLookup()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg font-mono focus:border-orange-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleHashLookup}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-orange-600 hover:bg-orange-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    Lookup Hash
                  </button>
                </div>
                <p className="mt-3 text-xs text-gray-500">
                  MalwareBazaar • VirusTotal public API • Real malware intelligence
                </p>
              </div>

              {apiData?.analysis && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold">Analysis Result</h3>
                    <span className={`px-3 py-1 rounded-full text-sm font-bold ${
                      apiData.analysis.threatLevel === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                      apiData.analysis.threatLevel === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                      'bg-yellow-500/20 text-yellow-400'
                    }`}>
                      {apiData.analysis.threatLevel}
                    </span>
                  </div>
                  
                  <div className="space-y-3">
                    <div className="p-3 bg-gray-800 rounded-lg">
                      <span className="text-gray-400 text-sm">Hash Type:</span>
                      <span className="ml-2 font-mono">{apiData.hashType}</span>
                    </div>
                    
                    {apiData.analysis.findings.map((finding: string, idx: number) => (
                      <div key={idx} className="p-3 bg-gray-800/50 rounded text-sm text-gray-300">
                        <CheckCircle className="inline w-4 h-4 text-blue-400 mr-2" />
                        {finding}
                      </div>
                    ))}

                    <div className={`p-4 rounded-lg mt-4 ${
                      apiData.analysis.recommendation.includes('ISOLATE') ? 'bg-red-500/10 border border-red-500/30' :
                      apiData.analysis.recommendation.includes('Quarantine') ? 'bg-orange-500/10 border border-orange-500/30' :
                      'bg-blue-500/10 border border-blue-500/30'
                    }`}>
                      <strong>Recommendation:</strong> {apiData.analysis.recommendation}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ==================== CVE DATABASE TAB ==================== */}
          {activeTab === 'cve' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Shield className="w-7 h-7 text-red-400" /> CVE Database (NIST NVD)
              </h2>
              
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Enter CVE ID (e.g., CVE-2024-1234) or keyword"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleCVESearch()}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-red-500 focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={handleCVESearch}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    Search NVD
                  </button>
                </div>
                <p className="mt-3 text-xs text-gray-500">
                  Official NIST National Vulnerability Database v2.0 • CVSS scores • CWE classification
                </p>
              </div>

              {apiData?.vulnerabilities && (
                <div className="space-y-4">
                  <p className="text-sm text-gray-400">
                    Found {apiData.totalResults} results (showing {apiData.vulnerabilities.length})
                  </p>
                  
                  {apiData.vulnerabilities.map((vuln: any, idx: number) => {
                    const cve = vuln.id || vuln.cve?.id;
                    const metrics = vuln.metrics || vuln.cve?.metrics;
                    const cvssScore = metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore;
                    const descriptions = vuln.descriptions || vuln.cve?.descriptions;
                    const desc = descriptions?.find((d: any) => d.lang === 'en')?.value;
                    
                    return (
                      <div key={idx} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                        <div className="flex items-start justify-between">
                          <div>
                            <h3 className="font-bold text-lg text-red-400 font-mono">{cve}</h3>
                            <p className="text-sm text-gray-300 mt-2 line-clamp-3">{desc}</p>
                          </div>
                          {cvssScore && (
                            <div className={`px-3 py-2 rounded-lg text-center ml-4 ${
                              cvssScore >= 9 ? 'bg-red-500/20 text-red-400' :
                              cvssScore >= 7 ? 'bg-orange-500/20 text-orange-400' :
                              cvssScore >= 4 ? 'bg-yellow-500/20 text-yellow-400' :
                              'bg-green-500/20 text-green-400'
                            }`}>
                              <div className="text-2xl font-bold">{cvssScore}</div>
                              <div className="text-xs">CVSS</div>
                            </div>
                          )}
                        </div>
                        
                        {vuln.references?.length > 0 && (
                          <div className="mt-4 flex flex-wrap gap-2">
                            {vuln.references.slice(0, 5).map((ref: any, rIdx: number) => (
                              <a
                                key={rIdx}
                                href={ref.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                              >
                                <ExternalLink className="w-3 h-3" />
                                {new URL(ref.url).hostname}
                              </a>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* ==================== AI ANALYST TAB ==================== */}
          {activeTab === 'ai' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Cpu className="w-7 h-7 text-emerald-400" /> AI Threat Analyst
              </h2>
              
              <div className="bg-gradient-to-br from-gray-900 to-gray-800 border border-gray-700 rounded-xl p-6">
                <p className="text-gray-300 mb-4">
                  Powered by z-ai-web-dev-sdk. Enter any IP, domain, hash, or threat indicator for AI-powered OSINT analysis.
                </p>
                
                <div className="flex gap-4">
                  <div className="flex-1">
                    <textarea
                      placeholder="Enter target for AI analysis...&#10;Examples:&#10;• 185.220.101.34&#10;• suspicious-domain.com&#10;• af35c... (malware hash)&#10;• APT29 tactics"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      rows={4}
                      className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-emerald-500 focus:outline-none resize-none"
                    />
                  </div>
                </div>
                
                <div className="flex gap-3 mt-4">
                  <button
                    onClick={handleAIAnalysis}
                    disabled={loading || !inputValue}
                    className="px-6 py-3 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 rounded-lg font-medium flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                    Run AI Analysis
                  </button>
                </div>
              </div>

              {apiData?.analysis && (
                <div className="bg-gray-900 border border-emerald-500/30 rounded-xl p-6">
                  <div className="flex items-center gap-2 mb-4">
                    <Zap className="w-5 h-5 text-emerald-500" />
                    <h3 className="font-semibold">AI Analysis Complete</h3>
                    <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 rounded text-xs">AI Generated</span>
                  </div>
                  
                  <div className="space-y-4">
                    <div className="p-4 bg-gray-800 rounded-lg">
                      <h4 className="text-sm text-gray-400 mb-2">Executive Summary</h4>
                      <p className="text-white">{apiData.analysis.summary}</p>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-4 bg-gray-800 rounded-lg">
                        <h4 className="text-sm text-gray-400 mb-2">Threat Level</h4>
                        <span className={`text-2xl font-bold ${
                          apiData.analysis.threatLevel === 'CRITICAL' ? 'text-red-400' :
                          apiData.analysis.threatLevel === 'HIGH' ? 'text-orange-400' : 'text-yellow-400'
                        }`}>
                          {apiData.analysis.threatLevel}
                        </span>
                      </div>
                      <div className="p-4 bg-gray-800 rounded-lg">
                        <h4 className="text-sm text-gray-400 mb-2">Confidence</h4>
                        <span className="text-2xl font-bold text-blue-400">{apiData.analysis.confidence}%</span>
                      </div>
                    </div>

                    {apiData.analysis.keyFindings?.length > 0 && (
                      <div className="p-4 bg-gray-800 rounded-lg">
                        <h4 className="text-sm text-gray-400 mb-2">Key Findings</h4>
                        <ul className="space-y-2">
                          {apiData.analysis.keyFindings.map((finding: string, idx: number) => (
                            <li key={idx} className="flex items-start gap-2 text-sm">
                              <Target className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                              {finding}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {apiData.analysis.indicators?.length > 0 && (
                      <div className="p-4 bg-gray-800 rounded-lg">
                        <h4 className="text-sm text-gray-400 mb-2">Related Indicators</h4>
                        <div className="space-y-2">
                          {apiData.analysis.indicators.map((ind: any, idx: number) => (
                            <div key={idx} className="flex items-center gap-2 p-2 bg-gray-700/50 rounded font-mono text-sm">
                              <span className="px-2 py-0.5 bg-gray-600 rounded text-xs">{ind.type}</span>
                              <span>{ind.value}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {apiData.analysis.recommendations?.length > 0 && (
                      <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                        <h4 className="text-sm text-blue-400 mb-2">Recommendations</h4>
                        <ul className="space-y-2">
                          {apiData.analysis.recommendations.map((rec: string, idx: number) => (
                            <li key={idx} className="flex items-start gap-2 text-sm text-blue-200">
                              <CheckCircle className="w-4 h-4 mt-0.5 shrink-0" />
                              {rec}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ==================== THREAT FEEDS TAB ==================== */}
          {activeTab === 'threats' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <AlertTriangle className="w-7 h-7 text-yellow-400" /> Live Threat Feeds
              </h2>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[
                  { id: 'cisa', name: 'CISA KEV', desc: 'Known Exploited Vulnerabilities', icon: Shield, color: 'red' },
                  { id: 'abusech', name: 'AbuseCH SSLBL', desc: 'Malicious SSL Certificates', icon: Lock, color: 'orange' },
                  { id: 'malwaredl', name: 'MalwareBazaar', desc: 'Recent Malware Samples', icon: Bug, color: 'purple' },
                ].map(({ id, name, desc, icon: Icon, color }) => (
                  <button
                    key={id}
                    onClick={() => handleThreatFeedLoad(id)}
                    disabled={loading}
                    className="p-5 bg-gray-900 border border-gray-800 rounded-xl hover:border-${color}-500 transition-colors text-left disabled:opacity-50"
                  >
                    <Icon className={`w-8 h-8 text-${color}-400 mb-3`} />
                    <h3 className="font-semibold">{name}</h3>
                    <p className="text-sm text-gray-400 mt-1">{desc}</p>
                    <span className="inline-block mt-3 text-xs text-${color}-400">Click to load →</span>
                  </button>
                ))}
                
                <button
                  onClick={() => handleThreatFeedLoad()}
                  disabled={loading}
                  className="p-5 bg-gray-900 border border-dashed border-gray-700 rounded-xl hover:border-gray-500 transition-colors text-left col-span-full"
                >
                  <RefreshCw className="w-8 h-8 text-gray-400 mb-3" />
                  <h3 className="font-semibold">Load All Feeds</h3>
                  <p className="text-sm text-gray-400 mt-1">Fetch latest from all sources simultaneously</p>
                </button>
              </div>

              {apiData?.feeds && (
                <div className="space-y-6">
                  {apiData.feeds.map((feed: any, fIdx: number) => (
                    <div key={fIdx} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="font-semibold flex items-center gap-2">
                          <Globe className="w-5 h-5 text-blue-400" />
                          {feed.source}
                          <span className="text-xs text-gray-400">({feed.count} entries)</span>
                        </h3>
                        <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">LIVE</span>
                      </div>
                      
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b border-gray-800">
                              {Object.keys(feed.entries[0] || {}).slice(0, 5).map((key) => (
                                <th key={key} className="text-left py-2 px-2 text-gray-400 font-medium capitalize">
                                  {key.replace(/([A-Z])/g, ' $1').trim()}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {feed.entries.slice(0, 10).map((entry: any, eIdx: number) => (
                              <tr key={eIdx} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                                {Object.values(entry).slice(0, 5).map((val: any, vIdx: number) => (
                                  <td key={vIdx} className="py-2 px-2 text-gray-300 truncate max-w-[200px]">
                                    {typeof val === 'string' && val.length > 40 ? val.substring(0, 40) + '...' : String(val)}
                                  </td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ==================== IOC MANAGER TAB ==================== */}
          {activeTab === 'iocs' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <Database className="w-7 h-7 text-indigo-400" /> IOC Manager
                </h2>
                <button
                  onClick={() => {
                    setFormData({ type: 'IP', value: '', description: '', severity: 'MEDIUM', tags: [] });
                    setModalType('add');
                    setShowModal(true);
                  }}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-lg font-medium flex items-center gap-2"
                >
                  <Plus className="w-4 h-4" /> Add IOC
                </button>
              </div>

              {/* Filters */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <div className="flex flex-wrap gap-4">
                  <div className="flex items-center gap-2">
                    <Filter className="w-4 h-4 text-gray-400" />
                    <select
                      value={filterType}
                      onChange={(e) => setFilterType(e.target.value)}
                      className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm"
                    >
                      <option value="all">All Types</option>
                      <option value="IP">IP</option>
                      <option value="DOMAIN">Domain</option>
                      <option value="URL">URL</option>
                      <option value="HASH">Hash</option>
                      <option value="CVE">CVE</option>
                      <option value="EMAIL">Email</option>
                    </select>
                  </div>
                  
                  <select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm"
                  >
                    <option value="all">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="INFO">Info</option>
                  </select>
                  
                  <select
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value)}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm"
                  >
                    <option value="all">All Statuses</option>
                    <option value="MALICIOUS">Malicious</option>
                    <option value="SUSPICIOUS">Suspicious</option>
                    <option value="UNKNOWN">Unknown</option>
                    <option value="BENIGN">Benign</option>
                  </select>
                  
                  <button onClick={loadIOCs} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">
                    Apply Filters
                  </button>
                </div>
              </div>

              {/* IOC Table */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-800">
                      <tr>
                        <th className="text-left py-3 px-4 text-gray-400 font-medium">Type</th>
                        <th className="text-left py-3 px-4 text-gray-400 font-medium">Value</th>
                        <th className="text-left py-3 px-4 text-gray-400 font-medium">Description</th>
                        <th className="text-left py-3 px-4 text-gray-400 font-medium">Severity</th>
                        <th className="text-left py-3 px-4 text-gray-400 font-medium">Status</th>
                        <th className="text-left py-3 px-4 text-gray-400 font-medium">Confidence</th>
                        <th className="text-left py-3 px-4 text-gray-400 font-medium">Source</th>
                        <th className="text-left py-3 px-4 text-gray-400 font-medium">Updated</th>
                        <th className="text-right py-3 px-4 text-gray-400 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {iocs.map((ioc) => (
                        <tr key={ioc.id} className="border-t border-gray-800 hover:bg-gray-800/50">
                          <td className="py-3 px-4">
                            <span className="px-2 py-1 bg-gray-700 rounded text-xs font-mono">{ioc.type}</span>
                          </td>
                          <td className="py-3 px-4 font-mono text-sm max-w-[200px] truncate" title={ioc.value}>
                            {ioc.value}
                          </td>
                          <td className="py-3 px-4 text-gray-400 max-w-[250px] truncate" title={ioc.description}>
                            {ioc.description}
                          </td>
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
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2">
                              <div className="w-16 h-2 bg-gray-700 rounded-full overflow-hidden">
                                <div 
                                  className="h-full bg-blue-500"
                                  style={{ width: `${ioc.confidence}%` }}
                                />
                              </div>
                              <span className="text-xs text-gray-400">{ioc.confidence}%</span>
                            </div>
                          </td>
                          <td className="py-3 px-4 text-gray-400 text-xs">{ioc.source || '-'}</td>
                          <td className="py-3 px-4 text-gray-400 text-xs">
                            {new Date(ioc.lastUpdated).toLocaleDateString()}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <div className="flex items-center justify-end gap-1">
                              <button onClick={() => openDetailModal(ioc)} className="p-1.5 hover:bg-gray-700 rounded" title="View Details">
                                <Eye className="w-4 h-4" />
                              </button>
                              <button onClick={() => openEditModal(ioc)} className="p-1.5 hover:bg-gray-700 rounded" title="Edit">
                                <Edit3 className="w-4 h-4" />
                              </button>
                              <button onClick={() => copyToClipboard(ioc.value)} className="p-1.5 hover:bg-gray-700 rounded" title="Copy">
                                <Copy className="w-4 h-4" />
                              </button>
                              <button onClick={() => handleDeleteIOC(ioc.id)} className="p-1.5 hover:bg-red-500/20 text-red-400 rounded" title="Delete">
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                      {iocs.length === 0 && (
                        <tr>
                          <td colSpan={9} className="py-12 text-center text-gray-500">
                            <Database className="w-12 h-12 mx-auto mb-3 opacity-50" />
                            <p>No IOCs found. Add some manually or run reconnaissance.</p>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ==================== EXPORT TAB ==================== */}
          {activeTab === 'export' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold flex items-center gap-3">
                <Download className="w-7 h-7 text-green-400" /> Export Intelligence Data
              </h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                  <FileText className="w-10 h-10 text-blue-400 mb-4" />
                  <h3 className="font-semibold text-lg mb-2">JSON Export</h3>
                  <p className="text-gray-400 text-sm mb-4">
                    Full structured export with all IOC metadata, analyses, and alerts in machine-readable format.
                  </p>
                  <button
                    onClick={() => handleExport('json')}
                    className="w-full px-4 py-3 bg-blue-600 hover:bg-blue-700 rounded-lg font-medium flex items-center justify-center gap-2"
                  >
                    <Download className="w-4 h-4" /> Export JSON
                  </button>
                </div>

                <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                  <FileText className="w-10 h-10 text-green-400 mb-4" />
                  <h3 className="font-semibold text-lg mb-2">CSV Export</h3>
                  <p className="text-gray-400 text-sm mb-4">
                    Spreadsheet-compatible format for Excel, SIEM import, or further analysis.
                  </p>
                  <button
                    onClick={() => handleExport('csv')}
                    className="w-full px-4 py-3 bg-green-600 hover:bg-green-700 rounded-lg font-medium flex items-center justify-center gap-2"
                  >
                    <Download className="w-4 h-4" /> Export CSV
                  </button>
                </div>
              </div>

              <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <h3 className="font-semibold mb-4">Export Options</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-2">Filter by Type</label>
                    <select
                      value={filterType}
                      onChange={(e) => setFilterType(e.target.value)}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm"
                    >
                      <option value="all">All Types</option>
                      <option value="IP">IP</option>
                      <option value="DOMAIN">Domain</option>
                      <option value="URL">URL</option>
                      <option value="HASH">Hash</option>
                      <option value="CVE">CVE</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-2">Filter by Severity</label>
                    <select
                      value={filterSeverity}
                      onChange={(e) => setFilterSeverity(e.target.value)}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm"
                    >
                      <option value="all">All Severities</option>
                      <option value="CRITICAL">Critical Only</option>
                      <option value="HIGH">High+</option>
                      <option value="MEDIUM">Medium+</option>
                    </select>
                  </div>
                </div>
              </div>

              <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4">
                <h4 className="font-medium mb-2 flex items-center gap-2">
                  <Info className="w-4 h-4 text-blue-400" /> Export Summary
                </h4>
                <p className="text-sm text-gray-400">
                  Current selection: <strong>{iocs.length} IOCs</strong> will be exported.
                  {filterType !== 'all' && ` Filtered by type: ${filterType}`}
                  {filterSeverity !== 'all' && ` Filtered by severity: ${filterSeverity}`}
                </p>
              </div>
            </div>
          )}

          {/* ==================== REPORTS TAB ==================== */}
          {activeTab === 'reports' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold flex items-center gap-3">
                  <FileText className="w-7 h-7 text-pink-400" /> Executive Reports
                </h2>
                <button
                  onClick={handleGenerateReport}
                  disabled={loading}
                  className="px-4 py-2 bg-pink-600 hover:bg-pink-700 rounded-lg font-medium flex items-center gap-2"
                >
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4" />}
                  Generate Report
                </button>
              </div>

              {apiData?.executiveSummary && (
                <div className="space-y-6">
                  {/* Executive Summary Card */}
                  <div className="bg-gradient-to-br from-gray-900 to-gray-800 border border-pink-500/30 rounded-xl p-6">
                    <h3 className="font-semibold text-lg mb-4 flex items-center gap-2">
                      <BarChart3 className="w-5 h-5 text-pink-400" /> Executive Summary
                    </h3>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <StatCard label="Total IOCs" value={apiData.executiveSummary.totalIOCs} />
                      <StatCard label="Active Alerts" value={apiData.executiveSummary.activeAlerts} color="red" />
                      <StatCard label="Critical Items" value={apiData.executiveSummary.criticalIOCs} color="red" />
                      <StatCard label="Malicious" value={apiData.executiveSummary.maliciousIOCs} color="red" />
                    </div>
                    <div className="mt-4 p-3 bg-gray-800/50 rounded-lg">
                      <p className="text-sm text-gray-400">
                        <strong>Sources covered:</strong> {apiData.executiveSummary.sourcesCovered.join(', ') || 'None yet'}
                      </p>
                    </div>
                  </div>

                  {/* Charts Row */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-4">Severity Breakdown</h3>
                      <div className="space-y-3">
                        {Object.entries(apiData.severityBreakdown || {}).map(([key, value]: [string, any]) => (
                          <div key={key} className="flex items-center gap-3">
                            <span className="w-20 text-sm text-gray-400">{key}</span>
                            <div className="flex-1 h-6 bg-gray-800 rounded overflow-hidden">
                              <div
                                className="h-full rounded"
                                style={{
                                  width: `${(value / Math.max(...Object.values(apiData.severityBreakdown))) * 100}%`,
                                  backgroundColor: SEVERITY_COLORS[key as Severity]
                                }}
                              />
                            </div>
                            <span className="w-10 text-right text-sm font-mono">{value}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-4">Type Distribution</h3>
                      <ResponsiveContainer width="100%" height={250}>
                        <PieChart>
                          <Pie
                            data={Object.entries(apiData.typeDistribution || {}).map(([name, value]) => ({ name, value }))}
                            innerRadius={60}
                            outerRadius={100}
                            paddingAngle={5}
                            dataKey="value"
                          >
                            {CHART_COLORS.map((color, index) => (
                              <Cell key={index} fill={color} />
                            ))}
                          </Pie>
                          <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Top Threats */}
                  {apiData.topThreats?.length > 0 && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-4 flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-yellow-400" /> Top Active Threats
                      </h3>
                      <div className="space-y-2">
                        {apiData.topThreats.map((threat: any, idx: number) => (
                          <div key={idx} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg">
                            <div className="flex items-center gap-3">
                              <span className="text-gray-500 text-sm">#{idx + 1}</span>
                              <span className="font-medium">{threat.title}</span>
                            </div>
                            <div className="flex items-center gap-3">
                              <span className={`px-2 py-1 rounded text-xs ${
                                threat.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                                threat.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                                'bg-yellow-500/20 text-yellow-400'
                              }`}>
                                {threat.severity}
                              </span>
                              <span className="text-xs text-gray-500">
                                {new Date(threat.createdAt).toLocaleDateString()}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recent Intelligence */}
                  {apiData.recentIntelligence?.length > 0 && (
                    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                      <h3 className="font-semibold mb-4">Recent Intelligence</h3>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b border-gray-800">
                              <th className="text-left py-2 px-3 text-gray-400">Type</th>
                              <th className="text-left py-2 px-3 text-gray-400">Value</th>
                              <th className="text-left py-2 px-3 text-gray-400">Severity</th>
                              <th className="text-left py-2 px-3 text-gray-400">Status</th>
                              <th className="text-left py-2 px-3 text-gray-400">Source</th>
                            </tr>
                          </thead>
                          <tbody>
                            {apiData.recentIntelligence.map((item: any, idx: number) => (
                              <tr key={idx} className="border-b border-gray-800/50">
                                <td className="py-2 px-3"><span className="px-2 py-0.5 bg-gray-700 rounded text-xs">{item.type}</span></td>
                                <td className="py-2 px-3 font-mono text-sm">{item.value}</td>
                                <td className="py-2 px-3"><span style={{ color: SEVERITY_COLORS[item.severity] }}>{item.severity}</span></td>
                                <td className="py-2 px-3"><span style={{ color: STATUS_COLORS[item.status] }}>{item.status}</span></td>
                                <td className="py-2 px-3 text-gray-400 text-xs">{item.source || '-'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {!apiData && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
                  <FileText className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                  <h3 className="text-lg font-semibold mb-2">No Report Generated Yet</h3>
                  <p className="text-gray-400 mb-4">Click "Generate Report" to create an executive summary of all collected intelligence.</p>
                </div>
              )}
            </div>
          )}
        </main>
      </div>

      {/* ==================== MODAL ==================== */}
      {showModal && selectedIOC && modalType === 'detail' && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setShowModal(false)}>
          <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-3xl w-full max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="sticky top-0 bg-gray-900 border-b border-gray-800 p-4 flex items-center justify-between">
              <h3 className="font-bold text-lg">IOC Details</h3>
              <button onClick={() => setShowModal(false)} className="p-2 hover:bg-gray-800 rounded-lg">
                <X className="w-5 h-5" />
              </button>
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
                <div className="col-span-2"><span className="text-gray-400 text-sm">Description:</span><p>{selectedIOC.description}</p></div>
                <div><span className="text-gray-400 text-sm">First Seen:</span><p>{new Date(selectedIOC.firstSeen).toLocaleString()}</p></div>
                <div><span className="text-gray-400 text-sm">Last Updated:</span><p>{new Date(selectedIOC.lastUpdated).toLocaleString()}</p></div>
              </div>
              
              {selectedIOC.tags?.length > 0 && (
                <div className="flex flex-wrap gap-2 pt-4 border-t border-gray-800">
                  {selectedIOC.tags.map((tag, idx) => (
                    <span key={idx} className="px-2 py-1 bg-gray-700 rounded text-xs">{tag}</span>
                  ))}
                </div>
              )}

              {selectedIOC.rawResponse && (
                <details className="pt-4 border-t border-gray-800">
                  <summary className="cursor-pointer text-sm text-gray-400 hover:text-white">View Raw API Response</summary>
                  <pre className="mt-2 p-4 bg-gray-950 rounded-lg overflow-x-auto text-xs max-h-60 overflow-y-auto">
                    {typeof selectedIOC.rawResponse === 'string' 
                      ? JSON.stringify(JSON.parse(selectedIOC.rawResponse), null, 2)
                      : JSON.stringify(selectedIOC.rawResponse, null, 2)
                    }
                  </pre>
                </details>
              )}
            </div>
            
            <div className="sticky bottom-0 bg-gray-900 border-t border-gray-800 p-4 flex justify-end gap-3">
              <button onClick={() => { setModalType('edit'); }} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm">
                <Edit3 className="w-4 h-4 inline mr-1" /> Edit
              </button>
              <button onClick={() => { handleDeleteIOC(selectedIOC.id); setShowModal(false); }} className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-sm">
                <Trash2 className="w-4 h-4 inline mr-1" /> Delete
              </button>
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
              <button onClick={() => setShowModal(false)} className="p-2 hover:bg-gray-800 rounded-lg">
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Type *</label>
                <select
                  value={formData.type}
                  onChange={(e) => setFormData({...formData, type: e.target.value})}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                  disabled={modalType === 'edit'}
                >
                  <option value="IP">IP Address</option>
                  <option value="DOMAIN">Domain</option>
                  <option value="URL">URL</option>
                  <option value="HASH">Hash (MD5/SHA)</option>
                  <option value="CVE">CVE ID</option>
                  <option value="EMAIL">Email</option>
                </select>
              </div>
              
              <div>
                <label className="block text-sm text-gray-400 mb-1">Value *</label>
                <input
                  type="text"
                  value={formData.value}
                  onChange={(e) => setFormData({...formData, value: e.target.value})}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg font-mono"
                  placeholder={modalType === 'add' ? 'Enter indicator value...' : ''}
                  disabled={modalType === 'edit'}
                />
              </div>
              
              <div>
                <label className="block text-sm text-gray-400 mb-1">Description</label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({...formData, description: e.target.value})}
                  rows={3}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg resize-none"
                  placeholder="Add context about this indicator..."
                />
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Severity</label>
                  <select
                    value={formData.severity}
                    onChange={(e) => setFormData({...formData, severity: e.target.value})}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="INFO">Info</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Tags (comma separated)</label>
                  <input
                    type="text"
                    value={formData.tags.join(', ')}
                    onChange={(e) => setFormData({...formData, tags: e.target.value.split(',').map(t => t.trim()).filter(Boolean)})}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg"
                    placeholder="tag1, tag2..."
                  />
                </div>
              </div>
            </div>
            
            <div className="border-t border-gray-800 p-4 flex justify-end gap-3">
              <button onClick={() => setShowModal(false)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg">
                Cancel
              </button>
              <button
                onClick={modalType === 'add' ? handleAddIOC : handleUpdateIOC}
                disabled={!formData.value}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 rounded-lg"
              >
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
      <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
        {icon}
        {label}
      </div>
      <div className={`font-medium text-sm ${alert ? 'text-red-400' : ''}`}>{value}</div>
    </div>
  );
}

function SecurityCheck({ label, pass }: { label: string; pass: boolean }) {
  return (
    <div className={`p-3 rounded-lg flex items-center gap-3 ${pass ? 'bg-green-500/10' : 'bg-red-500/10'}`}>
      {pass ? (
        <CheckCircle className="w-5 h-5 text-green-500" />
      ) : (
        <XCircle className="w-5 h-5 text-red-500" />
      )}
      <div>
        <p className="font-medium text-sm">{label}</p>
        <p className={`text-xs ${pass ? 'text-green-400' : 'text-red-400'}`}>
          {pass ? 'Configured' : 'Not Found'}
        </p>
      </div>
    </div>
  );
}

function StatCard({ label, value, color = 'blue' }: { label: string; value: number; color?: string }) {
  return (
    <div className="p-4 bg-gray-800/50 rounded-lg text-center">
      <p className="text-3xl font-bold text-{color}-400">{value}</p>
      <p className="text-sm text-gray-400 mt-1">{label}</p>
    </div>
  );
}
