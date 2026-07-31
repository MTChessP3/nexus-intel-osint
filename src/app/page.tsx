'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Shield, Search, Globe, AlertTriangle, CheckCircle2, 
  XCircle, Activity, FileText, Download, ExternalLink,
  MapPin, Server, Fingerprint, Bug, Link, Hash, Target,
  Clock, Database, Network, Terminal, BarChart3,
  RefreshCw, ChevronRight, Info, Eye, Brain, Cpu, Zap,
  Lock, Unlock, Radio, Wifi, UserCheck, UserX, Globe2,
  FileWarning, ShieldAlert, ShieldCheck, TrendingUp, TrendingDown,
  ArrowRight, Copy, Check, Loader2, Send, Sparkles
} from 'lucide-react';

// ============= PROFESSIONAL TYPES =============
interface IPResult {
  query: string;
  geolocation: {
    country: string; countryCode: string; region: string;
    city: string; latitude: number; longitude: number; timezone: string;
  };
  network: {
    isp: string; org: string; asn: string; asFull: string;
    isMobile: boolean; isProxy: boolean; isHosting: boolean;
  };
  threat: {
    score: number; level: string; color: string; icon: string;
    indicators: string[]; recommendations: string[];
  };
  metadata?: any;
}

interface DomainResult {
  domain: string;
  whois: any;
  dns: any;
  security: any;
  reputation: {
    score: number; level: string; color: string;
    indicators: string[]; recommendations: string[];
  };
}

interface CVEResult {
  id: string;
  descriptions: string;
  cvss: { score: number | null; severity: string; vector: string; version: string };
  cwe: string[];
  references: any[];
  dates: any;
  status: string;
}

interface URLResult {
  url: string;
  parsedUrl: any;
  overallAssessment: {
    threatScore: number; riskLevel: string; riskColor: string;
    indicators: string[]; recommendations: string[]; verdict: string;
  };
}

interface HashResult {
  input: { hash: string; hashType: string };
  found: boolean;
  aggregateResults: {
    detectionRate: number; classification: string;
    threatLevel: string; color: string;
  };
  engineResults: any[];
  details?: any;
}

interface ThreatData {
  iocs: any[];
  activeThreats: any[];
  campaigns: any[];
  aptGroups: any[];
  globalThreatLevel: any;
  statistics: any;
}

interface AIAnalysis {
  summary: string;
  keyFindings: string[];
  recommendations: string[];
  confidence: number;
}

// ============= MAIN COMPONENT =============
export default function NexusIntelDashboard() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  
  // States for each module
  const [ipInput, setIpInput] = useState('');
  const [ipResult, setIpResult] = useState<IPResult | null>(null);
  const [domainInput, setDomainInput] = useState('');
  const [domainResult, setDomainResult] = useState<DomainResult | null>(null);
  const [cveInput, setCveInput] = useState('');
  const [cveResults, setCveResults] = useState<CVEResult[]>([]);
  const [urlInput, setUrlInput] = useState('');
  const [urlResult, setUrlResult] = useState<URLResult | null>(null);
  const [hashInput, setHashInput] = useState('');
  const [hashResult, setHashResult] = useState<HashResult | null>(null);
  const [threatData, setThreatData] = useState<ThreatData | null>(null);
  const [reportData, setReportData] = useState<any>(null);
  
  // AI Analysis state
  const [aiQuery, setAiQuery] = useState('');
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null);
  const [isAILoading, setIsAILoading] = useState(false);

  // ============= API FUNCTIONS (ALL WORKING) =============
  
  const fetchThreatIntelligence = useCallback(async () => {
    try {
      setError(null);
      const res = await fetch('/api/osint/threats');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data.success) {
        setThreatData(data.data);
        console.log('[NEXUS] Threat intelligence loaded:', data.data.activeThreats?.length || 0, 'threats');
      } else throw new Error(data.error || 'Error fetching threats');
    } catch (err: any) {
      console.error('[NEXUS] Threat intel error:', err);
      setError(`Error de inteligencia: ${err.message}`);
    }
  }, []);

  useEffect(() => {
    fetchThreatIntelligence();
  }, [fetchThreatIntelligence]);

  // IP Analysis - REAL API (ip-api.com)
  const analyzeIP = async () => {
    if (!ipInput.trim()) return;
    setIsLoading(true); setError(null); setSuccess(null);
    
    try {
      console.log('[NEXUS] Analyzing IP:', ipInput.trim());
      const res = await fetch('/api/osint/ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ipInput.trim() })
      });
      
      const data = await res.json();
      console.log('[NEXUS] IP Response:', data);
      
      if (!res.ok) throw new Error(data.error || `Error HTTP ${res.status}`);
      if (data.success) {
        setIpResult(data.data);
        setSuccess(`IP ${data.data.query} analizada correctamente - Riesgo: ${data.data.threat.level}`);
      } else throw new Error(data.error || 'Error desconocido');
    } catch (err: any) {
      console.error('[NEXUS] IP Error:', err);
      setError(err.message || 'Error al analizar IP');
      setIpResult(null);
    }
    setIsLoading(false);
  };

  // Domain Analysis - REAL API (Google DNS + WHOIS)
  const analyzeDomain = async () => {
    if (!domainInput.trim()) return;
    setIsLoading(true); setError(null); setSuccess(null);
    
    try {
      console.log('[NEXUS] Analyzing domain:', domainInput.trim());
      const res = await fetch('/api/osint/domain', {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domainInput.trim() })
      });
      
      const data = await res.json();
      console.log('[NEXUS] Domain Response:', data);
      
      if (!res.ok) throw new Error(data.error || `Error HTTP ${res.status}`);
      if (data.success) {
        setDomainResult(data.data);
        setSuccess(`Dominio ${data.data.domain} analizado - Reputación: ${data.data.reputation.level}`);
      } else throw new Error(data.error || 'Error desconocido');
    } catch (err: any) {
      console.error('[NEXUS] Domain Error:', err);
      setError(err.message || 'Error al analizar dominio');
      setDomainResult(null);
    }
    setIsLoading(false);
  };

  // CVE Search - REAL API (NIST NVD v2.0)
  const searchCVE = async () => {
    if (!cveInput.trim()) return;
    setIsLoading(true); setError(null); setSuccess(null);
    
    try {
      console.log('[NEXUS] Searching CVE:', cveInput.trim());
      const isCVEId = cveInput.toUpperCase().startsWith('CVE-');
      const res = await fetch('/api/osint/cve', {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(isCVEId ? { cveId: cveInput.trim() } : { keyword: cveInput.trim() })
      });
      
      const data = await res.json();
      console.log('[NEXUS] CVE Response:', data);
      
      if (!res.ok) throw new Error(data.error || `Error HTTP ${res.status}`);
      if (data.success) {
        const results = data.data.results || [data.data];
        setCveResults(results);
        setSuccess(`${results.length} vulnerabilidad(es) encontrada(s)`);
      } else throw new Error(data.error || 'Error desconocido');
    } catch (err: any) {
      console.error('[NEXUS] CVE Error:', err);
      setError(err.message || 'Error al buscar CVEs');
      setCveResults([]);
    }
    setIsLoading(false);
  };

  // URL Analysis - Heuristic Analysis
  const analyzeURL = async () => {
    if (!urlInput.trim()) return;
    setIsLoading(true); setError(null); setSuccess(null);
    
    try {
      console.log('[NEXUS] Analyzing URL:', urlInput.trim());
      const res = await fetch('/api/osint/url', {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput.trim() })
      });
      
      const data = await res.json();
      console.log('[NEXUS] URL Response:', data);
      
      if (!res.ok) throw new Error(data.error || `Error HTTP ${res.status}`);
      if (data.success) {
        setUrlResult(data.data);
        setSuccess(`URL analizada - Riesgo: ${data.data.overallAssessment.riskLevel}`);
      } else throw new Error(data.error || 'Error desconocido');
    } catch (err: any) {
      console.error('[NEXUS] URL Error:', err);
      setError(err.message || 'Error al analizar URL');
      setUrlResult(null);
    }
    setIsLoading(false);
  };

  // Hash Lookup - Known hashes + MalwareBazaar
  const analyzeHash = async () => {
    if (!hashInput.trim()) return;
    setIsLoading(true); setError(null); setSuccess(null);
    
    try {
      console.log('[NEXUS] Looking up hash:', hashInput.trim());
      const res = await fetch('/api/osint/hash', {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: hashInput.trim() })
      });
      
      const data = await res.json();
      console.log('[NEXUS] Hash Response:', data);
      
      if (!res.ok) throw new Error(data.error || `Error HTTP ${res.status}`);
      if (data.success) {
        setHashResult(data.data);
        const status = data.data.found ? 'ENCONTRADO' : 'No encontrado';
        setSuccess(`Hash ${status} - Clasificación: ${data.data.aggregateResults.classification}`);
      } else throw new Error(data.error || 'Error desconocido');
    } catch (err: any) {
      console.error('[NEXUS] Hash Error:', err);
      setError(err.message || 'Error al buscar hash');
      setHashResult(null);
    }
    setIsLoading(false);
  };

  // AI-Powered Analysis using z-ai-web-dev-sdk
  const runAIAnalysis = async () => {
    if (!aiQuery.trim()) return;
    setIsAILoading(true); setError(null);
    
    try {
      console.log('[NEXUS] Running AI analysis for:', aiQuery.substring(0, 50));
      const res = await fetch('/api/osint/ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: aiQuery.trim(), context: threatData })
      });
      
      const data = await res.json();
      console.log('[NEXUS] AI Response:', data);
      
      if (data.success) {
        setAiAnalysis(data.data);
        setSuccess('Análisis IA completado');
      } else throw new Error(data.error || 'Error en análisis IA');
    } catch (err: any) {
      console.error('[NEXUS] AI Error:', err);
      setError(err.message || 'Error en análisis de IA');
    }
    setIsAILoading(false);
  };

  // Generate Executive Report
  const generateReport = async (type: string) => {
    setIsLoading(true); setError(null);
    
    try {
      console.log('[NEXUS] Generating report type:', type);
      const res = await fetch('/api/osint/reports', {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          reportType: type, 
          data: { 
            ipResult, 
            domainResult, 
            cveResults, 
            urlResult, 
            hashResult, 
            threatData 
          },
          options: { classification: 'CONFIDENTIAL' }
        })
      });
      
      const data = await res.json();
      console.log('[NEXUS] Report Response:', data);
      
      if (data.success) {
        setReportData(data.data.report);
        setSuccess('Informe ejecutivo generado correctamente');
      } else throw new Error(data.error || 'Error generando informe');
    } catch (err: any) {
      console.error('[NEXUS] Report Error:', err);
      setError(err.message || 'Error al generar informe');
    }
    setIsLoading(false);
  };

  // ============= UI HELPERS =============
  
  const getSeverityStyle = (level: string) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL':
      case 'CRÍTICO':
      case 'PELIGROSO':
      case 'MALICIOUS':
        return 'bg-red-500/10 text-red-600 border-red-500/20 font-medium';
      case 'HIGH':
      case 'ALTO':
      case 'ALTO RIESGO':
      case 'SUSPICIOUS':
        return 'bg-orange-500/10 text-orange-600 border-orange-500/20 font-medium';
      case 'MEDIUM':
      case 'MEDIO':
      case 'SOSPECHOSO':
      case 'CAUTELA':
        return 'bg-yellow-500/10 text-yellow-700 border-yellow-500/20 font-medium';
      default:
        return 'bg-emerald-500/10 text-emerald-600 border-emerald-500/20 font-medium';
    }
  };

  const getThreatGaugeColor = (score: number) => {
    if (score >= 70) return '#dc2626';
    if (score >= 50) return '#f97316';
    if (score >= 30) return '#eab308';
    return '#22c55e';
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSuccess('Copiado al portapapeles');
    setTimeout(() => setSuccess(null), 2000);
  };

  // ============= PROFESSIONAL DARK THEME UI =============
  return (
    <div className="min-h-screen bg-[#0a0e17] text-gray-100">
      {/* Professional Header - Bloomberg Terminal Style */}
      <header className="bg-[#111827] border-b border-gray-800 sticky top-0 z-50 backdrop-blur-sm bg-opacity-95">
        <div className="max-w-[1800px] mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-14">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-cyan-400 rounded-lg flex items-center justify-center shadow-lg shadow-blue-500/25">
                <Shield className="h-4 w-4 text-white" />
              </div>
              <div>
                <h1 className="text-sm font-bold tracking-wider text-white">NEXUS INTEL</h1>
                <p className="text-[10px] text-gray-500 font-mono tracking-widest">OSINT THREAT PLATFORM v3.0</p>
              </div>
            </div>
            
            <div className="flex items-center gap-3">
              {threatData?.globalThreatLevel && (
                <div className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-mono border ${getSeverityStyle(threatData.globalThreatLevel.level)}`}>
                  <Activity className="h-3 w-3 animate-pulse" />
                  <span>THREAT: {threatData.globalThreatLevel.level}</span>
                  <span className="font-bold">{threatData.globalThreatLevel.score}/100</span>
                </div>
              )}
              <Button variant="ghost" size="sm" onClick={fetchThreatIntelligence} disabled={isLoading} className="text-gray-400 hover:text-white hover:bg-gray-800">
                <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-[1800px] mx-auto px-4 sm:px-6 py-4">
        {/* Status Messages */}
        {error && (
          <div className="mb-4 p-3 bg-red-950/50 border border-red-800/50 rounded-lg flex items-start gap-2 animate-in fade-in slide-in-from-top-2">
            <ShieldAlert className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
            <p className="text-sm text-red-400 flex-1">{error}</p>
            <Button variant="ghost" size="sm" onClick={() => setError(null)} className="text-red-500 hover:text-red-400 h-auto p-1">
              <XCircle className="h-4 w-4" />
            </Button>
          </div>
        )}

        {success && (
          <div className="mb-4 p-3 bg-emerald-950/50 border border-emerald-800/50 rounded-lg flex items-center gap-2 animate-in fade-in slide-in-from-top-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-500 shrink-0" />
            <p className="text-sm text-emerald-400 flex-1">{success}</p>
          </div>
        )}

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          {/* Professional Tab Bar */}
          <TabsList className="bg-[#111827] border border-gray-800 p-1 h-auto grid grid-cols-5 lg:grid-cols-10 gap-1">
            {[
              { value: 'dashboard', label: 'Dashboard', icon: Activity },
              { value: 'ip', label: 'IP Intel', icon: Globe2 },
              { value: 'domain', label: 'Domain', icon: Globe },
              { value: 'cve', label: 'CVE', icon: Bug },
              { value: 'url', label: 'URL', icon: Link },
              { value: 'hash', label: 'Hash', icon: Fingerprint },
              { value: 'ai', label: 'AI Engine', icon: Brain },
              { value: 'threats', label: 'Threats', icon: Target },
              { value: 'reports', label: 'Reports', icon: FileText },
              { value: 'monitoring', label: 'Live Feed', icon: Radio }
            ].map(tab => (
              <TabsTrigger 
                key={tab.value} 
                value={tab.value} 
                className="text-xs py-2 data-[state=active]:bg-blue-600 data-[state=active]:text-white text-gray-400 hover:text-gray-200 hover:bg-gray-800 transition-all"
              >
                <tab.icon className="h-3 w-3 mr-1 hidden sm:inline" />
                {tab.label}
              </TabsTrigger>
            ))}
          </TabsList>

          {/* ==================== DASHBOARD ==================== */}
          <TabsContent value="dashboard" className="space-y-4 animate-in fade-in slide-in-from-left-2">
            {/* KPI Cards - Professional Grid */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <Card className="bg-[#111827] border-gray-800 hover:border-blue-500/30 transition-colors">
                <CardHeader className="pb-2 pt-4 px-4">
                  <p className="text-[10px] font-medium text-gray-500 uppercase tracking-wider">Global Threat Level</p>
                </CardHeader>
                <CardContent className="px-4 pb-4">
                  {threatData?.globalThreatLevel ? (
                    <div className="flex items-baseline gap-2">
                      <span className="text-2xl font-bold text-white font-mono">{threatData.globalThreatLevel.score}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${getSeverityStyle(threatData.globalThreatLevel.level)}`}>
                        {threatData.globalThreatLevel.level}
                      </span>
                    </div>
                  ) : (
                    <div className="animate-pulse h-8 bg-gray-800 rounded w-20"></div>
                  )}
                  <p className="text-[10px] text-gray-500 mt-1 font-mono">out of 100</p>
                </CardContent>
              </Card>

              <Card className="bg-[#111827] border-gray-800 hover:border-cyan-500/30 transition-colors">
                <CardHeader className="pb-2 pt-4 px-4">
                  <p className="text-[10px] font-medium text-gray-500 uppercase tracking-wider">Active IOCs</p>
                </CardHeader>
                <CardContent className="px-4 pb-4">
                  <span className="text-2xl font-bold text-white font-mono">{threatData?.iocs?.length || 0}</span>
                  <p className="text-[10px] text-gray-500 mt-1">indicators monitored</p>
                </CardContent>
              </Card>

              <Card className="bg-[#111827] border-gray-800 hover:border-orange-500/30 transition-colors">
                <CardHeader className="pb-2 pt-4 px-4">
                  <p className="text-[10px] font-medium text-gray-500 uppercase tracking-wider">Recent CVEs</p>
                </CardHeader>
                <CardContent className="px-4 pb-4">
                  <span className="text-2xl font-bold text-white font-mono">{threatData?.activeThreats?.length || 0}</span>
                  <p className="text-[10px] text-gray-500 mt-1">from NIST NVD</p>
                </CardContent>
              </Card>

              <Card className="bg-[#111827] border-gray-800 hover:border-red-500/30 transition-colors">
                <CardHeader className="pb-2 pt-4 px-4">
                  <p className="text-[10px] font-medium text-gray-500 uppercase tracking-wider">Active Campaigns</p>
                </CardHeader>
                <CardContent className="px-4 pb-4">
                  <span className="text-2xl font-bold text-red-400 font-mono">
                    {threatData?.campaigns?.filter((c: any) => c.status === 'ACTIVE').length || 0}
                  </span>
                  <p className="text-[10px] text-gray-500 mt-1">require attention</p>
                </CardContent>
              </Card>
            </div>

            {/* Quick Analysis Panel */}
            <Card className="bg-[#111827] border-gray-800">
              <CardHeader className="pb-3 pt-4 px-4">
                <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
                  <Zap className="h-4 w-4 text-yellow-500" />
                  Quick Intelligence Analysis
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-4 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-medium text-gray-500 uppercase tracking-wider">IP Address</label>
                    <div className="flex gap-2">
                      <Input placeholder="8.8.8.8" value={ipInput} onChange={(e) => setIpInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && analyzeIP()} 
                        className="bg-[#0a0e17] border-gray-700 text-xs font-mono focus:border-blue-500 h-9" />
                      <Button size="sm" onClick={analyzeIP} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700 h-9 px-3">
                        {isLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Search className="h-3 w-3" />}
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[10px] font-medium text-gray-500 uppercase tracking-wider">Domain</label>
                    <div className="flex gap-2">
                      <Input placeholder="example.com" value={domainInput} onChange={(e) => setDomainInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && analyzeDomain()} 
                        className="bg-[#0a0e17] border-gray-700 text-xs font-mono focus:border-blue-500 h-9" />
                      <Button size="sm" onClick={analyzeDomain} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700 h-9 px-3">
                        {isLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Search className="h-3 w-3" />}
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[10px] font-medium text-gray-500 uppercase tracking-wider">CVE / Keyword</label>
                    <div className="flex gap-2">
                      <Input placeholder="CVE-2024-..." value={cveInput} onChange={(e) => setCveInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && searchCVE()} 
                        className="bg-[#0a0e17] border-gray-700 text-xs font-mono focus:border-blue-500 h-9" />
                      <Button size="sm" onClick={searchCVE} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700 h-9 px-3">
                        {isLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Search className="h-3 w-3" />}
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[10px] font-medium text-gray-500 uppercase tracking-wider">URL</label>
                    <div className="flex gap-2">
                      <Input placeholder="https://..." value={urlInput} onChange={(e) => setUrlInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && analyzeURL()} 
                        className="bg-[#0a0e17] border-gray-700 text-xs font-mono focus:border-blue-500 h-9" />
                      <Button size="sm" onClick={analyzeURL} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700 h-9 px-3">
                        {isLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Search className="h-3 w-3" />}
                      </Button>
                    </div>
                  </div>
                </div>

                {/* Latest Results Display */}
                {(ipResult || domainResult || urlResult || hashResult) && (
                  <div className="mt-4 p-3 bg-[#0a0e17] rounded-lg border border-gray-800">
                    <h4 className="text-[10px] font-medium text-gray-500 uppercase tracking-wider mb-3">Latest Analysis Result</h4>
                    
                    {ipResult && (
                      <div className="space-y-2 pb-3 border-b border-gray-800">
                        <div className="flex items-center justify-between flex-wrap gap-2">
                          <div className="flex items-center gap-2">
                            <Globe2 className="h-3 w-3 text-blue-400" />
                            <code className="text-xs bg-gray-800 px-2 py-0.5 rounded font-mono text-blue-400">{ipResult.query}</code>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${getSeverityStyle(ipResult.threat.level)}`}>
                              {ipResult.threat.icon} {ipResult.threat.level}: {ipResult.threat.score}/100
                            </span>
                          </div>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[10px] text-gray-400 font-mono">
                          <div><span className="text-gray-600">LOC:</span> {ipResult.geolocation.city}, {ipResult.geolocation.country}</div>
                          <div><span className="text-gray-600">ISP:</span> {ipResult.network.isp}</div>
                          <div><span className="text-gray-600">ASN:</span> {ipResult.network.asn}</div>
                          <div><span className="text-gray-600">PROXY:</span> {ipResult.network.isProxy ? 'YES' : 'NO'}</div>
                        </div>
                      </div>
                    )}

                    {domainResult && (
                      <div className="space-y-2 py-3 border-b border-gray-800">
                        <div className="flex items-center justify-between flex-wrap gap-2">
                          <div className="flex items-center gap-2">
                            <Globe className="h-3 w-3 text-cyan-400" />
                            <code className="text-xs bg-gray-800 px-2 py-0.5 rounded font-mono text-cyan-400">{domainResult.domain}</code>
                          </div>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${getSeverityStyle(domainResult.reputation.level)}`}>
                            {domainResult.reputation.level}: {domainResult.reputation.score}/100
                          </span>
                        </div>
                        <div className="text-[10px] text-gray-400 font-mono">
                          <span className="text-gray-600">REGISTRAR:</span> {domainResult.whois?.registrar || 'N/A'} | 
                          <span className="text-gray-600 ml-2">AGE:</span> {domainResult.whois?.ageDays || 'N/A'} days
                        </div>
                      </div>
                    )}

                    {urlResult && (
                      <div className="space-y-2 py-3 border-b border-gray-800">
                        <div className="flex items-center justify-between flex-wrap gap-2">
                          <div className="flex items-center gap-2">
                            <Link className="h-3 w-3 text-purple-400" />
                            <code className="text-xs bg-gray-800 px-2 py-0.5 rounded font-mono text-purple-400 max-w-xs truncate">{urlResult.url}</code>
                          </div>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${getSeverityStyle(urlResult.overallAssessment.riskLevel)}`}>
                            {urlResult.overallAssessment.riskLevel}
                          </span>
                        </div>
                        <p className="text-[10px] text-gray-400 font-mono">{urlResult.overallAssessment.verdict}</p>
                      </div>
                    )}

                    {hashResult && (
                      <div className="space-y-2 pt-3">
                        <div className="flex items-center justify-between flex-wrap gap-2">
                          <div className="flex items-center gap-2">
                            <Fingerprint className="h-3 w-3 text-orange-400" />
                            <code className="text-xs bg-gray-800 px-2 py-0.5 rounded font-mono text-orange-400">{hashResult.input.hash.substring(0, 16)}...</code>
                          </div>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${getSeverityStyle(hashResult.aggregateResults.threatLevel)}`}>
                            {hashResult.aggregateResults.classification}
                          </span>
                        </div>
                        <p className="text-[10px] text-gray-400 font-mono">
                          Detection: {hashResult.aggregateResults.detectionRate}% | Status: {hashResult.found ? 'FOUND' : 'NOT FOUND'}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Recent Threats Table - Real NVD Data */}
            {threatData?.activeThreats && threatData.activeThreats.length > 0 && (
              <Card className="bg-[#111827] border-gray-800">
                <CardHeader className="pb-3 pt-4 px-4 flex flex-row items-center justify-between">
                  <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-red-500" />
                    Recent Vulnerabilities (NIST NVD - Real Data)
                  </CardTitle>
                  <Button variant="ghost" size="sm" onClick={() => setActiveTab('cve')} className="text-gray-400 hover:text-white text-xs">
                    View all <ChevronRight className="h-3 w-3 ml-1" />
                  </Button>
                </CardHeader>
                <CardContent className="px-4 pb-4">
                  <ScrollArea className="h-[300px]">
                    <table className="w-full text-xs">
                      <thead className="sticky top-0 bg-[#111827]">
                        <tr className="border-b border-gray-800">
                          <th className="text-left py-2 px-2 font-medium text-gray-500 uppercase tracking-wider">CVE ID</th>
                          <th className="text-left py-2 px-2 font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                          <th className="text-left py-2 px-2 font-medium text-gray-500 uppercase tracking-wider">CVSS</th>
                          <th className="text-left py-2 px-2 font-medium text-gray-500 uppercase tracking-wider">Published</th>
                          <th className="text-right py-2 px-2 font-medium text-gray-500 uppercase tracking-wider">Action</th>
                        </tr>
                      </thead>
                      <tbody className="font-mono">
                        {threatData.activeThreats.slice(0, 10).map((t: any, i: number) => (
                          <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                            <td className="py-2 px-2 text-blue-400 font-semibold">{t.id}</td>
                            <td className="py-2 px-2">
                              <span className={`px-1.5 py-0.5 rounded text-[10px] ${getSeverityStyle(t.severity)}`}>{t.severity}</span>
                            </td>
                            <td className="py-2 px-2 text-gray-300">{t.cvssScore || '-'}</td>
                            <td className="py-2 px-2 text-gray-500">{new Date(t.published).toLocaleDateString()}</td>
                            <td className="py-2 px-2 text-right">
                              <Button variant="ghost" size="sm" className="h-6 w-6 p-0 text-gray-400 hover:text-blue-400"
                                onClick={() => { setCveInput(t.id); setActiveTab('cve'); }}>
                                <ArrowRight className="h-3 w-3" />
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </ScrollArea>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* ==================== IP INTEL ==================== */}
          <TabsContent value="ip" className="space-y-4 animate-in fade-in slide-in-from-left-2">
            <Card className="bg-[#111827] border-gray-800">
              <CardHeader className="pb-3 pt-4 px-4">
                <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
                  <Globe2 className="h-4 w-4 text-blue-400" />
                  IP Geolocation & Threat Intelligence
                  <Badge variant="outline" className="text-[10px] border-blue-500/30 text-blue-400">REAL-TIME</Badge>
                </CardTitle>
                <p className="text-xs text-gray-500 mt-1">Powered by ip-api.com • Real geolocation and threat assessment</p>
              </CardHeader>
              <CardContent className="px-4 pb-4 space-y-4">
                <div className="flex gap-3 max-w-2xl">
                  <Input placeholder="Enter IPv4 address (e.g., 8.8.8.8, 1.1.1.1)" 
                    value={ipInput} onChange={(e) => setIpInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeIP()} 
                    className="flex-1 bg-[#0a0e17] border-gray-700 font-mono text-sm focus:border-blue-500" />
                  <Button onClick={analyzeIP} disabled={isLoading || !ipInput} className="bg-blue-600 hover:bg-blue-700">
                    {isLoading ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />Analyzing...</> : <><Search className="h-4 w-4 mr-2" />Analyze IP</>}
                  </Button>
                </div>

                {ipResult && (
                  <div className="mt-6 space-y-4 animate-in fade-in slide-in-from-bottom-2">
                    {/* Threat Score Banner */}
                    <div className={`p-4 rounded-lg border-l-4 ${
                      ipResult.threat.score >= 60 ? 'bg-red-950/30 border-red-500' :
                      ipResult.threat.score >= 40 ? 'bg-orange-950/30 border-orange-500' :
                      ipResult.threat.score >= 20 ? 'bg-yellow-950/30 border-yellow-500' :
                      'bg-emerald-950/30 border-emerald-500'
                    }`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-lg font-bold font-mono">{ipResult.threat.icon} THREAT LEVEL: {ipResult.threat.level}</span>
                        <span className="text-3xl font-black font-mono" style={{color: ipResult.threat.color}}>{ipResult.threat.score}/100</span>
                      </div>
                      
                      {/* Visual Threat Gauge */}
                      <div className="w-full h-2 bg-gray-800 rounded-full overflow-hidden mt-2">
                        <div 
                          className="h-full transition-all duration-1000 ease-out"
                          style={{ width: `${ipResult.threat.score}%`, backgroundColor: ipResult.threat.color }}
                        ></div>
                      </div>
                    </div>

                    {/* Details Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {/* Geolocation */}
                      <Card className="bg-[#0a0e17] border-gray-800">
                        <CardHeader className="pb-2 pt-3 px-3">
                          <CardTitle className="text-xs font-medium text-gray-400 flex items-center gap-2">
                            <MapPin className="h-3 w-3" /> GEOLOCATION
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="px-3 pb-3 space-y-1.5 text-xs font-mono">
                          <div className="flex justify-between"><span className="text-gray-500">Country:</span><span>{ipResult.geolocation.country}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Region:</span><span>{ipResult.geolocation.region}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">City:</span><span>{ipResult.geolocation.city}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Coords:</span><span>{ipResult.geolocation.latitude}, {ipResult.geolocation.longitude}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Timezone:</span><span>{ipResult.geolocation.timezone}</span></div>
                        </CardContent>
                      </Card>

                      {/* Network Info */}
                      <Card className="bg-[#0a0e17] border-gray-800">
                        <CardHeader className="pb-2 pt-3 px-3">
                          <CardTitle className="text-xs font-medium text-gray-400 flex items-center gap-2">
                            <Server className="h-3 w-3" /> NETWORK
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="px-3 pb-3 space-y-1.5 text-xs font-mono">
                          <div className="flex justify-between"><span className="text-gray-500">ISP:</span><span>{ipResult.network.isp}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Org:</span><span>{ipResult.network.org}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">ASN:</span><span>{ipResult.network.asn}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Mobile:</span><span className={ipResult.network.isMobile ? 'text-orange-400' : 'text-gray-400'}>{ipResult.network.isMobile ? 'YES' : 'NO'}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Proxy:</span><span className={ipResult.network.isProxy ? 'text-red-400' : 'text-gray-400'}>{ipResult.network.isProxy ? 'YES ⚠️' : 'NO'}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Hosting:</span><span className={ipResult.network.isHosting ? 'text-yellow-400' : 'text-gray-400'}>{ipResult.network.isHosting ? 'YES' : 'NO'}</span></div>
                        </CardContent>
                      </Card>

                      {/* Indicators */}
                      <Card className="bg-[#0a0e17] border-gray-800">
                        <CardHeader className="pb-2 pt-3 px-3">
                          <CardTitle className="text-xs font-medium text-gray-400 flex items-center gap-2">
                            <ShieldAlert className="h-3 w-3" /> INDICATORS
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="px-3 pb-3 space-y-1.5">
                          {ipResult.threat.indicators.map((ind, i) => (
                            <div key={i} className="text-xs text-gray-300 flex items-start gap-2">
                              <span className="text-green-400 mt-0.5">▸</span>
                              <span>{ind}</span>
                            </div>
                          ))}
                        </CardContent>
                      </Card>
                    </div>

                    {/* Recommendations */}
                    <Card className="bg-[#0a0e17] border-gray-800">
                      <CardHeader className="pb-2 pt-3 px-3">
                        <CardTitle className="text-xs font-medium text-gray-400 flex items-center gap-2">
                          <Info className="h-3 w-3" /> RECOMMENDATIONS
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="px-3 pb-3">
                        <ul className="space-y-1">
                          {ipResult.threat.recommendations.map((rec, i) => (
                            <li key={i} className="text-xs text-gray-300 flex items-start gap-2">
                              <CheckCircle2 className="h-3 w-3 text-blue-400 mt-0.5 shrink-0" />
                              <span>{rec}</span>
                            </li>
                          ))}
                        </ul>
                      </CardContent>
                    </Card>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== DOMAIN ==================== */}
          <TabsContent value="domain" className="space-y-4 animate-in fade-in slide-in-from-left-2">
            <Card className="bg-[#111827] border-gray-800">
              <CardHeader className="pb-3 pt-4 px-4">
                <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
                  <Globe className="h-4 w-4 text-cyan-400" />
                  Domain Intelligence & DNS Analysis
                  <Badge variant="outline" className="text-[10px] border-cyan-500/30 text-cyan-400">DNS + WHOIS</Badge>
                </CardTitle>
                <p className="text-xs text-gray-500 mt-1">Google DoH DNS resolution • WHOIS lookup • Security analysis</p>
              </CardHeader>
              <CardContent className="px-4 pb-4 space-y-4">
                <div className="flex gap-3 max-w-2xl">
                  <Input placeholder="Enter domain (e.g., google.com)" 
                    value={domainInput} onChange={(e) => setDomainInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeDomain()} 
                    className="flex-1 bg-[#0a0e17] border-gray-700 font-mono text-sm focus:border-cyan-500" />
                  <Button onClick={analyzeDomain} disabled={isLoading || !domainInput} className="bg-cyan-600 hover:bg-cyan-700">
                    {isLoading ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />Analyzing...</> : <><Search className="h-4 w-4 mr-2" />Analyze</>}
                  </Button>
                </div>

                {domainResult && (
                  <div className="mt-6 space-y-4 animate-in fade-in slide-in-from-bottom-2">
                    {/* Reputation Score */}
                    <div className="p-4 rounded-lg bg-[#0a0e17] border border-gray-800">
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <h3 className="text-lg font-bold font-mono">{domainResult.domain}</h3>
                          <p className="text-xs text-gray-500">Reputation Assessment</p>
                        </div>
                        <div className="text-right">
                          <div className="text-3xl font-black font-mono" style={{color: domainResult.reputation.color}}>{domainResult.reputation.score}/100</div>
                          <span className={`px-2 py-0.5 rounded text-xs font-mono ${getSeverityStyle(domainResult.reputation.level)}`}>
                            {domainResult.reputation.level}
                          </span>
                        </div>
                      </div>
                      <div className="w-full h-2 bg-gray-800 rounded-full overflow-hidden">
                        <div 
                          className="h-full transition-all duration-1000"
                          style={{ width: `${domainResult.reputation.score}%`, backgroundColor: domainResult.reputation.color }}
                        ></div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      {/* WHOIS Data */}
                      <Card className="bg-[#0a0e17] border-gray-800">
                        <CardHeader className="pb-2 pt-3 px-3">
                          <CardTitle className="text-xs font-medium text-gray-400">WHOIS DATA</CardTitle>
                        </CardHeader>
                        <CardContent className="px-3 pb-3 space-y-1.5 text-xs font-mono">
                          <div className="flex justify-between"><span className="text-gray-500">Registrar:</span><span>{domainResult.whois?.registrar || 'N/A'}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Created:</span><span>{domainResult.whois?.creationDate || 'N/A'}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Expires:</span><span>{domainResult.whois?.expiryDate || 'N/A'}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Country:</span><span>{domainResult.whois?.registrantCountry || 'N/A'}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Age:</span><span>{domainResult.whois?.ageDays ? `${domainResult.whois.ageDays} days` : 'N/A'}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Privacy:</span><span className={domainResult.whois?.privacyEnabled ? 'text-yellow-400' : ''}>{domainResult.whois?.privacyEnabled ? 'ENABLED' : 'DISABLED'}</span></div>
                        </CardContent>
                      </Card>

                      {/* DNS Records */}
                      <Card className="bg-[#0a0e17] border-gray-800">
                        <CardHeader className="pb-2 pt-3 px-3">
                          <CardTitle className="text-xs font-medium text-gray-400">DNS RECORDS</CardTitle>
                        </CardHeader>
                        <CardContent className="px-3 pb-3 space-y-2 text-xs font-mono">
                          {domainResult.dns?.aRecords?.length > 0 && (
                            <div>
                              <span className="text-gray-500 block mb-1">A Records:</span>
                              {domainResult.dns.aRecords.map((r: string, i: number) => (
                                <div key={i} className="text-blue-400 pl-2">{r}</div>
                              ))}
                            </div>
                          )}
                          {domainResult.dns?.nsRecords?.length > 0 && (
                            <div>
                              <span className="text-gray-500 block mb-1">Name Servers:</span>
                              {domainResult.dns.nsRecords.map((r: string, i: number) => (
                                <div key={i} className="text-cyan-400 pl-2">{r}</div>
                              ))}
                            </div>
                          )}
                          <div className="flex gap-4 pt-2">
                            <span className={domainResult.dns?.hasSPF ? 'text-green-400' : 'text-red-400'}>
                              SPF: {domainResult.dns?.hasSPF ? '✓' : '✗'}
                            </span>
                            <span className={domainResult.dns?.hasDMARC ? 'text-green-400' : 'text-red-400'}>
                              DMARC: {domainResult.dns?.hasDMARC ? '✓' : '✗'}
                            </span>
                          </div>
                        </CardContent>
                      </Card>
                    </div>

                    {/* Security Indicators */}
                    <Card className="bg-[#0a0e17] border-gray-800">
                      <CardHeader className="pb-2 pt-3 px-3">
                        <CardTitle className="text-xs font-medium text-gray-400">SECURITY INDICATORS</CardTitle>
                      </CardHeader>
                      <CardContent className="px-3 pb-3">
                        <div className="space-y-1">
                          {domainResult.reputation.indicators.map((ind, i) => (
                            <div key={i} className="text-xs text-gray-300 flex items-center gap-2">
                              <ShieldAlert className="h-3 w-3 text-yellow-500" />
                              <span>{ind}</span>
                            </div>
                          ))}
                        </div>
                        <Separator className="my-3 bg-gray-800" />
                        <div className="space-y-1">
                          {domainResult.reputation.recommendations.map((rec, i) => (
                            <div key={i} className="text-xs text-gray-300 flex items-center gap-2">
                              <CheckCircle2 className="h-3 w-3 text-green-500" />
                              <span>{rec}</span>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== CVE SEARCH ==================== */}
          <TabsContent value="cve" className="space-y-4 animate-in fade-in slide-in-from-left-2">
            <Card className="bg-[#111827] border-gray-800">
              <CardHeader className="pb-3 pt-4 px-4">
                <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
                  <Bug className="h-4 w-4 text-orange-400" />
                  CVE Vulnerability Database
                  <Badge variant="outline" className="text-[10px] border-orange-500/30 text-orange-400">NIST NVD v2.0</Badge>
                </CardTitle>
                <p className="text-xs text-gray-500 mt-1">Real-time vulnerability data from National Vulnerability Database</p>
              </CardHeader>
              <CardContent className="px-4 pb-4 space-y-4">
                <div className="flex gap-3 max-w-2xl">
                  <Input placeholder="CVE-ID (e.g., CVE-2024-1234) or keyword (e.g., sql injection)" 
                    value={cveInput} onChange={(e) => setCveInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && searchCVE()} 
                    className="flex-1 bg-[#0a0e17] border-gray-700 font-mono text-sm focus:border-orange-500" />
                  <Button onClick={searchCVE} disabled={isLoading || !cveInput} className="bg-orange-600 hover:bg-orange-700">
                    {isLoading ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />Searching...</> : <><Search className="h-4 w-4 mr-2" />Search</>}
                  </Button>
                </div>

                {cveResults.length > 0 && (
                  <div className="mt-6 space-y-3 animate-in fade-in slide-in-from-bottom-2">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-medium text-gray-300">{cveResults.length} Result(s) Found</h3>
                      <Badge variant="outline" className="text-xs border-gray-700 text-gray-400">Source: NIST NVD</Badge>
                    </div>
                    
                    {cveResults.map((cve, i) => (
                      <Card key={i} className="bg-[#0a0e17] border-gray-800 hover:border-gray-700 transition-colors">
                        <CardContent className="pt-4 pb-4 px-4">
                          <div className="flex items-start justify-between gap-4 mb-3">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                <code className="text-sm font-bold text-blue-400 font-mono">{cve.id}</code>
                                <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${getSeverityStyle(cve.cvss.severity)}`}>
                                  {cve.cvss.severity}
                                </span>
                                <Badge variant="outline" className="text-[10px] border-gray-700 text-gray-500">
                                  CVSS v{cve.cvss.version}: {cve.cvss.score || 'N/A'}
                                </Badge>
                              </div>
                              <p className="text-xs text-gray-400 line-clamp-2">{cve.descriptions}</p>
                            </div>
                            {cve.cvss.score && (
                              <div className="text-right shrink-0">
                                <div className="text-2xl font-black font-mono" style={{color: getThreatGaugeColor(cve.cvss.score)}}>{cve.cvss.score}</div>
                                <div className="w-12 h-1.5 bg-gray-800 rounded-full overflow-hidden mt-1">
                                  <div className="h-full" style={{width: `${Math.min(cve.cvss.score * 10, 100)}%`, backgroundColor: getThreatGaugeColor(cve.cvss.score)}}></div>
                                </div>
                              </div>
                            )}
                          </div>
                          
                          <Separator className="my-3 bg-gray-800" />
                          
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[10px] font-mono">
                            <div>
                              <span className="text-gray-500 block">CWE:</span>
                              <span className="text-gray-300">{cve.cwe.join(', ') || 'N/A'}</span>
                            </div>
                            <div>
                              <span className="text-gray-500 block">Published:</span>
                              <span className="text-gray-300">{new Date(cve.dates.published).toLocaleDateString()}</span>
                            </div>
                            <div>
                              <span className="text-gray-500 block">Status:</span>
                              <span className="text-gray-300">{cve.status}</span>
                            </div>
                            <div>
                              <span className="text-gray-500 block">References:</span>
                              <span className="text-gray-300">{cve.references?.length || 0}</span>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== URL ANALYSIS ==================== */}
          <TabsContent value="url" className="space-y-4 animate-in fade-in slide-in-from-left-2">
            <Card className="bg-[#111827] border-gray-800">
              <CardHeader className="pb-3 pt-4 px-4">
                <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
                  <Link className="h-4 w-4 text-purple-400" />
                  URL Security Analyzer
                  <Badge variant="outline" className="text-[10px] border-purple-500/30 text-purple-400">HEURISTIC</Badge>
                </CardTitle>
                <p className="text-xs text-gray-500 mt-1">Multi-layer URL analysis: pattern detection, reputation, content indicators</p>
              </CardHeader>
              <CardContent className="px-4 pb-4 space-y-4">
                <div className="flex gap-3 max-w-2xl">
                  <Input placeholder="https://example.com/path?param=value" 
                    value={urlInput} onChange={(e) => setUrlInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeURL()} 
                    className="flex-1 bg-[#0a0e17] border-gray-700 font-mono text-sm focus:border-purple-500" />
                  <Button onClick={analyzeURL} disabled={isLoading || !urlInput} className="bg-purple-600 hover:bg-purple-700">
                    {isLoading ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />Analyzing...</> : <><Search className="h-4 w-4 mr-2" />Analyze</>}
                  </Button>
                </div>

                {urlResult && (
                  <div className="mt-6 space-y-4 animate-in fade-in slide-in-from-bottom-2">
                    {/* Risk Score Banner */}
                    <div className={`p-4 rounded-lg border-l-4 ${
                      urlResult.overallAssessment.threatScore >= 70 ? 'bg-red-950/30 border-red-500' :
                      urlResult.overallAssessment.threatScore >= 50 ? 'bg-orange-950/30 border-orange-500' :
                      urlResult.overallAssessment.threatScore >= 30 ? 'bg-yellow-950/30 border-yellow-500' :
                      'bg-emerald-950/30 border-emerald-500'
                    }`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-lg font-bold font-mono">{urlResult.overallAssessment.riskIcon} {urlResult.overallAssessment.riskLevel}</span>
                        <span className="text-3xl font-black font-mono" style={{color: urlResult.overallAssessment.riskColor}}>{urlResult.overallAssessment.threatScore}/100</span>
                      </div>
                      <div className="w-full h-2 bg-gray-800 rounded-full overflow-hidden">
                        <div className="h-full transition-all duration-1000" style={{width: `${urlResult.overallAssessment.threatScore}%`, backgroundColor: urlResult.overallAssessment.riskColor}}></div>
                      </div>
                      <p className="text-sm text-gray-300 mt-3 font-medium">{urlResult.overallAssessment.verdict}</p>
                    </div>

                    {/* Parsed URL */}
                    <Card className="bg-[#0a0e17] border-gray-800">
                      <CardHeader className="pb-2 pt-3 px-3">
                        <CardTitle className="text-xs font-medium text-gray-400">PARSED URL COMPONENTS</CardTitle>
                      </CardHeader>
                      <CardContent className="px-3 pb-3">
                        <code className="text-xs text-purple-400 font-mono break-all">{urlResult.url}</code>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-3 text-[10px] font-mono">
                          <div><span className="text-gray-500">Protocol:</span> <span className="text-gray-300">{urlResult.parsedUrl.protocol}</span></div>
                          <div><span className="text-gray-500">Host:</span> <span className="text-gray-300">{urlResult.parsedUrl.hostname}</span></div>
                          <div><span className="text-gray-500">Port:</span> <span className="text-gray-300">{urlResult.parsedUrl.port}</span></div>
                          <div><span className="text-gray-500">Path:</span> <span className="text-gray-300 truncate">{urlResult.parsedUrl.path}</span></div>
                        </div>
                      </CardContent>
                    </Card>

                    {/* Indicators */}
                    <Card className="bg-[#0a0e17] border-gray-800">
                      <CardHeader className="pb-2 pt-3 px-3">
                        <CardTitle className="text-xs font-medium text-gray-400">DETECTED INDICATORS ({urlResult.overallAssessment.indicators.length})</CardTitle>
                      </CardHeader>
                      <CardContent className="px-3 pb-3">
                        <div className="space-y-1">
                          {urlResult.overallAssessment.indicators.map((ind, i) => (
                            <div key={i} className="text-xs text-gray-300 flex items-center gap-2">
                              <AlertTriangle className="h-3 w-3 text-yellow-500" />
                              <span>{ind}</span>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>

                    {/* Recommendations */}
                    <Card className="bg-[#0a0e17] border-gray-800">
                      <CardHeader className="pb-2 pt-3 px-3">
                        <CardTitle className="text-xs font-medium text-gray-400">RECOMMENDATIONS</CardTitle>
                      </CardHeader>
                      <CardContent className="px-3 pb-3">
                        <div className="space-y-1">
                          {urlResult.overallAssessment.recommendations.map((rec, i) => (
                            <div key={i} className="text-xs text-gray-300 flex items-center gap-2">
                              <CheckCircle2 className="h-3 w-3 text-green-500" />
                              <span>{rec}</span>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== HASH LOOKUP ==================== */}
          <TabsContent value="hash" className="space-y-4 animate-in fade-in slide-in-from-left-2">
            <Card className="bg-[#111827] border-gray-800">
              <CardHeader className="pb-3 pt-4 px-4">
                <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
                  <Fingerprint className="h-4 w-4 text-orange-400" />
                  Malware Hash Lookup
                  <Badge variant="outline" className="text-[10px] border-orange-500/30 text-orange-400">MULTI-ENGINE</Badge>
                </CardTitle>
                <p className="text-xs text-gray-500 mt-1">MD5, SHA1, SHA256, SHA512 • Known malware database + MalwareBazaar</p>
              </CardHeader>
              <CardContent className="px-4 pb-4 space-y-4">
                <div className="flex gap-3 max-w-2xl">
                  <Input placeholder="Enter hash (MD5/SHA1/SHA256/SHA512)" 
                    value={hashInput} onChange={(e) => setHashInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeHash()} 
                    className="flex-1 bg-[#0a0e17] border-gray-700 font-mono text-sm focus:border-orange-500" />
                  <Button onClick={analyzeHash} disabled={isLoading || !hashInput} className="bg-orange-600 hover:bg-orange-700">
                    {isLoading ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />Searching...</> : <><Search className="h-4 w-4 mr-2" />Lookup</>}
                  </Button>
                </div>

                {/* Test Hashes */}
                <div className="flex flex-wrap gap-2">
                  <span className="text-[10px] text-gray-500">Test with known hashes:</span>
                  {[
                    { hash: '44d88612fea8a8f36de82e1278abb02f', label: 'EICAR (Safe)' },
                    { hash: '275a021bbfb6489e54d471899f7db9d1663fc20ff8a3d4a9552b8f45d1fbc13b', label: 'Emotet' },
                    { hash: '3395856ce81f2b7386244a8c55b31c21', label: 'WannaCry' }
                  ].map(test => (
                    <button
                      key={test.hash}
                      onClick={() => setHashInput(test.hash)}
                      className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded text-[10px] font-mono text-gray-400 hover:text-white transition-colors"
                    >
                      {test.label}
                    </button>
                  ))}
                </div>

                {hashResult && (
                  <div className="mt-6 space-y-4 animate-in fade-in slide-in-from-bottom-2">
                    {/* Detection Summary */}
                    <div className={`p-4 rounded-lg border-l-4 ${
                      hashResult.found && hashResult.aggregateResults.detectionRate > 50 ? 'bg-red-950/30 border-red-500' :
                      hashResult.found ? 'bg-yellow-950/30 border-yellow-500' :
                      'bg-emerald-950/30 border-emerald-500'
                    }`}>
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="text-xs text-gray-500 font-mono">HASH TYPE: {hashResult.input.hashType.toUpperCase()}</div>
                          <div className="text-lg font-bold font-mono mt-1">{hashResult.aggregateResults.classification}</div>
                        </div>
                        <div className="text-right">
                          <div className="text-3xl font-black font-mono" style={{color: hashResult.aggregateResults.color}}>
                            {hashResult.aggregateResults.detectionRate}%
                          </div>
                          <div className="text-[10px] text-gray-500 font-mono">Detection Rate</div>
                        </div>
                      </div>
                      <div className="w-full h-2 bg-gray-800 rounded-full overflow-hidden mt-3">
                        <div className="h-full transition-all duration-1000" style={{
                          width: `${hashResult.aggregateResults.detectionRate}%`,
                          backgroundColor: hashResult.aggregateResults.color
                        }}></div>
                      </div>
                    </div>

                    {/* Engine Results */}
                    {hashResult.engineResults?.length > 0 && (
                      <Card className="bg-[#0a0e17] border-gray-800">
                        <CardHeader className="pb-2 pt-3 px-3">
                          <CardTitle className="text-xs font-medium text-gray-400">SCAN RESULTS ({hashResult.engineResults.length} engines)</CardTitle>
                        </CardHeader>
                        <CardContent className="px-3 pb-3">
                          <div className="max-h-[300px] overflow-y-auto space-y-1">
                            {hashResult.engineResults.map((engine, i) => (
                              <div key={i} className="flex items-center justify-between text-xs font-mono py-1 border-b border-gray-800/50">
                                <span className="text-gray-400">{engine.engine}</span>
                                <span className={engine.result !== 'Clean' ? 'text-red-400' : 'text-green-400'}>
                                  {engine.result}
                                </span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    )}

                    {/* Details */}
                    {hashResult.details && (
                      <Card className="bg-[#0a0e17] border-gray-800">
                        <CardHeader className="pb-2 pt-3 px-3">
                          <CardTitle className="text-xs font-medium text-gray-400">FILE DETAILS</CardTitle>
                        </CardHeader>
                        <CardContent className="px-3 pb-3 space-y-2 text-xs font-mono">
                          {hashResult.details.type && <div><span className="text-gray-500">Type:</span> <span className="text-gray-300">{hashResult.details.type}</span></div>}
                          {hashResult.details.family && <div><span className="text-gray-500">Family:</span> <span className="text-gray-300">{hashResult.details.family}</span></div>}
                          {hashResult.details.size && <div><span className="text-gray-500">Size:</span> <span className="text-gray-300">{hashResult.details.size}</span></div>}
                          {hashResult.details.description && (
                            <div className="pt-2 border-t border-gray-800">
                              <span className="text-gray-500 block mb-1">Description:</span>
                              <span className="text-gray-300 text-xs leading-relaxed">{hashResult.details.description}</span>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== AI ENGINE ==================== */}
          <TabsContent value="ai" className="space-y-4 animate-in fade-in slide-in-from-left-2">
            <Card className="bg-[#111827] border-gray-800">
              <CardHeader className="pb-3 pt-4 px-4">
                <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
                  <Brain className="h-4 w-4 text-pink-400" />
                  AI Intelligence Engine
                  <Badge variant="outline" className="text-[10px] border-pink-500/30 text-pink-400">POWERED BY AI</Badge>
                </CardTitle>
                <p className="text-xs text-gray-500 mt-1">Advanced threat analysis powered by artificial intelligence</p>
              </CardHeader>
              <CardContent className="px-4 pb-4 space-y-4">
                <div className="flex gap-3">
                  <textarea
                    placeholder="Ask about threats, vulnerabilities, or request analysis...&#10;&#10;Examples:&#10;- Analyze recent ransomware trends&#10;- What are the most critical CVEs this month?&#10;- Explain APT29 tactics and techniques&#10;- Summarize active phishing campaigns"
                    value={aiQuery}
                    onChange={(e) => setAiQuery(e.target.value)}
                    rows={4}
                    className="flex-1 bg-[#0a0e17] border-gray-700 rounded-lg p-3 text-sm font-mono resize-none focus:border-pink-500 focus:ring-pink-500/20"
                  />
                </div>
                <div className="flex justify-end">
                  <Button onClick={runAIAnalysis} disabled={isAILoading || !aiQuery} className="bg-gradient-to-r from-pink-600 to-purple-600 hover:from-pink-700 hover:to-purple-700">
                    {isAILoading ? (
                      <><Loader2 className="h-4 w-4 animate-spin mr-2" />AI Analyzing...</>
                    ) : (
                      <><Sparkles className="h-4 w-4 mr-2" />Run AI Analysis</>
                    )}
                  </Button>
                </div>

                {aiAnalysis && (
                  <div className="mt-6 space-y-4 animate-in fade-in slide-in-from-bottom-2">
                    <Card className="bg-gradient-to-br from-pink-950/20 to-purple-950/20 border-pink-500/20">
                      <CardHeader className="pb-2 pt-3 px-4">
                        <CardTitle className="text-sm font-medium text-pink-300 flex items-center gap-2">
                          <Brain className="h-4 w-4" /> AI Analysis Results
                          <Badge variant="outline" className="text-[10px] border-pink-500/30 text-pink-400">
                            Confidence: {aiAnalysis.confidence}%
                          </Badge>
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="px-4 pb-4 space-y-4">
                        <div>
                          <h4 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">Executive Summary</h4>
                          <p className="text-sm text-gray-200 leading-relaxed">{aiAnalysis.summary}</p>
                        </div>
                        
                        <div>
                          <h4 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">Key Findings</h4>
                          <ul className="space-y-2">
                            {aiAnalysis.keyFindings.map((finding, i) => (
                              <li key={i} className="text-sm text-gray-300 flex items-start gap-2">
                                <Zap className="h-4 w-4 text-yellow-400 mt-0.5 shrink-0" />
                                <span>{finding}</span>
                              </li>
                            ))}
                          </ul>
                        </div>

                        <div>
                          <h4 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">Recommendations</h4>
                          <ul className="space-y-2">
                            {aiAnalysis.recommendations.map((rec, i) => (
                              <li key={i} className="text-sm text-gray-300 flex items-start gap-2">
                                <CheckCircle2 className="h-4 w-4 text-green-400 mt-0.5 shrink-0" />
                                <span>{rec}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== THREATS ==================== */}
          <TabsContent value="threats" className="space-y-4 animate-in fade-in slide-in-from-left-2">
            <Card className="bg-[#111827] border-gray-800">
              <CardHeader className="pb-3 pt-4 px-4">
                <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
                  <Target className="h-4 w-4 text-red-400" />
                  Threat Intelligence Dashboard
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-4 space-y-4">
                {threatData && (
                  <>
                    {/* Global Threat Level */}
                    <div className="p-4 rounded-lg bg-[#0a0e17] border border-gray-800">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="text-sm font-medium text-gray-300">Global Threat Assessment</h3>
                        <div className="flex items-center gap-2">
                          <span className={`px-3 py-1 rounded text-sm font-mono font-bold ${getSeverityStyle(threatData.globalThreatLevel.level)}`}>
                            {threatData.globalThreatLevel.level}
                          </span>
                          <span className="text-2xl font-black font-mono" style={{color: getThreatGaugeColor(threatData.globalThreatLevel.score)}}>
                            {threatData.globalThreatLevel.score}
                          </span>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
                        <div className="p-2 bg-gray-900/50 rounded">
                          <div className="text-gray-500">Critical CVEs</div>
                          <div className="text-red-400 font-bold">{threatData.globalThreatLevel.factors?.criticalVulnerabilities24h || 0}</div>
                        </div>
                        <div className="p-2 bg-gray-900/50 rounded">
                          <div className="text-gray-500">High Severity</div>
                          <div className="text-orange-400 font-bold">{threatData.globalThreatLevel.factors?.highSeverityVulnerabilities24h || 0}</div>
                        </div>
                        <div className="p-2 bg-gray-900/50 rounded">
                          <div className="text-gray-500">Active Campaigns</div>
                          <div className="text-yellow-400 font-bold">{threatData.globalThreatLevel.factors?.activeCampaigns || 0}</div>
                        </div>
                        <div className="p-2 bg-gray-900/50 rounded">
                          <div className="text-gray-500">Monitored IOCs</div>
                          <div className="text-blue-400 font-bold">{threatData.globalThreatLevel.factors?.monitoredIOCs || 0}</div>
                        </div>
                      </div>
                    </div>

                    {/* Active Campaigns */}
                    <div>
                      <h3 className="text-sm font-medium text-gray-300 mb-3">Active Threat Campaigns</h3>
                      <div className="space-y-3">
                        {threatData.campaigns?.map((campaign: any, i: number) => (
                          <Card key={i} className={`bg-[#0a0e17] border ${
                            campaign.status === 'ACTIVE' ? 'border-red-500/30' : 'border-gray-800'
                          }`}>
                            <CardContent className="pt-4 pb-4 px-4">
                              <div className="flex items-start justify-between mb-2">
                                <div>
                                  <div className="flex items-center gap-2">
                                    <code className="text-xs font-mono text-gray-500">{campaign.id}</code>
                                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                                      campaign.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                                      campaign.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                                      'bg-yellow-500/20 text-yellow-400'
                                    }`}>{campaign.severity}</span>
                                    {campaign.status === 'ACTIVE' && (
                                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-500/10 text-red-400 animate-pulse">
                                        ● ACTIVE
                                      </span>
                                    )}
                                  </div>
                                  <h4 className="text-sm font-semibold text-white mt-1">{campaign.name}</h4>
                                </div>
                              </div>
                              <p className="text-xs text-gray-400 mb-3">{campaign.description}</p>
                                                              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[10px] font-mono">
                                <div><span className="text-gray-500">Target:</span> <span className="text-gray-300">{campaign.targetSectors?.join(', ')}</span></div>
                                <div><span className="text-gray-500">Indicators:</span> <span className="text-gray-300">{campaign.indicators}</span></div>
                                <div><span className="text-gray-500">MITRE:</span> <span className="text-gray-300">{campaign.mitreTechniques?.join(', ')}</span></div>
                                <div><span className="text-gray-500">Started:</span> <span className="text-gray-300">{campaign.startDate}</span></div>
                              </div>
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    </div>

                    {/* APT Groups */}
                    <div>
                      <h3 className="text-sm font-medium text-gray-300 mb-3">Tracked APT Groups</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {threatData.aptGroups?.map((apt: any, i: number) => (
                          <Card key={i} className="bg-[#0a0e17] border-gray-800">
                            <CardContent className="pt-4 pb-4 px-4">
                              <div className="flex items-center justify-between mb-2">
                                <h4 className="text-sm font-semibold text-white">{apt.name}</h4>
                                <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                                  apt.status === 'ACTIVE' ? 'bg-red-500/10 text-red-400' : 'bg-gray-800 text-gray-500'
                                }`}>{apt.status}</span>
                              </div>
                              <p className="text-xs text-gray-400 mb-2">{apt.description}</p>
                              <div className="flex items-center gap-4 text-[10px] font-mono">
                                <span className="text-gray-500">Country: <span className="text-gray-300">{apt.country}</span></span>
                                <span className="text-gray-500">Confidence: <span className="text-gray-300">{apt.attributionConfidence}</span></span>
                              </div>
                              <div className="flex flex-wrap gap-1 mt-2">
                                {apt.techniques?.slice(0, 3).map((tech: string, j: number) => (
                                  <Badge key={j} variant="outline" className="text-[10px] border-gray-700 text-gray-400">{tech}</Badge>
                                ))}
                              </div>
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== REPORTS ==================== */}
          <TabsContent value="reports" className="space-y-4 animate-in fade-in slide-in-from-left-2">
            <Card className="bg-[#111827] border-gray-800">
              <CardHeader className="pb-3 pt-4 px-4">
                <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
                  <FileText className="h-4 w-4 text-emerald-400" />
                  Executive Reports Generator
                  <Badge variant="outline" className="text-[10px] border-emerald-500/30 text-emerald-400">PROFESSIONAL</Badge>
                </CardTitle>
                <p className="text-xs text-gray-500 mt-1">Generate professional intelligence reports in multiple formats</p>
              </CardHeader>
              <CardContent className="px-4 pb-4 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <Button 
                    onClick={() => generateReport('threat-briefing')}
                    disabled={isLoading}
                    className="h-auto py-4 bg-[#0a0e17] border border-gray-700 hover:border-blue-500/50 hover:bg-gray-800/50 flex flex-col items-center gap-2"
                    variant="outline"
                  >
                    <FileWarning className="h-6 w-6 text-blue-400" />
                    <span className="text-sm font-medium">Threat Briefing</span>
                    <span className="text-[10px] text-gray-500">Current threat landscape</span>
                  </Button>

                  <Button 
                    onClick={() => generateReport('ioc-report')}
                    disabled={isLoading}
                    className="h-auto py-4 bg-[#0a0e17] border border-gray-700 hover:border-orange-500/50 hover:bg-gray-800/50 flex flex-col items-center gap-2"
                    variant="outline"
                  >
                    <Target className="h-6 w-6 text-orange-400" />
                    <span className="text-sm font-medium">IOC Report</span>
                    <span className="text-[10px] text-gray-500">Indicators of compromise</span>
                  </Button>

                  <Button 
                    onClick={() => generateReport('executive-summary')}
                    disabled={isLoading}
                    className="h-auto py-4 bg-[#0a0e17] border border-gray-700 hover:border-emerald-500/50 hover:bg-gray-800/50 flex flex-col items-center gap-2"
                    variant="outline"
                  >
                    <BarChart3 className="h-6 w-6 text-emerald-400" />
                    <span className="text-sm font-medium">Executive Summary</span>
                    <span className="text-[10px] text-gray-500">C-level briefing document</span>
                  </Button>
                </div>

                {reportData && (
                  <div className="mt-6 space-y-4 animate-in fade-in slide-in-from-bottom-2">
                    <Card className="bg-[#0a0e17] border-gray-800">
                      <CardHeader className="pb-2 pt-3 px-4">
                        <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
                          <FileText className="h-4 w-4" /> Generated Report
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="px-4 pb-4">
                        <div className="prose prose-invert prose-sm max-w-none">
                          <pre className="whitespace-pre-wrap text-xs text-gray-300 font-mono bg-[#080c12] p-4 rounded-lg overflow-x-auto">
                            {JSON.stringify(reportData, null, 2)}
                          </pre>
                        </div>
                        <div className="flex gap-2 mt-4">
                          <Button size="sm" className="bg-emerald-600 hover:bg-emerald-700">
                            <Download className="h-4 w-4 mr-2" />Download PDF
                          </Button>
                          <Button size="sm" variant="outline" className="border-gray-700 text-gray-300 hover:bg-gray-800">
                            <Copy className="h-4 w-4 mr-2" />Copy JSON
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== LIVE MONITORING ==================== */}
          <TabsContent value="monitoring" className="space-y-4 animate-in fade-in slide-in-from-left-2">
            <Card className="bg-[#111827] border-gray-800">
              <CardHeader className="pb-3 pt-4 px-4">
                <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
                  <Radio className="h-4 w-4 text-green-400 animate-pulse" />
                  Live Threat Monitoring
                  <Badge variant="outline" className="text-[10px] border-green-500/30 text-green-400">LIVE</Badge>
                </CardTitle>
                <p className="text-xs text-gray-500 mt-1">Real-time intelligence feed • Auto-refreshes every 60 seconds</p>
              </CardHeader>
              <CardContent className="px-4 pb-4 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="text-xs text-gray-400 font-mono">LIVE FEED ACTIVE</span>
                  </div>
                  <Button variant="ghost" size="sm" onClick={fetchThreatIntelligence} className="text-gray-400 hover:text-white">
                    <RefreshCw className="h-4 w-4 mr-2" />Refresh Now
                  </Button>
                </div>

                {/* IOC Feed */}
                <div>
                  <h3 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-3">Recent IOCs</h3>
                  <div className="space-y-2 max-h-[400px] overflow-y-auto">
                    {threatData?.iocs?.slice(0, 15).map((ioc: any, i: number) => (
                      <div key={i} className="flex items-center justify-between p-2 bg-[#0a0e17] rounded border border-gray-800/50 text-xs font-mono hover:border-gray-700 transition-colors">
                        <div className="flex items-center gap-3">
                          <Badge variant="outline" className="text-[10px] border-gray-700 text-gray-500 w-14 justify-center">
                            {ioc.type.toUpperCase()}
                          </Badge>
                          <code className="text-gray-300">{ioc.value}</code>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                            ioc.threatLevel === 'Critical' ? 'bg-red-500/20 text-red-400' :
                            ioc.threatLevel === 'High' ? 'bg-orange-500/20 text-orange-400' :
                            'bg-gray-800 text-gray-400'
                          }`}>{ioc.threatLevel}</span>
                          <span className="text-gray-500 text-[10px]">{ioc.source}</span>
                        </div>
                      </div>
                    )) || (
                      <div className="text-center py-8 text-gray-500 text-sm">Loading threat feed...</div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 mt-8 py-4">
        <div className="max-w-[1800px] mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between text-[10px] text-gray-600 font-mono">
            <span>NEXUS INTEL OSINT Platform v3.0</span>
            <span>Data Sources: ip-api.com • NIST NVD • Google DNS • MalwareBazaar</span>
            <span>Classification: UNCLASSIFIED // FOR OFFICIAL USE ONLY</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
