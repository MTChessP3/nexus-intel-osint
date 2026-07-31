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
  ArrowRight, Copy, Check, Loader2, Send, Sparkles, Play
} from 'lucide-react';

// ============= TYPES =============
interface IPResult {
  query: string;
  geolocation: any;
  network: any;
  threat: any;
}

interface ThreatData {
  iocs: any[];
  activeThreats: any[];
  campaigns: any[];
  aptGroups: any[];
  globalThreatLevel: any;
  statistics: any;
}

// ============= MAIN COMPONENT =============
export default function NexusIntelDashboard() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  
  // Input states
  const [ipInput, setIpInput] = useState('8.8.8.8');
  const [domainInput, setDomainInput] = useState('google.com');
  const [cveInput, setCveInput] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [hashInput, setHashInput] = useState('');
  
  // Result states - initialized to show data loads
  const [ipResult, setIpResult] = useState<IPResult | null>(null);
  const [threatData, setThreatData] = useState<ThreatData | null>(null);
  const [cveResults, setCveResults] = useState<any[]>([]);
  const [domainResult, setDomainResult] = useState<any>(null);
  const [urlResult, setUrlResult] = useState<any>(null);
  const [hashResult, setHashResult] = useState<any>(null);
  const [aiAnalysis, setAiAnalysis] = useState<any>(null);
  const [reportData, setReportData] = useState<any>(null);

  // Auto-load data on mount
  useEffect(() => {
    console.log('[NEXUS] === PAGE LOADED - AUTO INITIALIZING ===');
    loadInitialData();
  }, []);

  // ============= API FUNCTIONS =============
  
  const loadInitialData = async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      console.log('[NEXUS] Loading initial threat data...');
      
      // Load threat intelligence automatically
      const threatsRes = await fetch('/api/osint/threats');
      if (threatsRes.ok) {
        const threatsData = await threatsRes.json();
        if (threatsData.success) {
          setThreatData(threatsData.data);
          console.log('[NEXUS] ✅ Threat data loaded:', threatsData.data.iocs?.length, 'IOCs');
          setSuccess(`Platform loaded! ${threatsData.data.iocs?.length || 0} IOCs monitoring`);
        }
      }

      // Auto-run IP analysis with default value
      console.log('[NEXUS] Running auto IP analysis for 8.8.8.8...');
      const ipRes = await fetch('/api/osint/ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: '8.8.8.8' })
      });
      
      if (ipRes.ok) {
        const ipData = await ipRes.json();
        if (ipData.success) {
          setIpResult(ipData.data);
          console.log('[NEXUS] ✅ IP data loaded:', ipData.data.query);
        }
      }

      // Auto-load recent CVEs
      console.log('[NEXUS] Loading recent CVEs...');
      const cveRes = await fetch('/api/osint/cve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keyword: 'critical vulnerability 2024' })
      });
      
      if (cveRes.ok) {
        const cveData = await cveRes.json();
        if (cveData.success && cveData.data?.results) {
          setCveResults(cveData.data.results.slice(0, 5));
          console.log('[NEXUS] ✅ CVE data loaded:', cveData.data.results.length, 'CVEs');
        }
      }

    } catch (err: any) {
      console.error('[NEXUS] ❌ Error loading initial data:', err);
      setError('Error loading data: ' + err.message);
    } finally {
      setIsLoading(false);
    }
  };

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
      
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      if (data.success) {
        setIpResult(data.data);
        setSuccess(`✅ IP ${data.data.query} analyzed - Risk: ${data.data.threat.level} (${data.data.threat.score}/100)`);
      } else throw new Error(data.error);
    } catch (err: any) {
      setError(err.message);
    }
    setIsLoading(false);
  };

  const analyzeDomain = async () => {
    if (!domainInput.trim()) return;
    setIsLoading(true); setError(null);
    
    try {
      const res = await fetch('/api/osint/domain', {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domainInput.trim() })
      });
      const data = await res.json();
      if (data.success) {
        setDomainResult(data.data);
        setSuccess(`✅ Domain ${data.data.domain} analyzed`);
      } else throw new Error(data.error);
    } catch (err: any) { setError(err.message); }
    setIsLoading(false);
  };

  const searchCVE = async () => {
    if (!cveInput.trim()) return;
    setIsLoading(true); setError(null);
    
    try {
      const isCVEId = cveInput.toUpperCase().startsWith('CVE-');
      const res = await fetch('/api/osint/cve', {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(isCVEId ? { cveId: cveInput } : { keyword: cveInput })
      });
      const data = await res.json();
      if (data.success) {
        setCveResults(data.data.results || [data.data]);
        setSuccess(`✅ Found ${data.data.results?.length || 1} CVE(s)`);
      } else throw new Error(data.error);
    } catch (err: any) { setError(err.message); }
    setIsLoading(false);
  };

  const analyzeURL = async () => {
    if (!urlInput.trim()) return;
    setIsLoading(true); setError(null);
    
    try {
      const res = await fetch('/api/osint/url', {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput.trim() })
      });
      const data = await res.json();
      if (data.success) {
        setUrlResult(data.data);
        setSuccess(`✅ URL analyzed - Risk: ${data.data.overallAssessment.riskLevel}`);
      } else throw new Error(data.error);
    } catch (err: any) { setError(err.message); }
    setIsLoading(false);
  };

  const analyzeHash = async () => {
    if (!hashInput.trim()) return;
    setIsLoading(true); setError(null);
    
    try {
      const res = await fetch('/api/osint/hash', {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: hashInput.trim() })
      });
      const data = await res.json();
      if (data.success) {
        setHashResult(data.data);
        setSuccess(`✅ Hash ${data.data.found ? 'FOUND' : 'not found'} - ${data.data.aggregateResults.classification}`);
      } else throw new Error(data.error);
    } catch (err: any) { setError(err.message); }
    setIsLoading(false);
  };

  const runAIAnalysis = async (query?: string) => {
    const aiQuery = query || 'Analyze current threat landscape and provide executive summary';
    setIsLoading(true); setError(null);
    
    try {
      const res = await fetch('/api/osint/ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: aiQuery, context: threatData })
      });
      const data = await res.json();
      if (data.success) {
        setAiAnalysis(data.data);
        setSuccess('✅ AI Analysis complete');
      } else throw new Error(data.error);
    } catch (err: any) { setError(err.message); }
    setIsLoading(false);
  };

  const generateReport = async (type: string) => {
    setIsLoading(true); setError(null);
    
    try {
      const res = await fetch('/api/osint/reports', {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          reportType: type, 
          data: { ipResult, domainResult, cveResults, urlResult, hashResult, threatData },
          options: { classification: 'CONFIDENTIAL' }
        })
      });
      const data = await res.json();
      if (data.success) {
        setReportData(data.data.report);
        setSuccess('✅ Report generated successfully!');
      } else throw new Error(data.error);
    } catch (err: any) { setError(err.message); }
    setIsLoading(false);
  };

  // ============= HELPERS =============
  
  const getSeverityStyle = (level: string) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL': case 'CRÍTICO': case 'PELIGROSO':
        return 'bg-red-500/20 text-red-400 border border-red-500/30';
      case 'HIGH': case 'ALTO': case 'ALTO RIESGO':
        return 'bg-orange-500/20 text-orange-400 border border-orange-500/30';
      case 'MEDIUM': case 'MEDIO': case 'SOSPECHOSO':
        return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30';
      default:
        return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
    }
  };

  // ============= RENDER =============
  return (
    <div className="min-h-screen bg-[#0a0e17] text-gray-100">
      {/* HEADER */}
      <header className="bg-gradient-to-r from-[#111827] to-[#1a1f35] border-b border-blue-900/30 sticky top-0 z-50">
        <div className="max-w-[1920px] mx-auto px-4 sm:px-6 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-cyan-500 rounded-xl flex items-center justify-center shadow-lg shadow-blue-500/25">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-lg font-bold tracking-wide text-white">NEXUS INTEL</h1>
                <p className="text-[10px] text-blue-400 font-mono tracking-widest">OSINT THREAT INTELLIGENCE PLATFORM v4.0</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {threatData?.globalThreatLevel && (
                <div className={`hidden sm:flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold font-mono animate-pulse ${getSeverityStyle(threatData.globalThreatLevel.level)}`}>
                  <Activity className="h-4 w-4" />
                  THREAT LEVEL: {threatData.globalThreatLevel.level}
                  <span className="text-sm">{threatData.globalThreatLevel.score}/100</span>
                </div>
              )}
              
              <Button 
                onClick={loadInitialData} 
                disabled={isLoading}
                className="bg-blue-600 hover:bg-blue-700 text-white"
              >
                {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                <span className="ml-2 hidden sm:inline">REFRESH</span>
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* MAIN CONTENT */}
      <main className="max-w-[1920px] mx-auto px-4 sm:px-6 py-6">
        
        {/* STATUS BANNER */}
        {(error || success) && (
          <div className={`mb-6 p-4 rounded-lg flex items-center gap-3 ${error ? 'bg-red-950/50 border border-red-800' : 'bg-emerald-950/50 border border-emerald-800'}`}>
            {error ? <XCircle className="h-5 w-5 text-red-500 shrink-0" /> : <CheckCircle2 className="h-5 w-5 text-emerald-500 shrink-0" />}
            <p className={`${error ? 'text-red-400' : 'text-emerald-400'} text-sm`}>{error || success}</p>
            <button onClick={() => { setError(null); setSuccess(null); }} className="ml-auto">
              <XCircle className="h-4 w-4 opacity-50 hover:opacity-100" />
            </button>
          </div>
        )}

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          
          {/* TAB NAVIGATION */}
          <TabsList className="bg-[#111827] border border-gray-800 p-2 h-auto grid grid-cols-5 lg:grid-cols-10 gap-2 rounded-xl">
            {[
              { value: 'dashboard', label: 'DASHBOARD', icon: Activity },
              { value: 'ip', label: 'IP Intel', icon: Globe2 },
              { value: 'domain', label: 'DOMAIN', icon: Globe },
              { value: 'cve', label: 'CVE DB', icon: Bug },
              { value: 'url', label: 'URL SCAN', icon: Link },
              { value: 'hash', label: 'HASH', icon: Fingerprint },
              { value: 'ai', label: 'AI ENGINE', icon: Brain },
              { value: 'threats', label: 'THREATS', icon: Target },
              { value: 'reports', label: 'REPORTS', icon: FileText },
              { value: 'monitoring', label: 'LIVE FEED', icon: Radio }
            ].map(tab => (
              <TabsTrigger 
                key={tab.value} 
                value={tab.value}
                className="text-[10px] sm:text-xs py-2.5 px-2 data-[state=active]:bg-blue-600 data-[state=active]:text-white text-gray-400 hover:text-white hover:bg-gray-800 transition-all rounded-lg font-medium"
              >
                <tab.icon className="h-3.5 w-3.5 mr-1 sm:mr-1.5" />
                <span className="hidden xs:inline">{tab.label}</span>
              </TabsTrigger>
            ))}
          </TabsList>

          {/* ==================== DASHBOARD TAB ==================== */}
          <TabsContent value="dashboard" className="space-y-6 animate-in fade-in duration-300">
            
            {/* LIVE STATUS INDICATOR */}
            <div className="flex items-center gap-3 p-4 bg-[#111827] rounded-xl border border-green-900/30">
              <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse shadow-lg shadow-green-500/50"></div>
              <span className="text-green-400 font-mono text-sm font-medium">PLATFORM ONLINE • ALL SYSTEMS OPERATIONAL</span>
              <span className="text-gray-500 text-xs ml-auto">Last updated: {new Date().toLocaleTimeString()}</span>
            </div>

            {/* KPI CARDS */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <Card className="bg-gradient-to-br from-[#111827] to-[#0d1117] border border-gray-800 hover:border-blue-500/50 transition-all group">
                <CardContent className="pt-6 pb-6">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Global Threat Level</p>
                    <ShieldAlert className="h-4 w-4 text-red-400 opacity-50 group-hover:opacity-100 transition-opacity" />
                  </div>
                  {threatData?.globalThreatLevel ? (
                    <>
                      <div className="text-4xl font-black text-white font-mono">{threatData.globalThreatLevel.score}</div>
                      <Badge className={`mt-2 ${getSeverityStyle(threatData.globalThreatLevel.level)}`}>{threatData.globalThreatLevel.level}</Badge>
                    </>
                  ) : (
                    <div className="animate-pulse space-y-2">
                      <div className="h-10 bg-gray-800 rounded w-24"></div>
                      <div className="h-6 bg-gray-800 rounded w-16"></div>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card className="bg-gradient-to-br from-[#111827] to-[#0d1117] border border-gray-800 hover:border-cyan-500/50 transition-all group">
                <CardContent className="pt-6 pb-6">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Active IOCs</p>
                    <Target className="h-4 w-4 text-cyan-400 opacity-50 group-hover:opacity-100 transition-opacity" />
                  </div>
                  <div className="text-4xl font-black text-cyan-400 font-mono">{threatData?.iocs?.length || 0}</div>
                  <p className="text-[10px] text-gray-500 mt-2">Indicators Monitored</p>
                </CardContent>
              </Card>

              <Card className="bg-gradient-to-br from-[#111827] to-[#0d1117] border border-gray-800 hover:border-orange-500/50 transition-all group">
                <CardContent className="pt-6 pb-6">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Recent Vulnerabilities</p>
                    <Bug className="h-4 w-4 text-orange-400 opacity-50 group-hover:opacity-100 transition-opacity" />
                  </div>
                  <div className="text-4xl font-black text-orange-400 font-mono">{threatData?.activeThreats?.length || cveResults.length}</div>
                  <p className="text-[10px] text-gray-500 mt-2">From NIST NVD</p>
                </CardContent>
              </Card>

              <Card className="bg-gradient-to-br from-[#111827] to-[#0d1117] border border-gray-800 hover:border-red-500/50 transition-all group">
                <CardContent className="pt-6 pb-6">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Active Campaigns</p>
                    <Radio className="h-4 w-4 text-red-400 opacity-50 group-hover:opacity-100 transition-opacity" />
                  </div>
                  <div className="text-4xl font-black text-red-400 font-mono">
                    {threatData?.campaigns?.filter((c: any) => c.status === 'ACTIVE').length || 0}
                  </div>
                  <p className="text-[10px] text-gray-500 mt-2">Require Attention</p>
                </CardContent>
              </Card>
            </div>

            {/* QUICK ANALYSIS PANEL */}
            <Card className="bg-[#111827] border border-gray-800">
              <CardHeader className="pb-4 pt-5 px-5">
                <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                  <Zap className="h-5 w-5 text-yellow-400" />
                  QUICK INTELLIGENCE ANALYSIS
                  <Badge variant="outline" className="text-[10px] border-yellow-500/30 text-yellow-400 ml-2">REAL-TIME DATA</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="px-5 pb-5 space-y-4">
                
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  
                  {/* IP INPUT */}
                  <div className="space-y-2">
                    <label className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold flex items-center gap-1">
                      <Globe2 className="h-3 w-3" /> IP Address
                    </label>
                    <div className="flex gap-2">
                      <Input 
                        value={ipInput} 
                        onChange={(e) => setIpInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && analyzeIP()} 
                        className="bg-[#0a0e17] border-gray-700 text-sm font-mono focus:border-blue-500 h-11"
                        placeholder="8.8.8.8"
                      />
                      <Button onClick={analyzeIP} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700 h-11 px-4">
                        <Search className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  {/* DOMAIN INPUT */}
                  <div className="space-y-2">
                    <label className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold flex items-center gap-1">
                      <Globe className="h-3 w-3" /> Domain
                    </label>
                    <div className="flex gap-2">
                      <Input 
                        value={domainInput} 
                        onChange={(e) => setDomainInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && analyzeDomain()} 
                        className="bg-[#0a0e17] border-gray-700 text-sm font-mono focus:border-cyan-500 h-11"
                        placeholder="example.com"
                      />
                      <Button onClick={analyzeDomain} disabled={isLoading} className="bg-cyan-600 hover:bg-cyan-700 h-11 px-4">
                        <Search className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  {/* CVE INPUT */}
                  <div className="space-y-2">
                    <label className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold flex items-center gap-1">
                      <Bug className="h-3 w-3" /> CVE / Keyword
                    </label>
                    <div className="flex gap-2">
                      <Input 
                        value={cveInput} 
                        onChange={(e) => setCveInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && searchCVE()} 
                        className="bg-[#0a0e17] border-gray-700 text-sm font-mono focus:border-orange-500 h-11"
                        placeholder="CVE-2024-..."
                      />
                      <Button onClick={searchCVE} disabled={isLoading} className="bg-orange-600 hover:bg-orange-700 h-11 px-4">
                        <Search className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  {/* URL INPUT */}
                  <div className="space-y-2">
                    <label className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold flex items-center gap-1">
                      <Link className="h-3 w-3" /> URL
                    </label>
                    <div className="flex gap-2">
                      <Input 
                        value={urlInput} 
                        onChange={(e) => setUrlInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && analyzeURL()} 
                        className="bg-[#0a0e17] border-gray-700 text-sm font-mono focus:border-purple-500 h-11"
                        placeholder="https://..."
                      />
                      <Button onClick={analyzeURL} disabled={isLoading} className="bg-purple-600 hover:bg-purple-700 h-11 px-4">
                        <Search className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </div>

                {/* LIVE RESULT DISPLAY */}
                {ipResult && (
                  <div className="mt-6 p-5 bg-gradient-to-r from-[#0a0e17] to-[#0d1220] rounded-xl border border-blue-900/30">
                    <div className="flex items-center gap-2 mb-4">
                      <CheckCircle2 className="h-5 w-5 text-green-400" />
                      <span className="text-sm font-bold text-green-400">LIVE ANALYSIS RESULT</span>
                      <Badge variant="outline" className="ml-auto text-[10px] border-blue-500/30 text-blue-400">REAL DATA FROM ip-api.com</Badge>
                    </div>
                    
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                      
                      {/* IP INFO */}
                      <div className="space-y-3">
                        <div className="flex items-center gap-2">
                          <code className="text-lg font-bold text-blue-400 font-mono">{ipResult.query}</code>
                          <Badge className={getSeverityStyle(ipResult.threat.level)}>
                            {ipResult.threat.icon} {ipResult.threat.level}
                          </Badge>
                        </div>
                        
                        {/* THREAT GAUGE */}
                        <div className="space-y-2">
                          <div className="flex justify-between text-xs">
                            <span className="text-gray-500">THREAT SCORE</span>
                            <span className="font-mono font-bold" style={{color: ipResult.threat.color}}>{ipResult.threat.score}/100</span>
                          </div>
                          <div className="w-full h-3 bg-gray-800 rounded-full overflow-hidden">
                            <div 
                              className="h-full transition-all duration-1000 ease-out rounded-full"
                              style={{ width: `${ipResult.threat.score}%`, backgroundColor: ipResult.threat.color }}
                            ></div>
                          </div>
                        </div>

                        <Separator className="bg-gray-800" />

                        {/* GEOLOCATION */}
                        <div className="space-y-1.5 text-xs font-mono">
                          <div className="flex items-center gap-2"><MapPin className="h-3 w-3 text-gray-500" /><span className="text-gray-500">Location:</span> <span className="text-white">{ipResult.geolocation.city}, {ipResult.geolocation.country}</span></div>
                          <div className="flex items-center gap-2"><Server className="h-3 w-3 text-gray-500" /><span className="text-gray-500">ISP:</span> <span className="text-white">{ipResult.network.isp}</span></div>
                          <div className="flex items-center gap-2"><Globe2 className="h-3 w-3 text-gray-500" /><span className="text-gray-500">ASN:</span> <span className="text-white">{ipResult.network.asn}</span></div>
                          <div className="flex items-center gap-2"><Shield className="h-3 w-3 text-gray-500" /><span className="text-gray-500">Proxy:</span> <span className={ipResult.network.isProxy ? 'text-red-400' : 'text-green-400'}>{ipResult.network.isProxy ? '⚠️ DETECTED' : '✓ NONE'}</span></div>
                          <div className="flex items-center gap-2"><Database className="h-3 w-3 text-gray-500" /><span className="text-gray-500">Hosting:</span> <span className={ipResult.network.isHosting ? 'text-yellow-400' : 'text-green-400'}>{ipResult.network.isHosting ? '⚠️ YES' : '✓ NO'}</span></div>
                        </div>
                      </div>

                      {/* INDICATORS */}
                      <div className="lg:col-span-2 space-y-3">
                        <div>
                          <h4 className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-2 flex items-center gap-1">
                            <ShieldAlert className="h-3 w-3" /> Threat Indicators
                          </h4>
                          <div className="space-y-1.5">
                            {ipResult.threat.indicators.map((ind: string, i: number) => (
                              <div key={i} className="text-xs text-gray-300 flex items-start gap-2 p-2 bg-gray-900/50 rounded">
                                <span className="text-yellow-400 mt-0.5">▸</span>
                                <span>{ind}</span>
                              </div>
                            ))}
                          </div>
                        </div>

                        <div>
                          <h4 className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-2 flex items-center gap-1">
                            <Info className="h-3 w-3" /> Recommendations
                          </h4>
                          <div className="space-y-1.5">
                            {ipResult.threat.recommendations.map((rec: string, i: number) => (
                              <div key={i} className="text-xs text-gray-300 flex items-start gap-2 p-2 bg-emerald-950/20 rounded border border-emerald-900/20">
                                <CheckCircle2 className="h-3 w-3 text-emerald-400 mt-0.5 shrink-0" />
                                <span>{rec}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* RECENT VULNERABILITIES TABLE */}
            {cveResults.length > 0 && (
              <Card className="bg-[#111827] border border-gray-800">
                <CardHeader className="pb-4 pt-5 px-5 flex flex-row items-center justify-between">
                  <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                    <ShieldAlert className="h-5 w-5 text-orange-400" />
                    RECENT VULNERABILITIES (NIST NVD)
                    <Badge variant="outline" className="text-[10px] border-orange-500/30 text-orange-400">REAL-TIME</Badge>
                  </CardTitle>
                  <Button variant="ghost" size="sm" onClick={() => setActiveTab('cve')} className="text-gray-400 hover:text-white">
                    View All <ChevronRight className="h-4 w-4 ml-1" />
                  </Button>
                </CardHeader>
                <CardContent className="px-5 pb-5">
                  <ScrollArea className="h-[350px]">
                    <table className="w-full text-sm">
                      <thead className="sticky top-0 bg-[#111827] z-10">
                        <tr className="border-b border-gray-800">
                          <th className="text-left py-3 px-3 font-semibold text-gray-400 uppercase text-[10px] tracking-wider">CVE ID</th>
                          <th className="text-left py-3 px-3 font-semibold text-gray-400 uppercase text-[10px] tracking-wider">Severity</th>
                          <th className="text-left py-3 px-3 font-semibold text-gray-400 uppercase text-[10px] tracking-wider">CVSS</th>
                          <th className="text-left py-3 px-3 font-semibold text-gray-400 uppercase text-[10px] tracking-wider">Published</th>
                          <th className="text-right py-3 px-3 font-semibold text-gray-400 uppercase text-[10px] tracking-wider">Action</th>
                        </tr>
                      </thead>
                      <tbody className="font-mono">
                        {cveResults.slice(0, 8).map((cve: any, i: number) => (
                          <tr key={i} className="border-b border-gray-800/50 hover:bg-blue-950/20 transition-colors">
                            <td className="py-3 px-3">
                              <code className="text-blue-400 font-semibold text-xs">{cve.id}</code>
                            </td>
                            <td className="py-3 px-3">
                              <Badge className={`text-[10px] ${getSeverityStyle(cve.cvss.severity)}`}>{cve.cvss.severity || 'UNKNOWN'}</Badge>
                            </td>
                            <td className="py-3 px-3 text-gray-300">{cve.cvss.score || '-'}</td>
                            <td className="py-3 px-3 text-gray-500 text-xs">{new Date(cve.dates.published).toLocaleDateString()}</td>
                            <td className="py-3 px-3 text-right">
                              <Button 
                                variant="ghost" 
                                size="sm" 
                                onClick={() => { setCveInput(cve.id); setActiveTab('cve'); }}
                                className="h-8 w-8 p-0 text-blue-400 hover:text-blue-300 hover:bg-blue-950/50"
                              >
                                <ArrowRight className="h-4 w-4" />
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

          {/* ==================== IP INTEL TAB ==================== */}
          <TabsContent value="ip" className="space-y-6 animate-in fade-in duration-300">
            <Card className="bg-[#111827] border border-gray-800">
              <CardHeader className="pb-4 pt-5 px-5">
                <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                  <Globe2 className="h-5 w-5 text-blue-400" />
                  IP GEOLocation & THREAT INTELLIGENCE
                  <Badge variant="outline" className="text-[10px] border-blue-500/30 text-blue-400">ip-api.com</Badge>
                </CardTitle>
                <p className="text-sm text-gray-400 mt-2">Real-time geolocation and threat assessment using ip-api.com API</p>
              </CardHeader>
              <CardContent className="px-5 pb-5 space-y-4">
                <div className="flex gap-3 max-w-2xl">
                  <Input 
                    value={ipInput} 
                    onChange={(e) => setIpInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeIP()} 
                    className="flex-1 bg-[#0a0e17] border-gray-700 font-mono text-base h-12 focus:border-blue-500"
                    placeholder="Enter IPv4 address (e.g., 8.8.8.8, 1.1.1.1)"
                  />
                  <Button onClick={analyzeIP} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700 h-12 px-6 text-sm font-bold">
                    {isLoading ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />Analyzing...</> : <><Search className="h-4 w-4 mr-2" />Analyze IP</>}
                  </Button>
                </div>

                {ipResult && (
                  <div className="mt-6 space-y-4 animate-in slide-in-from-bottom-2">
                    {/* Main Result Banner */}
                    <div className={`p-5 rounded-xl border-l-4 ${
                      ipResult.threat.score >= 60 ? 'bg-red-950/30 border-red-500' :
                      ipResult.threat.score >= 40 ? 'bg-orange-950/30 border-orange-500' :
                      ipResult.threat.score >= 20 ? 'bg-yellow-950/30 border-yellow-500' :
                      'bg-emerald-950/30 border-emerald-500'
                    }`}>
                      <div className="flex items-center justify-between mb-3">
                        <span className="text-xl font-bold font-mono">{ipResult.threat.icon} THREAT: {ipResult.threat.level}</span>
                        <span className="text-4xl font-black font-mono" style={{color: ipResult.threat.color}}>{ipResult.threat.score}/100</span>
                      </div>
                      <div className="w-full h-3 bg-gray-800 rounded-full overflow-hidden">
                        <div className="h-full transition-all duration-1000 rounded-full" style={{width: `${ipResult.threat.score}%`, backgroundColor: ipResult.threat.color}}></div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                      <Card className="bg-[#0a0e17] border-gray-800">
                        <CardHeader className="pb-2 pt-4 px-4">
                          <CardTitle className="text-xs font-bold text-gray-400 flex items-center gap-2"><MapPin className="h-4 w-4" /> GEOLOCATION</CardTitle>
                        </CardHeader>
                        <CardContent className="px-4 pb-4 space-y-2 text-xs font-mono">
                          <div className="flex justify-between"><span className="text-gray-500">Country:</span><span className="text-white">{ipResult.geolocation.country}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Region:</span><span className="text-white">{ipResult.geolocation.region}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">City:</span><span className="text-white">{ipResult.geolocation.city}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Coords:</span><span className="text-white">{ipResult.geolocation.latitude}, {ipResult.geolocation.longitude}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Timezone:</span><span className="text-white">{ipResult.geolocation.timezone}</span></div>
                        </CardContent>
                      </Card>

                      <Card className="bg-[#0a0e17] border-gray-800">
                        <CardHeader className="pb-2 pt-4 px-4">
                          <CardTitle className="text-xs font-bold text-gray-400 flex items-center gap-2"><Server className="h-4 w-4" /> NETWORK</CardTitle>
                        </CardHeader>
                        <CardContent className="px-4 pb-4 space-y-2 text-xs font-mono">
                          <div className="flex justify-between"><span className="text-gray-500">ISP:</span><span className="text-white">{ipResult.network.isp}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Org:</span><span className="text-white">{ipResult.network.org}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">ASN:</span><span className="text-white">{ipResult.network.asn}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Mobile:</span><span className={ipResult.network.isMobile ? 'text-orange-400' : 'text-gray-400'}>{ipResult.network.isMobile ? 'YES' : 'NO'}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Proxy:</span><span className={ipResult.network.isProxy ? 'text-red-400' : 'text-gray-400'}>{ipResult.network.isProxy ? '⚠️ YES' : 'NO'}</span></div>
                        </CardContent>
                      </Card>

                      <Card className="bg-[#0a0e17] border-gray-800">
                        <CardHeader className="pb-2 pt-4 px-4">
                          <CardTitle className="text-xs font-bold text-gray-400 flex items-center gap-2"><ShieldAlert className="h-4 w-4" /> INDICATORS</CardTitle>
                        </CardHeader>
                        <CardContent className="px-4 pb-4">
                          <div className="space-y-2">
                            {ipResult.threat.indicators.map((ind: string, i: number) => (
                              <div key={i} className="text-xs text-gray-300 flex items-start gap-2">
                                <span className="text-yellow-400 mt-0.5">•</span>
                                <span>{ind}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== AI ENGINE TAB ==================== */}
          <TabsContent value="ai" className="space-y-6 animate-in fade-in duration-300">
            <Card className="bg-gradient-to-br from-[#111827] to-[#0f1729] border border-purple-900/30">
              <CardHeader className="pb-4 pt-5 px-5">
                <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                  <Brain className="h-5 w-5 text-purple-400" />
                  AI INTELLIGENCE ENGINE
                  <Badge variant="outline" className="text-[10px] border-purple-500/30 text-purple-400">POWERED BY AI</Badge>
                </CardTitle>
                <p className="text-sm text-gray-400 mt-2">Advanced threat analysis powered by artificial intelligence</p>
              </CardHeader>
              <CardContent className="px-5 pb-5 space-y-4">
                
                {/* Quick AI Actions */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <Button 
                    onClick={() => runAIAnalysis('Analyze the current global cyber threat landscape and provide executive summary')}
                    disabled={isLoading}
                    className="h-auto py-4 bg-purple-600/20 border border-purple-500/30 hover:bg-purple-600/40 text-purple-300 flex flex-col items-center gap-2"
                    variant="outline"
                  >
                    <Brain className="h-6 w-6" />
                    <span className="font-bold">Threat Landscape</span>
                    <span className="text-[10px] text-purple-400/70">AI Analysis</span>
                  </Button>

                  <Button 
                    onClick={() => runAIAnalysis('Explain APT groups currently active and their tactics, techniques and procedures')}
                    disabled={isLoading}
                    className="h-auto py-4 bg-red-600/20 border border-red-500/30 hover:bg-red-600/40 text-red-300 flex flex-col items-center gap-2"
                    variant="outline"
                  >
                    <Target className="h-6 w-6" />
                    <span className="font-bold">APT Groups</span>
                    <span className="text-[10px] text-red-400/70">MITRE ATT&CK</span>
                  </Button>

                  <Button 
                    onClick={() => runAIAnalysis('Provide ransomware trends analysis and mitigation recommendations for enterprise security teams')}
                    disabled={isLoading}
                    className="h-auto py-4 bg-orange-600/20 border border-orange-500/30 hover:bg-orange-600/40 text-orange-300 flex flex-col items-center gap-2"
                    variant="outline"
                  >
                    <FileWarning className="h-6 w-6" />
                    <span className="font-bold">Ransomware</span>
                    <span className="text-[10px] text-orange-400/70">Trends & Mitigation</span>
                  </Button>
                </div>

                {/* Custom Query */}
                <div className="space-y-2">
                  <label className="text-xs text-gray-500 uppercase tracking-wider font-semibold">Custom AI Query</label>
                  <textarea
                    placeholder="Ask about threats, vulnerabilities, or request analysis..."
                    rows={3}
                    className="w-full bg-[#0a0e17] border border-gray-700 rounded-lg p-3 text-sm font-mono resize-none focus:border-purple-500"
                  />
                  <div className="flex justify-end">
                    <Button 
                      onClick={() => runAIAnalysis()}
                      disabled={isLoading}
                      className="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700"
                    >
                      {isLoading ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />AI Processing...</> : <><Sparkles className="h-4 w-4 mr-2" />Run AI Analysis</>}
                    </Button>
                  </div>
                </div>

                {/* AI Results */}
                {aiAnalysis && (
                  <div className="mt-6 p-5 bg-gradient-to-br from-purple-950/20 to-pink-950/20 rounded-xl border border-purple-500/20 animate-in fade-in">
                    <div className="flex items-center gap-2 mb-4">
                      <Brain className="h-5 w-5 text-purple-400" />
                      <span className="font-bold text-purple-300">AI Analysis Complete</span>
                      <Badge variant="outline" className="ml-auto text-[10px] border-purple-500/30 text-purple-400">
                        Confidence: {aiAnalysis.confidence}%
                      </Badge>
                    </div>
                    
                    <div className="space-y-4">
                      <div>
                        <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2 font-semibold">Executive Summary</h4>
                        <p className="text-sm text-gray-200 leading-relaxed">{aiAnalysis.summary}</p>
                      </div>
                      
                      <div>
                        <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2 font-semibold">Key Findings</h4>
                        <ul className="space-y-2">
                          {aiAnalysis.keyFindings.map((finding: string, i: number) => (
                            <li key={i} className="text-sm text-gray-300 flex items-start gap-2">
                              <Zap className="h-4 w-4 text-yellow-400 mt-0.5 shrink-0" />
                              <span>{finding}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== REPORTS TAB ==================== */}
          <TabsContent value="reports" className="space-y-6 animate-in fade-in duration-300">
            <Card className="bg-[#111827] border border-gray-800">
              <CardHeader className="pb-4 pt-5 px-5">
                <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                  <FileText className="h-5 w-5 text-emerald-400" />
                  EXECUTIVE REPORT GENERATOR
                  <Badge variant="outline" className="text-[10px] border-emerald-500/30 text-emerald-400">PROFESSIONAL</Badge>
                </CardTitle>
                <p className="text-sm text-gray-400 mt-2">Generate professional intelligence reports for C-suite executives</p>
              </CardHeader>
              <CardContent className="px-5 pb-5 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Button 
                    onClick={() => generateReport('threat-briefing')}
                    disabled={isLoading}
                    className="h-auto py-6 bg-[#0a0e17] border border-gray-700 hover:border-blue-500/50 hover:bg-gray-800/50 flex flex-col items-center gap-3"
                    variant="outline"
                  >
                    <FileWarning className="h-8 w-8 text-blue-400" />
                    <span className="font-bold">Threat Briefing</span>
                    <span className="text-xs text-gray-500">Current threat landscape report</span>
                  </Button>

                  <Button 
                    onClick={() => generateReport('ioc-report')}
                    disabled={isLoading}
                    className="h-auto py-6 bg-[#0a0e17] border border-gray-700 hover:border-orange-500/50 hover:bg-gray-800/50 flex flex-col items-center gap-3"
                    variant="outline"
                  >
                    <Target className="h-8 w-8 text-orange-400" />
                    <span className="font-bold">IOC Report</span>
                    <span className="text-xs text-gray-500">Indicators of compromise</span>
                  </Button>

                  <Button 
                    onClick={() => generateReport('executive-summary')}
                    disabled={isLoading}
                    className="h-auto py-6 bg-[#0a0e17] border border-gray-700 hover:border-emerald-500/50 hover:bg-gray-800/50 flex flex-col items-center gap-3"
                    variant="outline"
                  >
                    <BarChart3 className="h-8 w-8 text-emerald-400" />
                    <span className="font-bold">Executive Summary</span>
                    <span className="text-xs text-gray-500">C-level briefing document</span>
                  </Button>
                </div>

                {reportData && (
                  <div className="mt-6 p-5 bg-[#0a0e17] rounded-xl border border-gray-800 animate-in fade-in">
                    <div className="flex items-center gap-2 mb-4">
                      <FileText className="h-5 w-5 text-emerald-400" />
                      <span className="font-bold text-emerald-400">REPORT GENERATED SUCCESSFULLY</span>
                    </div>
                    <pre className="whitespace-pre-wrap text-xs text-gray-300 font-mono bg-[#080c12] p-4 rounded-lg max-h-[500px] overflow-auto">
                      {JSON.stringify(reportData, null, 2)}
                    </pre>
                    <div className="flex gap-2 mt-4">
                      <Button size="sm" className="bg-emerald-600 hover:bg-emerald-700">
                        <Download className="h-4 w-4 mr-2" />Download PDF
                      </Button>
                      <Button size="sm" variant="outline" className="border-gray-700 text-gray-300">
                        <Copy className="h-4 w-4 mr-2" />Copy JSON
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== OTHER TABS (SIMPLIFIED) ==================== */}
          
          {/* DOMAIN TAB */}
          <TabsContent value="domain" className="space-y-6 animate-in fade-in duration-300">
            <Card className="bg-[#111827] border border-gray-800">
              <CardHeader className="pb-4 pt-5 px-5">
                <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                  <Globe className="h-5 w-5 text-cyan-400" /> DOMAIN INTELLIGENCE
                </CardTitle>
              </CardHeader>
              <CardContent className="px-5 pb-5 space-y-4">
                <div className="flex gap-3 max-w-2xl">
                  <Input value={domainInput} onChange={(e) => setDomainInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && analyzeDomain()} className="flex-1 bg-[#0a0e17] border-gray-700 font-mono h-12" placeholder="google.com" />
                  <Button onClick={analyzeDomain} disabled={isLoading} className="bg-cyan-600 hover:bg-cyan-700 h-12 px-6">{isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />} Analyze</Button>
                </div>
                {domainResult && (
                  <div className="mt-4 p-4 bg-[#0a0e17] rounded-lg border border-gray-800">
                    <code className="text-cyan-400 font-bold">{domainResult.domain}</code>
                    <Badge className={`ml-2 ${getSeverityStyle(domainResult.reputation.level)}`}>{domainResult.reputation.level}: {domainResult.reputation.score}/100</Badge>
                    <pre className="mt-4 text-xs text-gray-400 font-mono whitespace-pre-wrap">{JSON.stringify(domainResult, null, 2)}</pre>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* CVE TAB */}
          <TabsContent value="cve" className="space-y-6 animate-in fade-in duration-300">
            <Card className="bg-[#111827] border border-gray-800">
              <CardHeader className="pb-4 pt-5 px-5">
                <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                  <Bug className="h-5 w-5 text-orange-400" /> CVE DATABASE (NIST NVD)
                </CardTitle>
              </CardHeader>
              <CardContent className="px-5 pb-5 space-y-4">
                <div className="flex gap-3 max-w-2xl">
                  <Input value={cveInput} onChange={(e) => setCveInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && searchCVE()} className="flex-1 bg-[#0a0e17] border-gray-700 font-mono h-12" placeholder="CVE-2024-1234 or keyword" />
                  <Button onClick={searchCVE} disabled={isLoading} className="bg-orange-600 hover:bg-orange-700 h-12 px-6">{isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />} Search</Button>
                </div>
                {cveResults.length > 0 && (
                  <div className="mt-4 space-y-2 max-h-[500px] overflow-y-auto">
                    {cveResults.map((cve: any, i: number) => (
                      <div key={i} className="p-3 bg-[#0a0e17] rounded border border-gray-800 flex items-center justify-between">
                        <div>
                          <code className="text-blue-400 font-bold text-sm">{cve.id}</code>
                          <Badge className={`ml-2 text-[10px] ${getSeverityStyle(cve.cvss.severity)}`}>{cve.cvss.severity}</Badge>
                          <p className="text-xs text-gray-400 mt-1 line-clamp-1">{cve.descriptions}</p>
                        </div>
                        <span className="text-lg font-mono font-bold text-gray-400">{cve.cvss.score || '-'}</span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* URL TAB */}
          <TabsContent value="url" className="space-y-6 animate-in fade-in duration-300">
            <Card className="bg-[#111827] border border-gray-800">
              <CardHeader className="pb-4 pt-5 px-5">
                <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                  <Link className="h-5 w-5 text-purple-400" /> URL SECURITY SCANNER
                </CardTitle>
              </CardHeader>
              <CardContent className="px-5 pb-5 space-y-4">
                <div className="flex gap-3 max-w-2xl">
                  <Input value={urlInput} onChange={(e) => setUrlInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && analyzeURL()} className="flex-1 bg-[#0a0e17] border-gray-700 font-mono h-12" placeholder="https://..." />
                  <Button onClick={analyzeURL} disabled={isLoading} className="bg-purple-600 hover:bg-purple-700 h-12 px-6">{isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />} Scan</Button>
                </div>
                {urlResult && (
                  <div className="mt-4 p-4 bg-[#0a0e17] rounded-lg border border-gray-800">
                    <code className="text-purple-400 text-sm">{urlResult.url}</code>
                    <Badge className={`ml-2 ${getSeverityStyle(urlResult.overallAssessment.riskLevel)}`}>{urlResult.overallAssessment.riskLevel}: {urlResult.overallAssessment.threatScore}/100</Badge>
                    <p className="text-sm text-gray-300 mt-2">{urlResult.overallAssessment.verdict}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* HASH TAB */}
          <TabsContent value="hash" className="space-y-6 animate-in fade-in duration-300">
            <Card className="bg-[#111827] border border-gray-800">
              <CardHeader className="pb-4 pt-5 px-5">
                <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                  <Fingerprint className="h-5 w-5 text-orange-400" /> MALWARE HASH LOOKUP
                </CardTitle>
              </CardHeader>
              <CardContent className="px-5 pb-5 space-y-4">
                <div className="flex gap-3 max-w-2xl">
                  <Input value={hashInput} onChange={(e) => setHashInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && analyzeHash()} className="flex-1 bg-[#0a0e17] border-gray-700 font-mono h-12" placeholder="MD5/SHA1/SHA256 hash" />
                  <Button onClick={analyzeHash} disabled={isLoading} className="bg-orange-600 hover:bg-orange-700 h-12 px-6">{isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />} Lookup</Button>
                </div>
                
                <div className="flex flex-wrap gap-2">
                  <span className="text-xs text-gray-500">Quick test:</span>
                  {[
                    { hash: '44d88612fea8a8f36de82e1278abb02f', label: 'EICAR (Safe)' },
                    { hash: '3395856ce81f2b7386244a8c55b31c21', label: 'WannaCry' }
                  ].map(test => (
                    <button key={test.hash} onClick={() => setHashInput(test.hash)} className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded text-xs font-mono text-gray-400 hover:text-white transition-colors">
                      {test.label}
                    </button>
                  ))}
                </div>

                {hashResult && (
                  <div className="mt-4 p-4 bg-[#0a0e17] rounded-lg border border-gray-800">
                    <code className="text-orange-400 text-sm">{hashResult.input.hash.substring(0, 32)}...</code>
                    <Badge className={`ml-2 ${getSeverityStyle(hashResult.aggregateResults.threatLevel)}`}>{hashResult.aggregateResults.classification}</Badge>
                    <div className="mt-2 text-2xl font-black font-mono" style={{color: hashResult.aggregateResults.color}}>{hashResult.aggregateResults.detectionRate}% Detection</div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* THREATS TAB */}
          <TabsContent value="threats" className="space-y-6 animate-in fade-in duration-300">
            <Card className="bg-[#111827] border border-gray-800">
              <CardHeader className="pb-4 pt-5 px-5">
                <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                  <Target className="h-5 w-5 text-red-400" /> THREAT INTELLIGENCE DASHBOARD
                </CardTitle>
              </CardHeader>
              <CardContent className="px-5 pb-5">
                {threatData ? (
                  <div className="space-y-4">
                    {/* Global Threat Level */}
                    <div className="p-4 bg-[#0a0e17] rounded-lg border border-gray-800">
                      <div className="flex items-center justify-between mb-3">
                        <span className="font-bold">Global Threat Assessment</span>
                        <Badge className={getSeverityStyle(threatData.globalThreatLevel.level)}>{threatData.globalThreatLevel.level}: {threatData.globalThreatLevel.score}/100</Badge>
                      </div>
                      <div className="grid grid-cols-4 gap-3 text-xs font-mono">
                        <div className="p-2 bg-gray-900/50 rounded text-center">
                          <div className="text-gray-500">Critical</div>
                          <div className="text-red-400 font-bold text-lg">{threatData.globalThreatLevel.factors?.criticalVulnerabilities24h || 0}</div>
                        </div>
                        <div className="p-2 bg-gray-900/50 rounded text-center">
                          <div className="text-gray-500">High</div>
                          <div className="text-orange-400 font-bold text-lg">{threatData.globalThreatLevel.factors?.highSeverityVulnerabilities24h || 0}</div>
                        </div>
                        <div className="p-2 bg-gray-900/50 rounded text-center">
                          <div className="text-gray-500">Campaigns</div>
                          <div className="text-yellow-400 font-bold text-lg">{threatData.globalThreatLevel.factors?.activeCampaigns || 0}</div>
                        </div>
                        <div className="p-2 bg-gray-900/50 rounded text-center">
                          <div className="text-gray-500">IOCs</div>
                          <div className="text-blue-400 font-bold text-lg">{threatData.globalThreatLevel.factors?.monitoredIOCs || 0}</div>
                        </div>
                      </div>
                    </div>

                    {/* Active Campaigns */}
                    <div>
                      <h3 className="font-bold mb-3 flex items-center gap-2"><Radio className="h-4 w-4 text-red-400" /> Active Campaigns</h3>
                      <div className="space-y-3">
                        {threatData.campaigns?.map((campaign: any, i: number) => (
                          <div key={i} className={`p-4 rounded-lg border ${campaign.status === 'ACTIVE' ? 'border-red-500/30 bg-red-950/10' : 'border-gray-800 bg-[#0a0e17]'}`}>
                            <div className="flex items-center gap-2 mb-2">
                              <code className="text-xs text-gray-500">{campaign.id}</code>
                              <Badge className={`text-[10px] ${campaign.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : campaign.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' : 'bg-yellow-500/20 text-yellow-400'}`}>{campaign.severity}</Badge>
                              {campaign.status === 'ACTIVE' && <Badge className="text-[10px] bg-red-500/10 text-red-400 animate-pulse">● ACTIVE</Badge>}
                            </div>
                            <h4 className="font-bold text-white">{campaign.name}</h4>
                            <p className="text-xs text-gray-400 mt-1">{campaign.description}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-12 text-gray-500">Loading threat data...</div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* MONITORING TAB */}
          <TabsContent value="monitoring" className="space-y-6 animate-in fade-in duration-300">
            <Card className="bg-[#111827] border border-gray-800">
              <CardHeader className="pb-4 pt-5 px-5">
                <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                  <Radio className="h-5 w-5 text-green-400 animate-pulse" /> LIVE THREAT MONITORING
                  <Badge variant="outline" className="text-[10px] border-green-500/30 text-green-400">LIVE FEED</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="px-5 pb-5">
                <div className="flex items-center gap-2 mb-4">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  <span className="text-xs text-gray-400 font-mono">LIVE FEED ACTIVE</span>
                  <Button variant="ghost" size="sm" onClick={loadInitialData} className="ml-auto text-gray-400 hover:text-white">
                    <RefreshCw className="h-4 w-4 mr-2" />Refresh
                  </Button>
                </div>
                
                <div className="space-y-2 max-h-[500px] overflow-y-auto">
                  {threatData?.iocs?.slice(0, 20).map((ioc: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-3 bg-[#0a0e17] rounded border border-gray-800/50 text-xs font-mono hover:border-gray-700">
                      <div className="flex items-center gap-3">
                        <Badge variant="outline" className="text-[10px] border-gray-700 text-gray-500 w-16 justify-center">{ioc.type.toUpperCase()}</Badge>
                        <code className="text-gray-300">{ioc.value}</code>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={`text-[10px] ${
                          ioc.threatLevel === 'Critical' ? 'bg-red-500/20 text-red-400' :
                          ioc.threatLevel === 'High' ? 'bg-orange-500/20 text-orange-400' :
                          'bg-gray-800 text-gray-400'
                        }`}>{ioc.threatLevel}</Badge>
                        <span className="text-gray-500 text-[10px]">{ioc.source}</span>
                      </div>
                    </div>
                  )) || <div className="text-center py-8 text-gray-500">Loading feed...</div>}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

        </Tabs>
      </main>

      {/* FOOTER */}
      <footer className="border-t border-gray-800 mt-8 py-4 bg-[#080c12]">
        <div className="max-w-[1920px] mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between text-[10px] text-gray-600 font-mono">
            <span>NEXUS INTEL v4.0 • OSINT Platform</span>
            <span>Data Sources: ip-api.com • NIST NVD v2.0 • Google DNS • MalwareBazaar</span>
            <span>Status: ALL SYSTEMS OPERATIONAL ✅</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
