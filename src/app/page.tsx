'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Shield, Search, Globe, Lock, AlertTriangle, CheckCircle2, 
  XCircle, Activity, Radar, FileText, Download, Eye, Copy,
  MapPin, Server, Fingerprint, Bug, Link, Hash, Target,
  TrendingUp, Clock, Zap, Database, Cpu,
  Network, Terminal, BarChart3, Bell, RefreshCw,
  Globe2, UserCheck, Users, ExternalLink, ChevronDown, ChevronUp
} from 'lucide-react';

// ============= TYPES =============
interface IPResult {
  query: string;
  geolocation: {
    country: string; countryCode: string; region: string;
    city: string; latitude: number; longitude: number;
  };
  network: {
    isp: string; org: string; asn: string;
    isMobile: boolean; isProxy: boolean; isHosting: boolean;
  };
  threat: {
    score: number; level: string; color: string;
    icon?: string; indicators: string[]; recommendations: string[];
  };
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
  analysis: any;
  overallAssessment: {
    threatScore: number; riskLevel: string; riskColor: string;
    riskIcon?: string; indicators: string[]; recommendations: string[]; verdict: string;
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

// ============= MAIN COMPONENT =============
export default function NexusIntelDashboard() {
  // State Management
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // IP Intel State
  const [ipInput, setIpInput] = useState('');
  const [ipResult, setIpResult] = useState<IPResult | null>(null);
  
  // Domain State
  const [domainInput, setDomainInput] = useState('');
  const [domainResult, setDomainResult] = useState<DomainResult | null>(null);
  
  // CVE State
  const [cveInput, setCveInput] = useState('');
  const [cveResults, setCveResults] = useState<CVEResult[]>([]);
  
  // URL State
  const [urlInput, setUrlInput] = useState('');
  const [urlResult, setUrlResult] = useState<URLResult | null>(null);
  
  // Hash State
  const [hashInput, setHashInput] = useState('');
  const [hashResult, setHashResult] = useState<HashResult | null>(null);
  
  // Threat Intel State
  const [threatData, setThreatData] = useState<ThreatData | null>(null);
  
  // Report State
  const [reportData, setReportData] = useState<any>(null);

  // ============= API FUNCTIONS =============
  const fetchThreatIntelligence = useCallback(async () => {
    try {
      setError(null);
      const res = await fetch('/api/osint/threats');
      const data = await res.json();
      if (data.success) setThreatData(data.data);
      else throw new Error(data.error || 'Error fetching threats');
    } catch (err: any) {
      console.error('Threat intel error:', err);
      setError(`Error cargando inteligencia: ${err.message}`);
    }
  }, []);

  // Initialize on mount
  useEffect(() => {
    fetchThreatIntelligence();
  }, [fetchThreatIntelligence]);

  // IP Analysis
  const analyzeIP = async () => {
    if (!ipInput) return;
    setIsLoading(true); setError(null);
    
    try {
      const res = await fetch('/api/osint/ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ipInput.trim() })
      });
      const data = await res.json();
      
      if (data.success) setIpResult(data.data);
      else throw new Error(data.error || 'Error analyzing IP');
    } catch (err: any) {
      setError(err.message || 'Error al analizar IP');
      setIpResult(null);
    }
    setIsLoading(false);
  };

  // Domain Analysis
  const analyzeDomain = async () => {
    if (!domainInput) return;
    setIsLoading(true); setError(null);
    
    try {
      const res = await fetch('/api/osint/domain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domainInput.trim() })
      });
      const data = await res.json();
      
      if (data.success) setDomainResult(data.data);
      else throw new Error(data.error || 'Error analyzing domain');
    } catch (err: any) {
      setError(err.message || 'Error al analizar dominio');
      setDomainResult(null);
    }
    setIsLoading(false);
  };

  // CVE Search
  const searchCVE = async () => {
    if (!cveInput) return;
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
      } else throw new Error(data.error || 'Error searching CVE');
    } catch (err: any) {
      setError(err.message || 'Error al buscar CVE');
      setCveResults([]);
    }
    setIsLoading(false);
  };

  // URL Analysis
  const analyzeURL = async () => {
    if (!urlInput) return;
    setIsLoading(true); setError(null);
    
    try {
      const res = await fetch('/api/osint/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput.trim() })
      });
      const data = await res.json();
      
      if (data.success) setUrlResult(data.data);
      else throw new Error(data.error || 'Error analyzing URL');
    } catch (err: any) {
      setError(err.message || 'Error al analizar URL');
      setUrlResult(null);
    }
    setIsLoading(false);
  };

  // Hash Lookup
  const analyzeHash = async () => {
    if (!hashInput) return;
    setIsLoading(true); setError(null);
    
    try {
      const res = await fetch('/api/osint/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: hashInput.trim() })
      });
      const data = await res.json();
      
      if (data.success) setHashResult(data.data);
      else throw new Error(data.error || 'Error looking up hash');
    } catch (err: any) {
      setError(err.message || 'Error al buscar hash');
      setHashResult(null);
    }
    setIsLoading(false);
  };

  // Report Generation
  const generateReport = async (type: string) => {
    setIsLoading(true); setError(null);
    
    try {
      const res = await fetch('/api/osint/reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reportType: type,
          data: threatData || {},
          options: { classification: 'CONFIDENTIAL' }
        })
      });
      const data = await res.json();
      
      if (data.success) setReportData(data.data.report);
      else throw new Error(data.error || 'Error generating report');
    } catch (err: any) {
      setError(err.message || 'Error al generar informe');
    }
    setIsLoading(false);
  };

  // Helper: Get threat color
  const getThreatColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'critical':
      case 'crítico':
      case 'peligroso':
      case 'malicious':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high':
      case 'alto':
      case 'alto riesgo':
      case 'suspicious':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium':
      case 'medio':
      case 'sospechoso':
      case 'cautela':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-green-500/20 text-green-400 border-green-500/30';
    }
  };

  // ============= RENDER =============
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black text-white">
      {/* Header */}
      <header className="border-b border-white/10 backdrop-blur-xl bg-black/40 sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600">
                <Shield className="h-6 w-6" />
              </div>
              <div>
                <h1 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                  NEXUS INTEL
                </h1>
                <p className="text-xs text-gray-500">OSINT Threat Intelligence Platform</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {threatData?.globalThreatLevel && (
                <Badge variant="outline" className={`${getThreatColor(threatData.globalThreatLevel.level)} px-3 py-1`}>
                  <Activity className="h-3 w-3 mr-1" />
                  Amenaza: {threatData.globalThreatLevel.level} ({threatData.globalThreatLevel.score})
                </Badge>
              )}
              <Button variant="ghost" size="sm" onClick={fetchThreatIntelligence} disabled={isLoading}>
                <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-6">
        {/* Error Display */}
        {error && (
          <Card className="mb-6 border-red-500/30 bg-red-950/20">
            <CardContent className="py-3 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-400" />
              <span className="text-red-300">{error}</span>
              <Button variant="ghost" size="sm" className="ml-auto" onClick={() => setError(null)}>
                ✕
              </Button>
            </CardContent>
          </Card>
        )}

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid grid-cols-5 lg:grid-cols-10 gap-1 bg-gray-900/80 p-1 h-auto">
            <TabsTrigger value="dashboard" className="text-xs py-2 data-[state=active]:bg-cyan-600">
              <Radar className="h-3 w-3 mr-1" /> Dashboard
            </TabsTrigger>
            <TabsTrigger value="ip" className="text-xs py-2 data-[state=active]:bg-cyan-600">
              <Globe2 className="h-3 w-3 mr-1" /> IP
            </TabsTrigger>
            <TabsTrigger value="domain" className="text-xs py-2 data-[state=active]:bg-cyan-600">
              <Globe className="h-3 w-3 mr-1" /> Dominio
            </TabsTrigger>
            <TabsTrigger value="cve" className="text-xs py-2 data-[state=active]:bg-cyan-600">
              <Bug className="h-3 w-3 mr-1" /> CVE
            </TabsTrigger>
            <TabsTrigger value="url" className="text-xs py-2 data-[state=active]:bg-cyan-600">
              <Link className="h-3 w-3 mr-1" /> URL
            </TabsTrigger>
            <TabsTrigger value="hash" className="text-xs py-2 data-[state=active]:bg-cyan-600">
              <Fingerprint className="h-3 w-3 mr-1" /> Hash
            </TabsTrigger>
            <TabsTrigger value="threats" className="text-xs py-2 data-[state=active]:bg-cyan-600">
              <Target className="h-3 w-3 mr-1" /> Amenazas
            </TabsTrigger>
            <TabsTrigger value="reports" className="text-xs py-2 data-[state=active]:bg-cyan-600">
              <FileText className="h-3 w-3 mr-1" /> Informes
            </TabsTrigger>
            <TabsTrigger value="monitoring" className="text-xs py-2 data-[state=active]:bg-cyan-600 hidden lg:flex">
              <Activity className="h-3 w-3 mr-1" /> Monitor
            </TabsTrigger>
            <TabsTrigger value="darkweb" className="text-xs py-2 data-[state=active]:bg-cyan-600 hidden lg:flex">
              <Eye className="h-3 w-3 mr-1" /> DarkWeb
            </TabsTrigger>
          </TabsList>

          {/* ==================== DASHBOARD TAB ==================== */}
          <TabsContent value="dashboard" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Global Threat Level */}
              <Card className="bg-gray-900/60 border-white/10">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium text-gray-400">Nivel de Amenaza Global</CardTitle>
                </CardHeader>
                <CardContent>
                  {threatData?.globalThreatLevel ? (
                    <div className="flex items-center gap-3">
                      <div className={`w-12 h-12 rounded-full flex items-center justify-center text-lg font-bold ${getThreatColor(threatData.globalThreatLevel.level)}`}>
                        {threatData.globalThreatLevel.score}
                      </div>
                      <div>
                        <p className={`font-semibold ${threatData.globalThreatLevel.color === '#dc2626' ? 'text-red-400' : threatData.globalThreatLevel.color === '#f97316' ? 'text-orange-400' : 'text-yellow-400'}`}>
                          {threatData.globalThreatLevel.level}
                        </p>
                        <p className="text-xs text-gray-500">de 100</p>
                      </div>
                    </div>
                  ) : (
                    <div className="animate-pulse space-y-2">
                      <div className="h-10 bg-gray-800 rounded"></div>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Active IOCs */}
              <Card className="bg-gray-900/60 border-white/10">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium text-gray-400">IOCs Activos</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-bold text-cyan-400">
                    {threatData?.iocs?.length || 0}
                  </div>
                  <p className="text-xs text-gray-500">Indicadores monitoreados</p>
                </CardContent>
              </Card>

              {/* Recent Vulnerabilities */}
              <Card className="bg-gray-900/60 border-white/10">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium text-gray-400">Vulnerabilidades Recientes</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-bold text-orange-400">
                    {threatData?.activeThreats?.length || 0}
                  </div>
                  <p className="text-xs text-gray-500">Últimos 24 horas</p>
                </CardContent>
              </Card>

              {/* Active Campaigns */}
              <Card className="bg-gray-900/60 border-white/10">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium text-gray-400">Campañas Activas</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-bold text-red-400">
                    {threatData?.campaigns?.filter((c: any) => c.status === 'ACTIVE').length || 0}
                  </div>
                  <p className="text-xs text-gray-500">Requieren atención</p>
                </CardContent>
              </Card>
            </div>

            {/* Quick Actions */}
            <Card className="bg-gray-900/60 border-white/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5 text-yellow-400" />
                  Análisis Rápido
                </CardTitle>
                <CardDescription>Ingrese un objetivo para comenzar el análisis OSINT</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="space-y-2">
                    <label className="text-xs text-gray-400">Dirección IP</label>
                    <div className="flex gap-2">
                      <Input 
                        placeholder="8.8.8.8" 
                        value={ipInput}
                        onChange={(e) => setIpInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && analyzeIP()}
                        className="bg-gray-800 border-gray-700"
                      />
                      <Button size="sm" onClick={analyzeIP} disabled={isLoading}>
                        <Search className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs text-gray-400">Dominio</label>
                    <div className="flex gap-2">
                      <Input 
                        placeholder="example.com"
                        value={domainInput}
                        onChange={(e) => setDomainInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && analyzeDomain()}
                        className="bg-gray-800 border-gray-700"
                      />
                      <Button size="sm" onClick={analyzeDomain} disabled={isLoading}>
                        <Search className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs text-gray-400">CVE ID</label>
                    <div className="flex gap-2">
                      <Input 
                        placeholder="CVE-2024-1234"
                        value={cveInput}
                        onChange={(e) => setCveInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && searchCVE()}
                        className="bg-gray-800 border-gray-700"
                      />
                      <Button size="sm" onClick={searchCVE} disabled={isLoading}>
                        <Search className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs text-gray-400">URL</label>
                    <div className="flex gap-2">
                      <Input 
                        placeholder="https://..."
                        value={urlInput}
                        onChange={(e) => setUrlInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && analyzeURL()}
                        className="bg-gray-800 border-gray-700"
                      />
                      <Button size="sm" onClick={analyzeURL} disabled={isLoading}>
                        <Search className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </div>

                {/* Quick Results */}
                {(ipResult || domainResult || urlResult || hashResult) && (
                  <div className="mt-4 p-4 rounded-lg bg-gray-800/50 border border-gray-700">
                    <h4 className="text-sm font-medium mb-2">Último Resultado:</h4>
                    
                    {ipResult && (
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          <Globe2 className="h-4 w-4 text-cyan-400" />
                          <span className="font-mono text-sm">{ipResult.query}</span>
                          <Badge className={getThreatColor(ipResult.threat.level)}>
                            {ipResult.threat.icon} {ipResult.threat.level}: {ipResult.threat.score}/100
                          </Badge>
                        </div>
                        <p className="text-xs text-gray-400">
                          📍 {ipResult.geolocation.city}, {ipResult.geolocation.country} | 
                          🏢 {ipResult.network.isp}
                        </p>
                      </div>
                    )}
                    
                    {urlResult && (
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          <Link className="h-4 w-4 text-cyan-400" />
                          <span className="font-mono text-sm truncate max-w-md">{urlResult.url}</span>
                          <Badge className={getThreatColor(urlResult.overallAssessment.riskLevel)}>
                            {urlResult.overallAssessment.riskIcon} {urlResult.overallAssessment.riskLevel}
                          </Badge>
                        </div>
                        <p className="text-xs text-gray-400">{urlResult.overallAssessment.verdict}</p>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Recent Threats Preview */}
            {threatData?.activeThreats && threatData.activeThreats.length > 0 && (
              <Card className="bg-gray-900/60 border-white/10">
                <CardHeader>
                  <CardTitle className="flex items-center justify-between">
                    <span className="flex items-center gap-2">
                      <AlertTriangle className="h-5 w-5 text-orange-400" />
                      Vulnerabilidades Recientes (NVD)
                    </span>
                    <Button variant="ghost" size="sm" onClick={() => setActiveTab('cve')}>
                      Ver todas →
                    </Button>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {threatData.activeThreats.slice(0, 5).map((threat: any, idx: number) => (
                      <div key={idx} className="flex items-center justify-between p-2 rounded bg-gray-800/50 hover:bg-gray-800 transition-colors">
                        <div className="flex items-center gap-3">
                          <Badge variant="outline" className={
                            threat.severity === 'CRITICAL' ? 'border-red-500 text-red-400' :
                            threat.severity === 'HIGH' ? 'border-orange-500 text-orange-400' :
                            'border-yellow-500 text-yellow-400'
                          }>
                            {threat.severity}
                          </Badge>
                          <span className="font-mono text-sm">{threat.id}</span>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-gray-400">
                          {threat.cvssScore && <span>CVSS: {threat.cvssScore}</span>}
                          <span>{new Date(threat.published).toLocaleDateString()}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* ==================== IP INTEL TAB ==================== */}
          <TabsContent value="ip" className="space-y-6">
            <Card className="bg-gray-900/60 border-white/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe2 className="h-5 w-5 text-cyan-400" />
                  Inteligencia de IP
                </CardTitle>
                <CardDescription>Análisis geolocalización y evaluación de amenazas de direcciones IP</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-4">
                  <Input 
                    placeholder="Ingrese dirección IPv4 o IPv6 (ej: 8.8.8.8, 2001:4860:4860::8888)"
                    value={ipInput}
                    onChange={(e) => setIpInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeIP()}
                    className="flex-1 bg-gray-800 border-gray-700"
                  />
                  <Button onClick={analyzeIP} disabled={isLoading || !ipInput}>
                    {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    Analizar IP
                  </Button>
                </div>

                {ipResult && (
                  <div className="mt-6 space-y-4">
                    {/* Threat Score Banner */}
                    <div className={`p-4 rounded-lg border ${getThreatColor(ipResult.threat.level)}`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-semibold text-lg">
                          {ipResult.threat.icon} Nivel de Amenaza: {ipResult.threat.level}
                        </span>
                        <span className="text-2xl font-bold">{ipResult.threat.score}/100</span>
                      </div>
                      <Progress value={ipResult.threat.score} className="h-2 mt-2" />
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Geolocation */}
                      <Card className="bg-gray-800/50 border-gray-700">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm flex items-center gap-2">
                            <MapPin className="h-4 w-4 text-green-400" />
                            Geolocalización
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm">
                          <div className="flex justify-between"><span className="text-gray-400">País:</span><span>{ipResult.geolocation.country} ({ipResult.geolocation.countryCode})</span></div>
                          <div className="flex justify-between"><span className="text-gray-400">Región:</span><span>{ipResult.geolocation.region}</span></div>
                          <div className="flex justify-between"><span className="text-gray-400">Ciudad:</span><span>{ipResult.geolocation.city}</span></div>
                          <div className="flex justify-between"><span className="text-gray-400">Coordenadas:</span><span className="font-mono">{ipResult.geolocation.latitude}, {ipResult.geolocation.longitude}</span></div>
                          <div className="flex justify-between"><span className="text-gray-400">Zona Horaria:</span><span>{ipResult.geolocation.timezone}</span></div>
                        </CardContent>
                      </Card>

                      {/* Network Info */}
                      <Card className="bg-gray-800/50 border-gray-700">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm flex items-center gap-2">
                            <Server className="h-4 w-4 text-blue-400" />
                            Información de Red
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm">
                          <div className="flex justify-between"><span className="text-gray-400">ISP:</span><span>{ipResult.network.isp}</span></div>
                          <div className="flex justify-between"><span className="text-gray-400">Organización:</span><span>{ipResult.network.org}</span></div>
                          <div className="flex justify-between"><span className="text-gray-400">ASN:</span><span className="font-mono">{ipResult.network.asn}</span></div>
                          <Separator />
                          <div className="flex justify-between"><span className="text-gray-400">Proxy/VPN:</span><Badge variant={ipResult.network.isProxy ? "destructive" : "default"}>{ipResult.network.isProxy ? 'Detectado' : 'No'}</Badge></div>
                          <div className="flex justify-between"><span className="text-gray-400">Hosting:</span><Badge variant={ipResult.network.isHosting ? "destructive" : "default"}>{ipResult.network.isHosting ? 'Sí - Data Center' : 'No'}</Badge></div>
                          <div className="flex justify-between"><span className="text-gray-400">Móvil:</span><Badge variant={ipResult.network.isMobile ? "default" : "secondary"}>{ipResult.network.isMobile ? 'Sí' : 'No'}</Badge></div>
                        </CardContent>
                      </Card>
                    </div>

                    {/* Indicators & Recommendations */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card className="bg-gray-800/50 border-gray-700">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm flex items-center gap-2">
                            <AlertTriangle className="h-4 w-4 text-yellow-400" />
                            Indicadores
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-1 text-sm">
                            {ipResult.threat.indicators.map((ind, i) => (
                              <li key={i} className="flex items-start gap-2">
                                <span className="text-yellow-400 mt-0.5">•</span>
                                <span>{ind}</span>
                              </li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>

                      <Card className="bg-gray-800/50 border-gray-700">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm flex items-center gap-2">
                            <CheckCircle2 className="h-4 w-4 text-green-400" />
                            Recomendaciones
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-1 text-sm">
                            {ipResult.threat.recommendations.map((rec, i) => (
                              <li key={i} className="flex items-start gap-2">
                                <span className="text-green-400 mt-0.5">✓</span>
                                <span>{rec}</span>
                              </li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== DOMAIN TAB ==================== */}
          <TabsContent value="domain" className="space-y-6">
            <Card className="bg-gray-900/60 border-white/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5 text-cyan-400" />
                  Análisis de Dominio
                </CardTitle>
                <CardDescription>Evaluación de seguridad y reputación de dominios</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-4">
                  <Input 
                    placeholder="Ingrese dominio (ej: google.com)"
                    value={domainInput}
                    onChange={(e) => setDomainInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeDomain()}
                    className="flex-1 bg-gray-800 border-gray-700"
                  />
                  <Button onClick={analyzeDomain} disabled={isLoading || !domainInput}>
                    {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    Analizar
                  </Button>
                </div>

                {domainResult && (
                  <div className="mt-6 space-y-4">
                    {/* Reputation Score */}
                    <div className={`p-4 rounded-lg border ${getThreatColor(domainResult.reputation.level)}`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-semibold text-lg">Reputación del Dominio</span>
                        <span className="text-2xl font-bold">{domainResult.reputation.score}/100</span>
                      </div>
                      <Badge className={getThreatColor(domainResult.reputation.level)}>
                        {domainResult.reputation.level}
                      </Badge>
                      <Progress value={domainResult.reputation.score} className="h-2 mt-2" />
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* WHOIS Info */}
                      <Card className="bg-gray-800/50 border-gray-700">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Información WHOIS</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm">
                          {domainResult.whois?.error ? (
                            <p className="text-gray-500">{domainResult.whois.error}</p>
                          ) : (
                            <>
                              <div className="flex justify-between"><span className="text-gray-400">Registrador:</span><span>{domainResult.whois.registrar}</span></div>
                              <div className="flex justify-between"><span className="text-gray-400">Creado:</span><span>{domainResult.whois.creationDate}</span></div>
                              <div className="flex justify-between"><span className="text-gray-400">Expira:</span><span>{domainResult.whois.expiryDate}</span></div>
                              <div className="flex justify-between"><span className="text-gray-400">País:</span><span>{domainResult.whois.registrantCountry}</span></div>
                              <div className="flex justify-between"><span className="text-gray-400">Edad (días):</span><span>{domainResult.whois.ageDays}</span></div>
                              <div className="flex justify-between"><span className="text-gray-400">WHOIS Privacy:</span><Badge variant={domainResult.whois.privacyEnabled ? "secondary" : "default"}>{domainResult.whois.privacyEnabled ? 'Activo' : 'Público'}</Badge></div>
                            </>
                          )}
                        </CardContent>
                      </Card>

                      {/* DNS Records */}
                      <Card className="bg-gray-800/50 border-gray-700">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Registros DNS</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm">
                          {domainResult.dns?.error ? (
                            <p className="text-gray-500">{domainResult.dns.error}</p>
                          ) : (
                            <>
                              <div className="flex justify-between"><span className="text-gray-400">Registros A:</span><span className="font-mono text-xs">{domainResult.dns.aRecords?.join(', ') || 'N/A'}</span></div>
                              <div className="flex justify-between"><span className="text-gray-400">MX:</span><span className="font-mono text-xs">{domainResult.dns.mxRecords?.join(', ') || 'N/A'}</span></div>
                              <div className="flex justify-between"><span className="text-gray-400">NS:</span><span className="font-mono text-xs">{domainResult.dns.nsRecords?.join(', ') || 'N/A'}</span></div>
                              <Separator />
                              <div className="flex justify-between"><span className="text-gray-400">SPF:</span><Badge variant={domainResult.dns.hasSPF ? "default" : "destructive"}>{domainResult.dns.hasSPF ? 'Configurado' : 'No configurado'}</Badge></div>
                              <div className="flex justify-between"><span className="text-gray-400">DMARC:</span><Badge variant={domainResult.dns.hasDMARC ? "default" : "destructive"}>{domainResult.dns.hasDMARC ? 'Configurado' : 'No configurado'}</Badge></div>
                            </>
                          )}
                        </CardContent>
                      </Card>
                    </div>

                    {/* Security Assessment */}
                    <Card className="bg-gray-800/50 border-gray-700">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm flex items-center gap-2">
                          <Shield className="h-4 w-4" />
                          Evaluación de Seguridad
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <h4 className="text-xs text-gray-400 mb-2">Indicadores Detectados:</h4>
                            <ul className="space-y-1 text-sm">
                              {domainResult.reputation.indicators.map((ind, i) => (
                                <li key={i}>• {ind}</li>
                              ))}
                            </ul>
                          </div>
                          <div>
                            <h4 className="text-xs text-gray-400 mb-2">Recomendaciones:</h4>
                            <ul className="space-y-1 text-sm">
                              {domainResult.reputation.recommendations.map((rec, i) => (
                                <li key={i}>• {rec}</li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== CVE TAB ==================== */}
          <TabsContent value="cve" className="space-y-6">
            <Card className="bg-gray-900/60 border-white/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bug className="h-5 w-5 text-cyan-400" />
                  Base de Datos de Vulnerabilidades (NIST NVD)
                </CardTitle>
                <CardDescription>Búsqueda de CVEs en la base de datos nacional de vulnerabilidades</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-4">
                  <Input 
                    placeholder="CVE-ID (ej: CVE-2024-1234) o palabra clave (ej: sql injection)"
                    value={cveInput}
                    onChange={(e) => setCveInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && searchCVE()}
                    className="flex-1 bg-gray-800 border-gray-700"
                  />
                  <Button onClick={searchCVE} disabled={isLoading || !cveInput}>
                    {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    Buscar CVE
                  </Button>
                </div>

                {cveResults.length > 0 && (
                  <div className="mt-6 space-y-4">
                    {/* Stats Summary */}
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                      {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map(sev => {
                        const count = cveResults.filter(c => c.cvss.severity === sev).length;
                        return (
                          <div key={sev} className={`p-3 rounded-lg text-center ${getThreatColor(sev)}`}>
                            <div className="text-2xl font-bold">{count}</div>
                            <div className="text-xs">{sev}</div>
                          </div>
                        );
                      })}
                    </div>

                    {/* Results List */}
                    <div className="space-y-3">
                      {cveResults.map((cve, idx) => (
                        <Card key={idx} className="bg-gray-800/50 border-gray-700 hover:border-gray-600 transition-colors">
                          <CardHeader className="pb-2">
                            <div className="flex items-center justify-between">
                              <CardTitle className="font-mono text-base flex items-center gap-2">
                                <ExternalLink className="h-4 w-4 text-cyan-400 cursor-pointer" onClick={() => window.open(`https://nvd.nist.gov/vuln/detail/${cve.id}`, '_blank')} />
                                {cve.id}
                              </CardTitle>
                              <Badge className={getThreatColor(cve.cvss.severity)}>
                                {cve.cvss.severity}
                              </Badge>
                            </div>
                          </CardHeader>
                          <CardContent className="space-y-3">
                            <p className="text-sm text-gray-300">{cve.descriptions}</p>
                            
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                              <div className="bg-gray-900/50 p-2 rounded">
                                <span className="text-gray-500 text-xs">CVSS v{cve.cvss.version}</span>
                                <p className="font-bold text-lg">{cve.cvss.score || 'N/A'}</p>
                              </div>
                              <div className="bg-gray-900/50 p-2 rounded">
                                <span className="text-gray-500 text-xs">Vector</span>
                                <p className="font-mono text-xs truncate">{cve.cvss.vector || 'N/A'}</p>
                              </div>
                              <div className="bg-gray-900/50 p-2 rounded">
                                <span className="text-gray-500 text-xs">Estado</span>
                                <p>{cve.status}</p>
                              </div>
                              <div className="bg-gray-900/50 p-2 rounded">
                                <span className="text-gray-500 text-xs">Publicado</span>
                                <p>{new Date(cve.dates.published).toLocaleDateString()}</p>
                              </div>
                            </div>

                            {cve.cwe.length > 0 && (
                              <div>
                                <span className="text-xs text-gray-500">CWE:</span>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {cve.cwe.map((cwe, i) => (
                                    <Badge key={i} variant="outline" className="text-xs">{cwe}</Badge>
                                  ))}
                                </div>
                              </div>
                            )}

                            {cve.references.length > 0 && (
                              <div>
                                <span className="text-xs text-gray-500">Referencias:</span>
                                <div className="flex flex-wrap gap-2 mt-1">
                                  {cve.references.slice(0, 3).map((ref, i) => (
                                    <a key={i} href={ref.url} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:underline flex items-center gap-1">
                                      <ExternalLink className="h-3 w-3" />
                                      {ref.tags[0] || 'Reference'}
                                    </a>
                                  ))}
                                </div>
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== URL TAB ==================== */}
          <TabsContent value="url" className="space-y-6">
            <Card className="bg-gray-900/60 border-white/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Link className="h-5 w-5 text-cyan-400" />
                  Analizador de Seguridad URL
                </CardTitle>
                <CardDescription>Detección de phishing, malware y URLs maliciosas</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-4">
                  <Input 
                    placeholder="https://ejemplo.com/pagina"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeURL()}
                    className="flex-1 bg-gray-800 border-gray-700"
                  />
                  <Button onClick={analyzeURL} disabled={isLoading || !urlInput}>
                    {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    Analizar URL
                  </Button>
                </div>

                {urlResult && (
                  <div className="mt-6 space-y-4">
                    {/* Overall Assessment */}
                    <div className={`p-4 rounded-lg border ${getThreatColor(urlResult.overallAssessment.riskLevel)}`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-semibold text-lg">
                          {urlResult.overallAssessment.riskIcon} {urlResult.overallAssessment.riskLevel}
                        </span>
                        <span className="text-2xl font-bold">{urlResult.overallAssessment.threatScore}/100</span>
                      </div>
                      <Progress value={urlResult.overallAssessment.threatScore} className="h-2 mt-2" />
                      <p className="mt-2 text-sm">{urlResult.overallAssessment.verdict}</p>
                    </div>

                    {/* Parsed URL */}
                    <Card className="bg-gray-800/50 border-gray-700">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm">URL Desglosada</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm font-mono">
                          <div className="bg-gray-900/50 p-2 rounded">
                            <span className="text-gray-500 text-xs block">Protocolo</span>
                            {urlResult.parsedUrl.protocol}
                          </div>
                          <div className="bg-gray-900/50 p-2 rounded">
                            <span className="text-gray-500 text-xs block">Host</span>
                            <span className="truncate block">{urlResult.parsedUrl.hostname}</span>
                          </div>
                          <div className="bg-gray-900/50 p-2 rounded">
                            <span className="text-gray-500 text-xs block">Puerto</span>
                            {urlResult.parsedUrl.port}
                          </div>
                          <div className="bg-gray-900/50 p-2 rounded">
                            <span className="text-gray-500 text-xs block">Path</span>
                            <span className="truncate block">{urlResult.parsedUrl.path || '/'}</span>
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    {/* Indicators and Recommendations */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card className="bg-gray-800/50 border-gray-700">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm text-red-400">⚠️ Indicadores de Riesgo</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-1 text-sm">
                            {urlResult.overallAssessment.indicators.map((ind, i) => (
                              <li key={i}>{ind}</li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>

                      <Card className="bg-gray-800/50 border-gray-700">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm text-green-400">✓ Recomendaciones</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-1 text-sm">
                            {urlResult.overallAssessment.recommendations.map((rec, i) => (
                              <li key={i}>{rec}</li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== HASH TAB ==================== */}
          <TabsContent value="hash" className="space-y-6">
            <Card className="bg-gray-900/60 border-white/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Fingerprint className="h-5 w-5 text-cyan-400" />
                  Búsqueda de Hash Malicioso
                </CardTitle>
                <CardDescription>Búsqueda multi-engine de hashes MD5, SHA1, SHA256</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-4">
                  <Input 
                    placeholder="MD5, SHA1, SHA256 hash..."
                    value={hashInput}
                    onChange={(e) => setHashInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeHash()}
                    className="flex-1 bg-gray-800 border-gray-700 font-mono"
                  />
                  <Button onClick={analyzeHash} disabled={isLoading || !hashInput}>
                    {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    Buscar Hash
                  </Button>
                </div>

                {hashResult && (
                  <div className="mt-6 space-y-4">
                    {/* Detection Summary */}
                    <div className={`p-4 rounded-lg border ${getThreatColor(hashResult.aggregateResults.threatLevel)}`}>
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm text-gray-400">Tipo: {hashResult.input.hashType.toUpperCase()}</p>
                          <p className="font-semibold text-lg mt-1">
                            {hashResult.found ? hashResult.aggregateResults.classification : 'No encontrado'}
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="text-sm text-gray-400">Detección</p>
                          <p className="text-3xl font-bold">{hashResult.aggregateResults.detectionRate}%</p>
                        </div>
                      </div>
                      <Progress value={hashResult.aggregateResults.detectionRate} className="h-2 mt-3" />
                    </div>

                    {/* Engine Results */}
                    {hashResult.engineResults.length > 0 && (
                      <Card className="bg-gray-800/50 border-gray-700">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Resultados por Motor ({hashResult.engineResults.length} escaneados)</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ScrollArea className="h-64">
                            <div className="space-y-1">
                              {hashResult.engineResults.map((engine: any, idx: number) => (
                                <div key={idx} className={`flex items-center justify-between p-2 rounded text-sm ${engine.result !== 'Clean' ? 'bg-red-950/30' : 'bg-gray-900/50'}`}>
                                  <span className="font-medium">{engine.engine}</span>
                                  <Badge variant={engine.result !== 'Clean' ? "destructive" : "secondary"}>
                                    {engine.result}
                                  </Badge>
                                </div>
                              ))}
                            </div>
                          </ScrollArea>
                        </CardContent>
                      </Card>
                    )}

                    {/* File Details */}
                    {hashResult.details && (
                      <Card className="bg-gray-800/50 border-gray-700">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Detalles del Archivo</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm">
                          {hashResult.details.name && <div className="flex justify-between"><span className="text-gray-400">Nombre:</span><span>{hashResult.details.name}</span></div>}
                          {hashResult.details.type && <div className="flex justify-between"><span className="text-gray-400">Tipo:</span><span>{hashResult.details.type}</span></div>}
                          {hashResult.details.description && <div className="mt-2 p-2 bg-gray-900/50 rounded">{hashResult.details.description}</div>}
                        </CardContent>
                      </Card>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== THREATS TAB ==================== */}
          <TabsContent value="threats" className="space-y-6">
            {/* Global Threat Level */}
            {threatData?.globalThreatLevel && (
              <Card className={`bg-gray-900/60 border-2 ${getThreatColor(threatData.globalThreatLevel.level)}`}>
                <CardContent className="py-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-lg font-semibold">Nivel de Amenaza Global Actual</h3>
                      <p className="text-sm text-gray-400 mt-1">
                        Última actualización: {new Date(threatData.globalThreatLevel.timestamp).toLocaleString('es-ES')}
                      </p>
                    </div>
                    <div className="text-right">
                      <div className={`text-5xl font-bold ${threatData.globalThreatLevel.color === '#dc2626' ? 'text-red-400' : threatData.globalThreatLevel.color === '#f97316' ? 'text-orange-400' : 'text-yellow-400'}`}>
                        {threatData.globalThreatLevel.score}
                      </div>
                      <Badge className={`mt-2 ${getThreatColor(threatData.globalThreatLevel.level)}`} style={{ fontSize: '1rem', padding: '0.5rem 1rem' }}>
                        {threatData.globalThreatLevel.level}
                      </Badge>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
                    <div className="text-center p-3 bg-black/20 rounded">
                      <p className="text-2xl font-bold text-red-400">{threatData.globalThreatLevel.factors.criticalVulnerabilities24h}</p>
                      <p className="text-xs text-gray-400">CVEs Críticos (24h)</p>
                    </div>
                    <div className="text-center p-3 bg-black/20 rounded">
                      <p className="text-2xl font-bold text-orange-400">{threatData.globalThreatLevel.factors.highSeverityVulnerabilities24h}</p>
                      <p className="text-xs text-gray-400">CVEs Altos (24h)</p>
                    </div>
                    <div className="text-center p-3 bg-black/20 rounded">
                      <p className="text-2xl font-bold text-purple-400">{threatData.globalThreatLevel.factors.activeCampaigns}</p>
                      <p className="text-xs text-gray-400">Campañas Activas</p>
                    </div>
                    <div className="text-center p-3 bg-black/20 rounded">
                      <p className="text-2xl font-bold text-cyan-400">{threatData.globalThreatLevel.factors.monitoredIOCs}</p>
                      <p className="text-xs text-gray-400">IOCs Monitoreados</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* APT Groups */}
            {threatData?.aptGroups && (
              <Card className="bg-gray-900/60 border-white/10">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Users className="h-5 w-5 text-red-400" />
                    Grupos APT Monitoreados
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {threatData.aptGroups.map((apt: any, idx: number) => (
                      <Card key={idx} className={`bg-gray-800/50 border ${apt.status === 'ACTIVE' ? 'border-red-500/30' : 'border-gray-700'}`}>
                        <CardHeader className="pb-2">
                          <div className="flex items-center justify-between">
                            <CardTitle className="text-base">{apt.name}</CardTitle>
                            <Badge variant={apt.status === 'ACTIVE' ? "destructive" : "secondary"}>
                              {apt.status}
                            </Badge>
                          </div>
                          <CardDescription>{apt.country} • Confianza: {apt.attributionConfidence}</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm">
                          <p>{apt.description}</p>
                          <div>
                            <span className="text-gray-500 text-xs">Objetivos:</span>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {apt.primaryTargets.map((t: string, i: number) => (
                                <Badge key={i} variant="outline" className="text-xs">{t}</Badge>
                              ))}
                            </div>
                          </div>
                          <div>
                            <span className="text-gray-500 text-xs">Técnicas:</span>
                            <p className="text-xs mt-1">{apt.techniques.join(', ')}</p>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Active Campaigns */}
            {threatData?.campaigns && (
              <Card className="bg-gray-900/60 border-white/10">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Target className="h-5 w-5 text-orange-400" />
                    Campañas de Amenazas Activas
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {threatData.campaigns.map((campaign: any, idx: number) => (
                      <Card key={idx} className={`bg-gray-800/50 border-l-4 ${
                        campaign.status === 'ACTIVE' ? 'border-l-red-500' : 'border-l-yellow-500'
                      }`}>
                        <CardHeader className="pb-2">
                          <div className="flex items-center justify-between">
                            <CardTitle className="text-base flex items-center gap-2">
                              {campaign.name}
                              <Badge className={getThreatColor(campaign.severity)}>{campaign.severity}</Badge>
                            </CardTitle>
                            <Badge variant={campaign.status === 'ACTIVE' ? "destructive" : "secondary"}>
                              {campaign.status}
                            </Badge>
                          </div>
                          <CardDescription>{campaign.description}</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
                            <div><span className="text-gray-500">ID:</span> <code>{campaign.id}</code></div>
                            <div><span className="text-gray-500">IOCs:</span> {campaign.indicators}</div>
                            <div><span className="text-gray-500">Sector:</span> {campaign.targetSectors.join(', ')}</div>
                            <div><span className="text-gray-500">MITRE:</span> {campaign.mitreTechniques.join(', ')}</div>
                          </div>
                          
                          <div>
                            <span className="text-sm text-gray-400">Recomendaciones:</span>
                            <ul className="mt-1 space-y-1 text-sm">
                              {campaign.recommendations.slice(0, 3).map((rec: string, i: number) => (
                                <li key={i} className="flex items-start gap-2">
                                  <ChevronRight className="h-4 w-4 text-cyan-400 mt-0.5 shrink-0" />
                                  {rec}
                                </li>
                              ))}
                            </ul>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* ==================== REPORTS TAB ==================== */}
          <TabsContent value="reports" className="space-y-6">
            <Card className="bg-gray-900/60 border-white/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileText className="h-5 w-5 text-cyan-400" />
                  Generador de Informes Ejecutivos
                </CardTitle>
                <CardDescription>Genere informes profesionales de inteligencia OSINT</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  <Button 
                    variant="outline" 
                    className="h-auto py-4 flex-col gap-2 border-gray-700 hover:bg-gray-800"
                    onClick={() => generateReport('threat-summary')}
                    disabled={isLoading}
                  >
                    <BarChart3 className="h-8 w-8 text-cyan-400" />
                    <span>Resumen de Amenazas</span>
                    <span className="text-xs text-gray-500">Informe ejecutivo global</span>
                  </Button>
                  
                  <Button 
                    variant="outline" 
                    className="h-auto py-4 flex-col gap-2 border-gray-700 hover:bg-gray-800"
                    onClick={() => generateReport('full-assessment')}
                    disabled={isLoading}
                  >
                    <Shield className="h-8 w-8 text-orange-400" />
                    <span>Evaluación Completa</span>
                    <span className="text-xs text-gray-500">Análisis integral OSINT</span>
                  </Button>
                  
                  <Button 
                    variant="outline" 
                    className="h-auto py-4 flex-col gap-2 border-gray-700 hover:bg-gray-800"
                    onClick={() => generateReport('ioc-report')}
                    disabled={isLoading}
                  >
                    <Database className="h-8 w-8 text-red-400" />
                    <span>Informe de IOCs</span>
                    <span className="text-xs text-gray-500">Indicadores de compromiso</span>
                  </Button>
                </div>

                {reportData && (
                  <div className="mt-6 space-y-4">
                    <Card className="bg-gradient-to-br from-gray-800 to-gray-900 border-cyan-500/30">
                      <CardHeader>
                        <CardTitle className="flex items-center justify-between">
                          <span>{reportData.title}</span>
                          <Button variant="outline" size="sm" onClick={() => {
                            const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = `nexus-intel-report-${Date.now()}.json`;
                            a.click();
                          }}>
                            <Download className="h-4 w-4 mr-1" />
                            Descargar
                          </Button>
                        </CardTitle>
                        <CardDescription>{reportData.subtitle}</CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        {/* Executive Summary */}
                        {reportData.executiveSummary && (
                          <div className="p-4 bg-black/30 rounded-lg">
                            <h4 className="font-semibold mb-2 flex items-center gap-2">
                              <Zap className="h-4 w-4 text-yellow-400" />
                              Resumen Ejecutivo
                            </h4>
                            <p className="text-sm text-gray-300 leading-relaxed">
                              {reportData.executiveSummary.content}
                            </p>
                            
                            {reportData.executiveSummary.keyFindings && (
                              <div className="mt-3">
                                <span className="text-xs text-gray-500">Hallazgos Clave:</span>
                                <ul className="mt-1 space-y-1 text-sm">
                                  {reportData.executiveSummary.keyFindings.map((finding: string, i: number) => (
                                    <li key={i} className="flex items-start gap-2">
                                      <CheckCircle2 className="h-4 w-4 text-green-400 mt-0.5 shrink-0" />
                                      {finding}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                            
                            {reportData.executiveSummary.recommendations && (
                              <div className="mt-3">
                                <span className="text-xs text-gray-500">Recomendaciones:</span>
                                <ul className="mt-1 space-y-1 text-sm">
                                  {reportData.executiveSummary.recommendations.map((rec: string, i: number) => (
                                    <li key={i} className="flex items-start gap-2">
                                      <Bell className="h-4 w-4 text-orange-400 mt-0.5 shrink-0" />
                                      {rec}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        )}

                        {/* Sections would be rendered here based on type */}
                        <div className="text-xs text-gray-500 text-center pt-4 border-t border-gray-700">
                          Clasificación: {reportData.metadata?.classification || 'CONFIDENTIAL'} | 
                          Generado: {new Date(reportData.metadata?.generatedAt).toLocaleString('es-ES')}
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== MONITORING TAB ==================== */}
          <TabsContent value="monitoring" className="space-y-6">
            <Card className="bg-gray-900/60 border-white/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5 text-cyan-400" />
                  Monitoreo en Tiempo Real
                </CardTitle>
                <CardDescription>Panel de actividad y alertas de seguridad</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-4 bg-green-950/20 border border-green-500/20 rounded-lg">
                    <div className="flex items-center gap-2 text-green-400">
                      <CheckCircle2 className="h-5 w-5" />
                      <span className="font-medium">Sistemas Operativos</span>
                    </div>
                    <p className="text-2xl font-bold mt-2">98.7%</p>
                    <p className="text-xs text-gray-500">Uptime últimos 30 días</p>
                  </div>
                  
                  <div className="p-4 bg-blue-950/20 border border-blue-500/20 rounded-lg">
                    <div className="flex items-center gap-2 text-blue-400">
                      <Network className="h-5 w-5" />
                      <span className="font-medium">APIs Conectadas</span>
                    </div>
                    <p className="text-2xl font-bold mt-2">7/7</p>
                    <p className="text-xs text-gray-500">Servicios activos</p>
                  </div>
                  
                  <div className="p-4 bg-yellow-950/20 border border-yellow-500/20 rounded-lg">
                    <div className="flex items-center gap-2 text-yellow-400">
                      <Clock className="h-5 w-5" />
                      <span className="font-medium">Última Sincronización</span>
                    </div>
                    <p className="text-2xl font-bold mt-2">Hace 2 min</p>
                    <p className="text-xs text-gray-500">Feed de amenazas</p>
                  </div>
                </div>

                {/* Activity Log */}
                <Card className="bg-gray-800/50 border-gray-700">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Registro de Actividad Reciente</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-64">
                      <div className="space-y-2 font-mono text-xs">
                        {[
                          { time: '14:32:15', type: 'info', msg: '[THREAT-FEED] Sincronización completada - 47 nuevos IOCs' },
                          { time: '14:31:02', type: 'warning', msg: '[ALERT] Detección de patrón de phishing relacionado con Microsoft 365' },
                          { time: '14:28:45', type: 'info', msg: '[NVD] Actualización de base de datos - 23 nuevas CVEs' },
                          { time: '14:25:11', type: 'success', msg: '[SCAN] Análisis IP completado - 8.8.8.8 clasificado como SEGURO' },
                          { time: '14:22:33', type: 'warning', msg: '[IOC] Nuevo indicador agregado - Dominio sospechoso detectado' },
                          { time: '14:18:07', type: 'info', msg: '[SYSTEM] Cache actualizado correctamente' },
                          { time: '14:15:44', type: 'error', msg: '[ERROR] Timeout en consulta DNS para ejemplo.com' },
                          { time: '14:12:29', type: 'success', msg: '[REPORT] Informe ejecutivo generado exitosamente' },
                        ].map((log, i) => (
                          <div key={i} className={`p-2 rounded ${
                            log.type === 'error' ? 'bg-red-950/20 text-red-400' :
                            log.type === 'warning' ? 'bg-yellow-950/20 text-yellow-400' :
                            log.type === 'success' ? 'bg-green-950/20 text-green-400' :
                            'bg-gray-900/50 text-gray-400'
                          }`}>
                            <span className="text-gray-500">[{log.time}]</span> {log.msg}
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== DARK WEB TAB ==================== */}
          <TabsContent value="darkweb" className="space-y-6">
            <Card className="bg-gray-900/60 border-white/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Eye className="h-5 w-5 text-purple-400" />
                  Monitor Dark Web / OSINT Avanzado
                </CardTitle>
                <CardDescription>Herramientas de inteligencia de fuentes abiertas avanzadas</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Card className="bg-gray-800/50 border-purple-500/20">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Terminal className="h-4 w-4 text-purple-400" />
                        Data Leak Monitoring
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="text-sm text-gray-400">
                      <p>Monitoreo de filtraciones de datos en foros y marketplaces del dark web.</p>
                      <Badge variant="outline" className="mt-2 text-purple-400">Próximamente</Badge>
                    </CardContent>
                  </Card>
                  
                  <Card className="bg-gray-800/50 border-purple-500/20">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <UserCheck className="h-4 w-4 text-purple-400" />
                        Credential Intelligence
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="text-sm text-gray-400">
                      <p>Detección de credenciales expuestas en brechas de datos.</p>
                      <Badge variant="outline" className="mt-2 text-purple-400">Próximamente</Badge>
                    </CardContent>
                  </Card>
                  
                  <Card className="bg-gray-800/50 border-purple-500/20">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <TrendingUp className="h-4 w-4 text-purple-400" />
                        Threat Actor Tracking
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="text-sm text-gray-400">
                      <p>Seguimiento de actores de amenazas y sus actividades.</p>
                      <Badge variant="outline" className="mt-2 text-purple-400">Próximamente</Badge>
                    </CardContent>
                  </Card>
                  
                  <Card className="bg-gray-800/50 border-purple-500/20">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Cpu className="h-4 w-4 text-purple-400" />
                        Ransomware Tracker
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="text-sm text-gray-400">
                      <p>Monitoreo de sitios de ransomware y víctimas.</p>
                      <Badge variant="outline" className="mt-2 text-purple-400">Próximamente</Badge>
                    </CardContent>
                  </Card>
                </div>

                <div className="p-4 bg-purple-950/10 border border-purple-500/20 rounded-lg">
                  <p className="text-sm text-purple-300">
                    <strong>Módulo en desarrollo:</strong> Estas funcionalidades requieren acceso especializado 
                    a fuentes del dark web y APIs de threat intelligence premium. La versión actual incluye 
                    monitoreo de amenazas convencionales mediante fuentes públicas (NVD, ip-api.com, etc.).
                  </p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/10 mt-12 py-6 text-center text-xs text-gray-500">
        <p>NEXUS INTEL OSINT Platform v2.0 | Datos: NIST NVD, ip-api.com, Threat Intelligence Feeds</p>
        <p className="mt-1">© 2024 | Para uso legítimo de seguridad e investigación únicamente</p>
      </footer>
    </div>
  );
}

// Helper component for chevron right
function ChevronRight({ className }: { className?: string }) {
  return (
    <svg className={className} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="9 18 15 12 9 6"></polyline>
    </svg>
  );
}
