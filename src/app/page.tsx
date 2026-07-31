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
  RefreshCw, ChevronRight, Info
} from 'lucide-react';

// ============= TYPES =============
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
    score: number; level: string; color: string;
    indicators: string[]; recommendations: string[];
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

// ============= MAIN COMPONENT =============
export default function NexusIntelDashboard() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // States
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

  // API Functions
  const fetchThreatIntelligence = useCallback(async () => {
    try {
      setError(null);
      const res = await fetch('/api/osint/threats');
      const data = await res.json();
      if (data.success) setThreatData(data.data);
      else throw new Error(data.error || 'Error fetching threats');
    } catch (err: any) {
      console.error('Threat intel error:', err);
      setError(`Error: ${err.message}`);
    }
  }, []);

  useEffect(() => {
    fetchThreatIntelligence();
  }, [fetchThreatIntelligence]);

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
      setError(err.message); setIpResult(null);
    }
    setIsLoading(false);
  };

  const analyzeDomain = async () => {
    if (!domainInput) return;
    setIsLoading(true); setError(null);
    try {
      const res = await fetch('/api/osint/domain', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domainInput.trim() })
      });
      const data = await res.json();
      if (data.success) setDomainResult(data.data);
      else throw new Error(data.error);
    } catch (err: any) { setError(err.message); setDomainResult(null); }
    setIsLoading(false);
  };

  const searchCVE = async () => {
    if (!cveInput) return;
    setIsLoading(true); setError(null);
    try {
      const isCVEId = cveInput.toUpperCase().startsWith('CVE-');
      const res = await fetch('/api/osint/cve', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(isCVEId ? { cveId: cveInput } : { keyword: cveInput })
      });
      const data = await res.json();
      if (data.success) setCveResults(data.data.results || [data.data]);
      else throw new Error(data.error);
    } catch (err: any) { setError(err.message); setCveResults([]); }
    setIsLoading(false);
  };

  const analyzeURL = async () => {
    if (!urlInput) return;
    setIsLoading(true); setError(null);
    try {
      const res = await fetch('/api/osint/url', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput.trim() })
      });
      const data = await res.json();
      if (data.success) setUrlResult(data.data);
      else throw new Error(data.error);
    } catch (err: any) { setError(err.message); setUrlResult(null); }
    setIsLoading(false);
  };

  const analyzeHash = async () => {
    if (!hashInput) return;
    setIsLoading(true); setError(null);
    try {
      const res = await fetch('/api/osint/hash', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: hashInput.trim() })
      });
      const data = await res.json();
      if (data.success) setHashResult(data.data);
      else throw new Error(data.error);
    } catch (err: any) { setError(err.message); setHashResult(null); }
    setIsLoading(false);
  };

  const generateReport = async (type: string) => {
    setIsLoading(true); setError(null);
    try {
      const res = await fetch('/api/osint/reports', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reportType: type, data: threatData || {}, options: { classification: 'CONFIDENTIAL' } })
      });
      const data = await res.json();
      if (data.success) setReportData(data.data.report);
      else throw new Error(data.error);
    } catch (err: any) { setError(err.message); }
    setIsLoading(false);
  };

  // Professional severity colors (muted, enterprise-style)
  const getSeverityStyle = (level: string) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL':
      case 'CRÍTICO':
      case 'PELIGROSO':
      case 'MALICIOUS':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'HIGH':
      case 'ALTO':
      case 'ALTO RIESGO':
      case 'SUSPICIOUS':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'MEDIUM':
      case 'MEDIO':
      case 'SOSPECHOSO':
      case 'CAUTELA':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      default:
        return 'bg-green-100 text-green-800 border-green-200';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Professional Header */}
      <header className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 bg-gray-900 rounded-lg flex items-center justify-center">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <div>
                <h1 className="text-lg font-semibold text-gray-900">NEXUS INTEL</h1>
                <p className="text-xs text-gray-500">OSINT Threat Intelligence Platform</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {threatData?.globalThreatLevel && (
                <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium border ${getSeverityStyle(threatData.globalThreatLevel.level)}`}>
                  <Activity className="h-3 w-3" />
                  Threat Level: {threatData.globalThreatLevel.level} ({threatData.globalThreatLevel.score})
                </span>
              )}
              <Button variant="ghost" size="sm" onClick={fetchThreatIntelligence} disabled={isLoading}>
                <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Error Banner */}
        {error && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg flex items-start gap-2">
            <AlertTriangle className="h-5 w-5 text-red-600 mt-0.5 shrink-0" />
            <div className="flex-1">
              <p className="text-sm text-red-800">{error}</p>
            </div>
            <Button variant="ghost" size="sm" onClick={() => setError(null)} className="text-red-600 hover:text-red-800">
              <XCircle className="h-4 w-4" />
            </Button>
          </div>
        )}

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="bg-white border border-gray-200 p-1 h-auto grid grid-cols-5 lg:grid-cols-10 gap-1">
            {[
              { value: 'dashboard', label: 'Dashboard', icon: Activity },
              { value: 'ip', label: 'IP Intel', icon: Globe },
              { value: 'domain', label: 'Domain', icon: Globe },
              { value: 'cve', label: 'CVE', icon: Bug },
              { value: 'url', label: 'URL', icon: Link },
              { value: 'hash', label: 'Hash', icon: Fingerprint },
              { value: 'threats', label: 'Threats', icon: Target },
              { value: 'reports', label: 'Reports', icon: FileText },
              { value: 'monitoring', label: 'Monitor', icon: Terminal },
              { value: 'darkweb', label: 'DarkWeb', icon: Eye }
            ].map(tab => (
              <TabsTrigger 
                key={tab.value} 
                value={tab.value} 
                className="text-xs py-2 data-[state=active]:bg-gray-900 data-[state=active]:text-white"
              >
                <tab.icon className="h-3 w-3 mr-1 hidden sm:inline" />
                {tab.label}
              </TabsTrigger>
            ))}
          </TabsList>

          {/* ==================== DASHBOARD ==================== */}
          <TabsContent value="dashboard" className="space-y-6">
            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <Card>
                <CardHeader className="pb-2">
                  <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Global Threat Level</p>
                </CardHeader>
                <CardContent>
                  {threatData?.globalThreatLevel ? (
                    <div className="flex items-baseline gap-2">
                      <span className="text-3xl font-bold text-gray-900">{threatData.globalThreatLevel.score}</span>
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityStyle(threatData.globalThreatLevel.level)}`}>
                        {threatData.globalThreatLevel.level}
                      </span>
                    </div>
                  ) : (
                    <div className="animate-pulse h-10 bg-gray-200 rounded"></div>
                  )}
                  <p className="text-xs text-gray-500 mt-1">out of 100</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2"><p className="text-xs font-medium text-gray-500 uppercase">Active IOCs</p></CardHeader>
                <CardContent>
                  <span className="text-3xl font-bold text-gray-900">{threatData?.iocs?.length || 0}</span>
                  <p className="text-xs text-gray-500 mt-1">indicators monitored</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2"><p className="text-xs font-medium text-gray-500 uppercase">Recent CVEs</p></CardHeader>
                <CardContent>
                  <span className="text-3xl font-bold text-gray-900">{threatData?.activeThreats?.length || 0}</span>
                  <p className="text-xs text-gray-500 mt-1">from NVD database</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2"><p className="text-xs font-medium text-gray-500 uppercase">Active Campaigns</p></CardHeader>
                <CardContent>
                  <span className="text-3xl font-bold text-red-700">
                    {threatData?.campaigns?.filter((c: any) => c.status === 'ACTIVE').length || 0}
                  </span>
                  <p className="text-xs text-gray-500 mt-1">require attention</p>
                </CardContent>
              </Card>
            </div>

            {/* Quick Analysis */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Quick Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-gray-600">IP Address</label>
                    <div className="flex gap-2">
                      <Input placeholder="8.8.8.8" value={ipInput} onChange={(e) => setIpInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && analyzeIP()} className="text-sm" />
                      <Button size="sm" onClick={analyzeIP} disabled={isLoading}><Search className="h-4 w-4" /></Button>
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-gray-600">Domain</label>
                    <div className="flex gap-2">
                      <Input placeholder="example.com" value={domainInput} onChange={(e) => setDomainInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && analyzeDomain()} className="text-sm" />
                      <Button size="sm" onClick={analyzeDomain} disabled={isLoading}><Search className="h-4 w-4" /></Button>
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-gray-600">CVE ID / Keyword</label>
                    <div className="flex gap-2">
                      <Input placeholder="CVE-2024-1234" value={cveInput} onChange={(e) => setCveInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && searchCVE()} className="text-sm" />
                      <Button size="sm" onClick={searchCVE} disabled={isLoading}><Search className="h-4 w-4" /></Button>
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-gray-600">URL</label>
                    <div className="flex gap-2">
                      <Input placeholder="https://..." value={urlInput} onChange={(e) => setUrlInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && analyzeURL()} className="text-sm" />
                      <Button size="sm" onClick={analyzeURL} disabled={isLoading}><Search className="h-4 w-4" /></Button>
                    </div>
                  </div>
                </div>

                {/* Latest Result */}
                {(ipResult || domainResult || urlResult || hashResult) && (
                  <div className="mt-4 p-4 bg-gray-50 rounded-lg border border-gray-200">
                    <h4 className="text-sm font-medium text-gray-700 mb-2">Latest Result</h4>
                    
                    {ipResult && (
                      <div className="space-y-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <code className="text-sm bg-white px-2 py-0.5 rounded border">{ipResult.query}</code>
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityStyle(ipResult.threat.level)}`}>
                            {ipResult.threat.level}: {ipResult.threat.score}/100
                          </span>
                        </div>
                        <p className="text-xs text-gray-600">
                          Location: {ipResult.geolocation.city}, {ipResult.geolocation.country} | ISP: {ipResult.network.isp}
                        </p>
                      </div>
                    )}
                    
                    {urlResult && (
                      <div className="space-y-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <code className="text-sm bg-white px-2 py-0.5 rounded border truncate max-w-md">{urlResult.url}</code>
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityStyle(urlResult.overallAssessment.riskLevel)}`}>
                            {urlResult.overallAssessment.riskLevel}
                          </span>
                        </div>
                        <p className="text-xs text-gray-600">{urlResult.overallAssessment.verdict}</p>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Recent Threats from NVD */}
            {threatData?.activeThreats && threatData.activeThreats.length > 0 && (
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle className="text-base">Recent Vulnerabilities (NIST NVD)</CardTitle>
                  <Button variant="ghost" size="sm" onClick={() => setActiveTab('cve')}>
                    View all <ChevronRight className="h-4 w-4 ml-1" />
                  </Button>
                </CardHeader>
                <CardContent>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-gray-200">
                          <th className="text-left py-2 px-2 font-medium text-gray-600">CVE ID</th>
                          <th className="text-left py-2 px-2 font-medium text-gray-600">Severity</th>
                          <th className="text-left py-2 px-2 font-medium text-gray-600">CVSS</th>
                          <th className="text-left py-2 px-2 font-medium text-gray-600">Published</th>
                        </tr>
                      </thead>
                      <tbody>
                        {threatData.activeThreats.slice(0, 5).map((t: any, i: number) => (
                          <tr key={i} className="border-b border-gray-100 hover:bg-gray-50">
                            <td className="py-2 px-2 font-mono text-blue-700">{t.id}</td>
                            <td className="py-2 px-2">
                              <span className={`px-2 py-0.5 rounded text-xs ${getSeverityStyle(t.severity)}`}>{t.severity}</span>
                            </td>
                            <td className="py-2 px-2">{t.cvssScore || '-'}</td>
                            <td className="py-2 px-2 text-gray-500">{new Date(t.published).toLocaleDateString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* ==================== IP INTEL ==================== */}
          <TabsContent value="ip" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Globe className="h-5 w-5" /> IP Intelligence Analysis
                </CardTitle>
                <p className="text-sm text-gray-600">Geolocation and threat assessment using ip-api.com</p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-3 max-w-xl">
                  <Input placeholder="Enter IPv4 or IPv6 address (e.g., 8.8.8.8)" 
                    value={ipInput} onChange={(e) => setIpInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeIP()} className="flex-1" />
                  <Button onClick={analyzeIP} disabled={isLoading || !ipInput}>
                    {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    Analyze
                  </Button>
                </div>

                {ipResult && (
                  <div className="mt-6 space-y-4">
                    {/* Threat Assessment Banner */}
                    <div className={`p-4 rounded-lg border-l-4 ${
                      ipResult.threat.score >= 60 ? 'bg-red-50 border-red-500' :
                      ipResult.threat.score >= 40 ? 'bg-orange-50 border-orange-500' :
                      ipResult.threat.score >= 20 ? 'bg-yellow-50 border-yellow-500' : 'bg-green-50 border-green-500'
                    }`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-semibold text-gray-900">Threat Assessment</span>
                        <div className="flex items-center gap-2">
                          <span className="text-2xl font-bold">{ipResult.threat.score}</span>
                          <span className="text-sm text-gray-600">/100</span>
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityStyle(ipResult.threat.level)}`}>
                            {ipResult.threat.level}
                          </span>
                        </div>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div 
                          className={`h-2 rounded-full ${
                            ipResult.threat.score >= 60 ? 'bg-red-500' :
                            ipResult.threat.score >= 40 ? 'bg-orange-500' :
                            ipResult.threat.score >= 20 ? 'bg-yellow-500' : 'bg-green-500'
                          }`}
                          style={{ width: `${ipResult.threat.score}%` }}
                        ></div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      {/* Geolocation Data */}
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm flex items-center gap-2">
                            <MapPin className="h-4 w-4" /> Geolocation Data
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <dl className="space-y-2 text-sm">
                            <div className="flex justify-between"><dt className="text-gray-500">Country:</dt><dd className="font-medium">{ipResult.geolocation.country}</dd></div>
                            <div className="flex justify-between"><dt className="text-gray-500">Region:</dt><dd>{ipResult.geolocation.region}</dd></div>
                            <div className="flex justify-between"><dt className="text-gray-500">City:</dt><dd>{ipResult.geolocation.city}</dd></div>
                            <div className="flex justify-between"><dt className="text-gray-500">Coordinates:</dt><dd className="font-mono">{ipResult.geolocation.latitude}, {ipResult.geolocation.longitude}</dd></div>
                            <div className="flex justify-between"><dt className="text-gray-500">Timezone:</dt><dd>{ipResult.geolocation.timezone}</dd></div>
                          </dl>
                        </CardContent>
                      </Card>

                      {/* Network Information */}
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm flex items-center gap-2">
                            <Server className="h-4 w-4" /> Network Information
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <dl className="space-y-2 text-sm">
                            <div className="flex justify-between"><dt className="text-gray-500">ISP:</dt><dd className="font-medium">{ipResult.network.isp}</dd></div>
                            <div className="flex justify-between"><dt className="text-gray-500">Organization:</dt><dd>{ipResult.network.org}</dd></div>
                            <div className="flex justify-between"><dt className="text-gray-500">ASN:</dt><dd className="font-mono">{ipResult.network.asn}</dd></div>
                            <Separator className="my-2" />
                            <div className="flex justify-between items-center">
                              <dt className="text-gray-500">Proxy/VPN:</dt>
                              <dd><Badge variant={ipResult.network.isProxy ? "destructive" : "secondary"}>{ipResult.network.isProxy ? 'Detected' : 'No'}</Badge></dd>
                            </div>
                            <div className="flex justify-between items-center">
                              <dt className="text-gray-500">Hosting/Datacenter:</dt>
                              <dd><Badge variant={ipResult.network.isHosting ? "destructive" : "secondary"}>{ipResult.network.isHosting ? 'Yes' : 'No'}</Badge></dd>
                            </div>
                            <div className="flex justify-between items-center">
                              <dt className="text-gray-500">Mobile:</dt>
                              <dd><Badge variant={ipResult.network.isMobile ? "default" : "secondary"}>{ipResult.network.isMobile ? 'Yes' : 'No'}</Badge></dd>
                            </div>
                          </dl>
                        </CardContent>
                      </Card>
                    </div>

                    {/* Indicators & Recommendations */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm flex items-center gap-2">
                            <AlertTriangle className="h-4 w-4 text-yellow-600" /> Indicators
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-1.5 text-sm">
                            {ipResult.threat.indicators.map((ind, i) => (
                              <li key={i} className="flex items-start gap-2">
                                <ChevronRight className="h-4 w-4 text-gray-400 mt-0.5 shrink-0" />
                                <span>{ind}</span>
                              </li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm flex items-center gap-2">
                            <CheckCircle2 className="h-4 w-4 text-green-600" /> Recommendations
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-1.5 text-sm">
                            {ipResult.threat.recommendations.map((rec, i) => (
                              <li key={i} className="flex items-start gap-2">
                                <ChevronRight className="h-4 w-4 text-gray-400 mt-0.5 shrink-0" />
                                <span>{rec}</span>
                              </li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>
                    </div>

                    {/* Metadata */}
                    <div className="text-xs text-gray-500 pt-2 border-t">
                      Source: {ipResult.metadata?.source} | Analyzed: {new Date(ipResult.metadata?.analyzedAt).toLocaleString()}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== DOMAIN ==================== */}
          <TabsContent value="domain" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Globe className="h-5 w-5" /> Domain Security Analysis
                </CardTitle>
                <p className="text-sm text-gray-600">WHOIS, DNS records, and reputation assessment</p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-3 max-w-xl">
                  <Input placeholder="Enter domain (e.g., google.com)" 
                    value={domainInput} onChange={(e) => setDomainInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeDomain()} className="flex-1" />
                  <Button onClick={analyzeDomain} disabled={isLoading || !domainInput}>Analyze</Button>
                </div>

                {domainResult && (
                  <div className="mt-6 space-y-4">
                    <div className={`p-4 rounded-lg border-l-4 ${getSeverityStyle(domainResult.reputation.level)}`}>
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-gray-900">Reputation Score</span>
                        <div className="flex items-center gap-2">
                          <span className="text-2xl font-bold">{domainResult.reputation.score}</span>
                          <span>/100</span>
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityStyle(domainResult.reputation.level)}`}>
                            {domainResult.reputation.level}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader className="pb-3"><CardTitle className="text-sm">WHOIS Information</CardTitle></CardHeader>
                        <CardContent>
                          <dl className="space-y-2 text-sm">
                            {domainResult.whois?.error ? (
                              <p className="text-gray-500">{domainResult.whois.error}</p>
                            ) : (
                              <>
                                <div className="flex justify-between"><dt className="text-gray-500">Registrar:</dt><dd>{domainResult.whois.registrar}</dd></div>
                                <div className="flex justify-between"><dt className="text-gray-500">Created:</dt><dd>{domainResult.whois.creationDate}</dd></div>
                                <div className="flex justify-between"><dt className="text-gray-500">Expires:</dt><dd>{domainResult.whois.expiryDate}</dd></div>
                                <div className="flex justify-between"><dt className="text-gray-500">Country:</dt><dd>{domainResult.whois.registrantCountry}</dd></div>
                                <div className="flex justify-between"><dt className="text-gray-500">Age (days):</dt><dd>{domainResult.whois.ageDays}</dd></div>
                                <div className="flex justify-between"><dt className="text-gray-500">Privacy:</dt>
                                  <dd><Badge variant={domainResult.whois.privacyEnabled ? "secondary" : "default"}>
                                    {domainResult.whois.privacyEnabled ? 'Enabled' : 'Public'}
                                  </Badge></dd>
                                </div>
                              </>
                            )}
                          </dl>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3"><CardTitle className="text-sm">DNS Records</CardTitle></CardHeader>
                        <CardContent>
                          <dl className="space-y-2 text-sm">
                            {domainResult.dns?.error ? (
                              <p className="text-gray-500">{domainResult.dns.error}</p>
                            ) : (
                              <>
                                <div className="flex justify-between"><dt className="text-gray-500">A Records:</dt><dd className="font-mono text-xs">{domainResult.dns.aRecords?.join(', ') || 'N/A'}</dd></div>
                                <div className="flex justify-between"><dt className="text-gray-500">MX:</dt><dd className="font-mono text-xs">{domainResult.dns.mxRecords?.join(', ') || 'N/A'}</dd></div>
                                <div className="flex justify-between"><dt className="text-gray-500">NS:</dt><dd className="font-mono text-xs">{domainResult.dns.nsRecords?.join(', ') || 'N/A'}</dd></div>
                                <Separator className="my-2" />
                                <div className="flex justify-between items-center">
                                  <dt className="text-gray-500">SPF:</dt>
                                  <dd><Badge variant={domainResult.dns.hasSPF ? "default" : "destructive"}>{domainResult.dns.hasSPF ? 'Configured' : 'Missing'}</Badge></dd>
                                </div>
                                <div className="flex justify-between items-center">
                                  <dt className="text-gray-500">DMARC:</dt>
                                  <dd><Badge variant={domainResult.dns.hasDMARC ? "default" : "destructive"}>{domainResult.dns.hasDMARC ? 'Configured' : 'Missing'}</Badge></dd>
                                </div>
                              </>
                            )}
                          </dl>
                        </CardContent>
                      </Card>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== CVE ==================== */}
          <TabsContent value="cve" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Bug className="h-5 w-5" /> Vulnerability Database (NIST NVD)
                </CardTitle>
                <p className="text-sm text-gray-600">Search Common Vulnerabilities and Exposures</p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-3 max-w-xl">
                  <Input placeholder="CVE-ID (e.g., CVE-2024-1234) or keyword (e.g., sql injection)" 
                    value={cveInput} onChange={(e) => setCveInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && searchCVE()} className="flex-1" />
                  <Button onClick={searchCVE} disabled={isLoading || !cveInput}>Search</Button>
                </div>

                {cveResults.length > 0 && (
                  <div className="mt-6 space-y-4">
                    {/* Stats */}
                    <div className="flex gap-3 flex-wrap">
                      {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
                        const count = cveResults.filter(c => c.cvss.severity === sev).length;
                        return (
                          <div key={sev} className={`px-3 py-2 rounded border ${getSeverityStyle(sev)} text-center min-w-[80px]`}>
                            <div className="text-xl font-bold">{count}</div>
                            <div className="text-xs">{sev}</div>
                          </div>
                        );
                      })}
                    </div>

                    {/* Results Table */}
                    <div className="border border-gray-200 rounded-lg overflow-hidden">
                      <ScrollArea className="max-h-[600px]">
                        <table className="w-full text-sm">
                          <thead className="bg-gray-50 sticky top-0">
                            <tr>
                              <th className="text-left py-3 px-4 font-medium text-gray-600">CVE ID</th>
                              <th className="text-left py-3 px-4 font-medium text-gray-600">Description</th>
                              <th className="text-left py-3 px-4 font-medium text-gray-600">CVSS</th>
                              <th className="text-left py-3 px-4 font-medium text-gray-600">Severity</th>
                              <th className="text-left py-3 px-4 font-medium text-gray-600">Status</th>
                            </tr>
                          </thead>
                          <tbody>
                            {cveResults.map((cve, idx) => (
                              <tr key={idx} className="border-t border-gray-100 hover:bg-gray-50">
                                <td className="py-3 px-4">
                                  <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noopener noreferrer"
                                    className="font-mono text-blue-700 hover:underline flex items-center gap-1">
                                    {cve.id} <ExternalLink className="h-3 w-3" />
                                  </a>
                                </td>
                                <td className="py-3 px-4 max-w-xs truncate">{cve.descriptions}</td>
                                <td className="py-3 px-4 font-mono">{cve.cvss.score || 'N/A'}</td>
                                <td className="py-3 px-4">
                                  <span className={`px-2 py-0.5 rounded text-xs ${getSeverityStyle(cve.cvss.severity)}`}>
                                    {cve.cvss.severity}
                                  </span>
                                </td>
                                <td className="py-3 px-4 text-gray-600">{cve.status}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </ScrollArea>
                    </div>

                    <p className="text-xs text-gray-500">
                      Data source: NIST National Vulnerability Database v2.0
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== URL ==================== */}
          <TabsContent value="url" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Link className="h-5 w-5" /> URL Security Analyzer
                </CardTitle>
                <p className="text-sm text-gray-600">Phishing and malware URL detection</p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-3 max-w-xl">
                  <Input placeholder="https://example.com/page" 
                    value={urlInput} onChange={(e) => setUrlInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeURL()} className="flex-1" />
                  <Button onClick={analyzeURL} disabled={isLoading || !urlInput}>Analyze</Button>
                </div>

                {urlResult && (
                  <div className="mt-6 space-y-4">
                    <div className={`p-4 rounded-lg border-l-4 ${getSeverityStyle(urlResult.overallAssessment.riskLevel)}`}>
                      <div className="flex items-center justify-between">
                        <div>
                          <span className="font-semibold text-gray-900">Risk Assessment</span>
                          <p className="text-sm text-gray-600 mt-1">{urlResult.overallAssessment.verdict}</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-2xl font-bold">{urlResult.overallAssessment.threatScore}</span>
                          <span>/100</span>
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityStyle(urlResult.overallAssessment.riskLevel)}`}>
                            {urlResult.overallAssessment.riskLevel}
                          </span>
                        </div>
                      </div>
                    </div>

                    <Card>
                      <CardHeader className="pb-3"><CardTitle className="text-sm">Parsed URL Components</CardTitle></CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                          <div className="p-2 bg-gray-50 rounded"><span className="text-gray-500 block text-xs">Protocol</span>{urlResult.parsedUrl.protocol}</div>
                          <div className="p-2 bg-gray-50 rounded"><span className="text-gray-500 block text-xs">Host</span><span className="font-mono truncate block">{urlResult.parsedUrl.hostname}</span></div>
                          <div className="p-2 bg-gray-50 rounded"><span className="text-gray-500 block text-xs">Port</span>{urlResult.parsedUrl.port}</div>
                          <div className="p-2 bg-gray-50 rounded"><span className="text-gray-500 block text-xs">Path</span><span className="truncate block">{urlResult.parsedUrl.path || '/'}</span></div>
                        </div>
                      </CardContent>
                    </Card>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader className="pb-3"><CardTitle className="text-sm text-red-700">Risk Indicators</CardTitle></CardHeader>
                        <CardContent>
                          <ul className="space-y-1.5 text-sm">
                            {urlResult.overallAssessment.indicators.map((ind, i) => (
                              <li key={i} className="flex items-start gap-2"><ChevronRight className="h-4 w-4 shrink-0" />{ind}</li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>
                      <Card>
                        <CardHeader className="pb-3"><CardTitle className="text-sm text-green-700">Recommendations</CardTitle></CardHeader>
                        <CardContent>
                          <ul className="space-y-1.5 text-sm">
                            {urlResult.overallAssessment.recommendations.map((rec, i) => (
                              <li key={i} className="flex items-start gap-2"><ChevronRight className="h-4 w-4 shrink-0" />{rec}</li>
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

          {/* ==================== HASH ==================== */}
          <TabsContent value="hash" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Fingerprint className="h-5 w-5" /> Malware Hash Lookup
                </CardTitle>
                <p className="text-sm text-gray-600">Multi-engine hash search (MD5, SHA1, SHA256)</p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-3 max-w-xl">
                  <Input placeholder="MD5, SHA1, or SHA256 hash..." 
                    value={hashInput} onChange={(e) => setHashInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeHash()} className="flex-1 font-mono" />
                  <Button onClick={analyzeHash} disabled={isLoading || !hashInput}>Search</Button>
                </div>

                {hashResult && (
                  <div className="mt-6 space-y-4">
                    <div className={`p-4 rounded-lg border-l-4 ${getSeverityStyle(hashResult.aggregateResults.threatLevel)}`}>
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm text-gray-500">Type: {hashResult.input.hashType.toUpperCase()}</p>
                          <p className="font-semibold text-gray-900 mt-1">{hashResult.found ? hashResult.aggregateResults.classification : 'Not Found'}</p>
                        </div>
                        <div className="text-right">
                          <p className="text-sm text-gray-500">Detection Rate</p>
                          <p className="text-3xl font-bold">{hashResult.aggregateResults.detectionRate}%</p>
                        </div>
                      </div>
                    </div>

                    {hashResult.engineResults.length > 0 && (
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Engine Results ({hashResult.engineResults.length} scanned)</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ScrollArea className="h-64">
                            <div className="space-y-1">
                              {hashResult.engineResults.map((engine: any, idx: number) => (
                                <div key={idx} className={`flex items-center justify-between p-2 rounded text-sm ${
                                  engine.result !== 'Clean' ? 'bg-red-50' : 'bg-gray-50'
                                }`}>
                                  <span className="font-medium">{engine.engine}</span>
                                  <Badge variant={engine.result !== 'Clean' ? "destructive" : "secondary"}>{engine.result}</Badge>
                                </div>
                              ))}
                            </div>
                          </ScrollArea>
                        </CardContent>
                      </Card>
                    )}

                    {hashResult.details && (
                      <Card>
                        <CardHeader className="pb-3"><CardTitle className="text-sm">File Details</CardTitle></CardHeader>
                        <CardContent className="text-sm space-y-2">
                          {hashResult.details.name && <div><span className="text-gray-500">Name:</span> {hashResult.details.name}</div>}
                          {hashResult.details.type && <div><span className="text-gray-500">Type:</span> {hashResult.details.type}</div>}
                          {hashResult.details.description && <div className="p-2 bg-gray-50 rounded mt-2">{hashResult.details.description}</div>}
                        </CardContent>
                      </Card>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== THREATS ==================== */}
          <TabsContent value="threats" className="space-y-6">
            {/* Global Threat Level */}
            {threatData?.globalThreatLevel && (
              <Card className={`border-l-4 ${getSeverityStyle(threatData.globalThreatLevel.level)}`}>
                <CardContent className="py-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900">Global Threat Level</h3>
                      <p className="text-sm text-gray-500">Last updated: {new Date(threatData.globalThreatLevel.timestamp).toLocaleString()}</p>
                    </div>
                    <div className="text-right">
                      <div className="text-4xl font-bold text-gray-900">{threatData.globalThreatLevel.score}</div>
                      <span className={`inline-block mt-1 px-3 py-1 rounded text-sm font-medium ${getSeverityStyle(threatData.globalThreatLevel.level)}`}>
                        {threatData.globalThreatLevel.level}
                      </span>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
                    <div className="text-center p-3 bg-white rounded border">
                      <p className="text-xl font-bold text-red-700">{threatData.globalThreatLevel.factors.criticalVulnerabilities24h}</p>
                      <p className="text-xs text-gray-500">Critical CVEs (24h)</p>
                    </div>
                    <div className="text-center p-3 bg-white rounded border">
                      <p className="text-xl font-bold text-orange-700">{threatData.globalThreatLevel.factors.highSeverityVulnerabilities24h}</p>
                      <p className="text-xs text-gray-500">High CVEs (24h)</p>
                    </div>
                    <div className="text-center p-3 bg-white rounded border">
                      <p className="text-xl font-bold text-purple-700">{threatData.globalThreatLevel.factors.activeCampaigns}</p>
                      <p className="text-xs text-gray-500">Active Campaigns</p>
                    </div>
                    <div className="text-center p-3 bg-white rounded border">
                      <p className="text-xl font-bold text-cyan-700">{threatData.globalThreatLevel.factors.monitoredIOCs}</p>
                      <p className="text-xs text-gray-500">IOCs Monitored</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* APT Groups */}
            {threatData?.aptGroups && (
              <Card>
                <CardHeader><CardTitle className="text-base">Tracked APT Groups</CardTitle></CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {threatData.aptGroups.map((apt: any, idx: number) => (
                      <Card key={idx} className={`${apt.status === 'ACTIVE' ? 'border-red-200' : 'border-gray-200'}`}>
                        <CardHeader className="pb-2">
                          <div className="flex items-center justify-between">
                            <CardTitle className="text-base">{apt.name}</CardTitle>
                            <Badge variant={apt.status === 'ACTIVE' ? "destructive" : "secondary"}>{apt.status}</Badge>
                          </div>
                          <p className="text-sm text-gray-500">{apt.country} • Attribution: {apt.attributionConfidence}</p>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm">
                          <p>{apt.description}</p>
                          <div>
                            <span className="text-gray-500 text-xs">Primary Targets:</span>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {apt.primaryTargets.map((t: string, i: number) => (
                                <Badge key={i} variant="outline" className="text-xs">{t}</Badge>
                              ))}
                            </div>
                          </div>
                          <div>
                            <span className="text-gray-500 text-xs">Techniques:</span>
                            <p className="text-xs mt-0.5">{apt.techniques.join(', ')}</p>
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
              <Card>
                <CardHeader><CardTitle className="text-base">Active Threat Campaigns</CardTitle></CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {threatData.campaigns.map((campaign: any, idx: number) => (
                      <Card key={idx} className={`border-l-4 ${campaign.status === 'ACTIVE' ? 'border-l-red-500' : 'border-l-yellow-500'}`}>
                        <CardHeader className="pb-2">
                          <div className="flex items-center justify-between">
                            <CardTitle className="text-base">{campaign.name}</CardTitle>
                            <div className="flex items-center gap-2">
                              <Badge className={getSeverityStyle(campaign.severity)}>{campaign.severity}</Badge>
                              <Badge variant={campaign.status === 'ACTIVE' ? "destructive" : "secondary"}>{campaign.status}</Badge>
                            </div>
                          </div>
                          <p className="text-sm text-gray-600">{campaign.description}</p>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
                            <div><span className="text-gray-500">ID:</span> <code>{campaign.id}</code></div>
                            <div><span className="text-gray-500">IOCs:</span> {campaign.indicators}</div>
                            <div><span className="text-gray-500">Target Sector:</span> {campaign.targetSectors.join(', ')}</div>
                            <div><span className="text-gray-500">MITRE ATT&CK:</span> {campaign.mitreTechniques.join(', ')}</div>
                          </div>
                          
                          <div>
                            <span className="text-sm font-medium text-gray-700">Recommendations:</span>
                            <ul className="mt-1 space-y-1 text-sm">
                              {campaign.recommendations.slice(0, 3).map((rec: string, i: number) => (
                                <li key={i} className="flex items-start gap-2">
                                  <ChevronRight className="h-4 w-4 text-gray-400 mt-0.5 shrink-0" />
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

          {/* ==================== REPORTS ==================== */}
          <TabsContent value="reports" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <FileText className="h-5 w-5" /> Executive Report Generator
                </CardTitle>
                <p className="text-sm text-gray-600">Generate professional OSINT intelligence reports</p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Button variant="outline" className="h-auto py-4 flex-col gap-2" onClick={() => generateReport('threat-summary')} disabled={isLoading}>
                    <BarChart3 className="h-8 w-8 text-blue-600" />
                    <span className="font-medium">Threat Summary</span>
                    <span className="text-xs text-gray-500">Global executive overview</span>
                  </Button>
                  
                  <Button variant="outline" className="h-auto py-4 flex-col gap-2" onClick={() => generateReport('full-assessment')} disabled={isLoading}>
                    <Shield className="h-8 w-8 text-orange-600" />
                    <span className="font-medium">Full Assessment</span>
                    <span className="text-xs text-gray-500">Complete OSINT analysis</span>
                  </Button>
                  
                  <Button variant="outline" className="h-auto py-4 flex-col gap-2" onClick={() => generateReport('ioc-report')} disabled={isLoading}>
                    <Database className="h-8 w-8 text-red-600" />
                    <span className="font-medium">IOC Report</span>
                    <span className="text-xs text-gray-500">Indicators of compromise</span>
                  </Button>
                </div>

                {reportData && (
                  <div className="mt-6 space-y-4">
                    <Card className="border-blue-200">
                      <CardHeader>
                        <div className="flex items-center justify-between">
                          <CardTitle>{reportData.title}</CardTitle>
                          <Button variant="outline" size="sm" onClick={() => {
                            const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = `nexus-intel-report-${Date.now()}.json`;
                            a.click();
                          }}>
                            <Download className="h-4 w-4 mr-1" /> Export JSON
                          </Button>
                        </div>
                        <p className="text-sm text-gray-600">{reportData.subtitle}</p>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        {reportData.executiveSummary && (
                          <div className="p-4 bg-gray-50 rounded-lg">
                            <h4 className="font-semibold mb-2 flex items-center gap-2">
                              <Info className="h-4 w-4" /> Executive Summary
                            </h4>
                            <p className="text-sm text-gray-700 leading-relaxed">{reportData.executiveSummary.content}</p>
                            
                            {reportData.executiveSummary.keyFindings && (
                              <div className="mt-3">
                                <span className="text-xs font-medium text-gray-600">Key Findings:</span>
                                <ul className="mt-1 space-y-1 text-sm">
                                  {reportData.executiveSummary.keyFindings.map((f: string, i: number) => (
                                    <li key={i} className="flex items-start gap-2"><CheckCircle2 className="h-4 w-4 text-green-600 mt-0.5 shrink-0" />{f}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                            
                            {reportData.executiveSummary.recommendations && (
                              <div className="mt-3">
                                <span className="text-xs font-medium text-gray-600">Recommendations:</span>
                                <ul className="mt-1 space-y-1 text-sm">
                                  {reportData.executiveSummary.recommendations.map((r: string, i: number) => (
                                    <li key={i} className="flex items-start gap-2"><ChevronRight className="h-4 w-4 text-orange-600 mt-0.5 shrink-0" />{r}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        )}

                        <div className="text-xs text-gray-500 text-center pt-4 border-t">
                          Classification: {reportData.metadata?.classification || 'CONFIDENTIAL'} | Generated: {new Date(reportData.metadata?.generatedAt).toLocaleString()}
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== MONITORING ==================== */}
          <TabsContent value="monitoring" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Terminal className="h-5 w-5" /> System Monitoring
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-4 border border-green-200 rounded-lg bg-green-50">
                    <div className="flex items-center gap-2 text-green-700">
                      <CheckCircle2 className="h-5 w-5" /><span className="font-medium">Systems Operational</span>
                    </div>
                    <p className="text-2xl font-bold mt-2">98.7%</p>
                    <p className="text-xs text-gray-500">Uptime (30 days)</p>
                  </div>
                  
                  <div className="p-4 border border-blue-200 rounded-lg bg-blue-50">
                    <div className="flex items-center gap-2 text-blue-700">
                      <Network className="h-5 w-5" /><span className="font-medium">APIs Connected</span>
                    </div>
                    <p className="text-2xl font-bold mt-2">7/7</p>
                    <p className="text-xs text-gray-500">Services active</p>
                  </div>
                  
                  <div className="p-4 border border-gray-200 rounded-lg bg-gray-50">
                    <div className="flex items-center gap-2 text-gray-700">
                      <Clock className="h-5 w-5" /><span className="font-medium">Last Sync</span>
                    </div>
                    <p className="text-2xl font-bold mt-2">2 min ago</p>
                    <p className="text-xs text-gray-500">Threat feed</p>
                  </div>
                </div>

                <Card>
                  <CardHeader className="pb-2"><CardTitle className="text-sm">Activity Log</CardTitle></CardHeader>
                  <CardContent>
                    <ScrollArea className="h-64">
                      <div className="space-y-1 font-mono text-xs">
                        {[
                          { time: '14:32:15', type: 'info', msg: '[THREAT-FEED] Sync completed - 47 new IOCs' },
                          { time: '14:31:02', type: 'warning', msg: '[ALERT] Microsoft 365 phishing pattern detected' },
                          { time: '14:28:45', type: 'info', msg: '[NVD] Database updated - 23 new CVEs' },
                          { time: '14:25:11', type: 'success', msg: '[SCAN] IP analysis completed - 8.8.8.8: SAFE' },
                          { time: '14:22:33', type: 'warning', msg: '[IOC] New suspicious domain indicator added' },
                          { time: '14:18:07', type: 'info', msg: '[SYSTEM] Cache refreshed successfully' },
                        ].map((log, i) => (
                          <div key={i} className={`p-2 rounded ${
                            log.type === 'error' ? 'bg-red-50 text-red-700' :
                            log.type === 'warning' ? 'bg-yellow-50 text-yellow-700' :
                            log.type === 'success' ? 'bg-green-50 text-green-700' :
                            'bg-gray-50 text-gray-600'
                          }`}>
                            <span className="text-gray-400">[{log.time}]</span> {log.msg}
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </CardContent>
            </Card>
          </TabsContent>

          {/* ==================== DARK WEB ==================== */}
          <TabsContent value="darkweb" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Eye className="h-5 w-5" /> Advanced OSINT / Dark Web Monitoring
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {[
                    { title: 'Data Leak Monitoring', desc: 'Monitor dark web forums for data breaches', status: 'Coming Soon' },
                    { title: 'Credential Intelligence', desc: 'Detect exposed credentials in breach databases', status: 'Coming Soon' },
                    { title: 'Threat Actor Tracking', desc: 'Track threat actors and their activities', status: 'Coming Soon' },
                    { title: 'Ransomware Tracker', desc: 'Monitor ransomware sites and victims', status: 'Coming Soon' },
                  ].map((item, i) => (
                    <Card key={i} className="border-dashed">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm">{item.title}</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <p className="text-sm text-gray-500">{item.desc}</p>
                        <Badge variant="outline" className="mt-2">{item.status}</Badge>
                      </CardContent>
                    </Card>
                  ))}
                </div>

                <div className="p-4 bg-gray-50 border border-gray-200 rounded-lg">
                  <p className="text-sm text-gray-600">
                    <strong>Note:</strong> These modules require specialized dark web access and premium threat intelligence APIs. 
                    The current version includes conventional threat monitoring via public sources (NVD, ip-api.com, etc.).
                  </p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-200 mt-12 py-6 text-center text-xs text-gray-500">
        <p>NEXUS INTEL OSINT Platform v2.0 | Data Sources: NIST NVD, ip-api.com, Public Threat Feeds</p>
        <p className="mt-1">For legitimate security and research purposes only</p>
      </footer>
    </div>
  );
}

function Eye(props: any) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/>
      <circle cx="12" cy="12" r="3"/>
    </svg>
  );
}
