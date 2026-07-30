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
  TrendingUp, TrendingDown, Clock, Zap, Database, Cpu,
  Network, Wifi, UserCheck, Users, Globe2, Terminal,
  BarChart3, PieChart, LineChart, Bell, Settings, RefreshCw
} from 'lucide-react';

// Types
interface IPResult {
  query: string;
  geolocation: {
    country: string;
    countryCode: string;
    region: string;
    city: string;
    latitude: number;
    longitude: number;
  };
  network: {
    isp: string;
    org: string;
    asn: string;
    isProxy: boolean;
    isHosting: boolean;
  };
  threat: {
    score: number;
    level: string;
    color: string;
    indicators: string[];
  };
}

interface DomainResult {
  domain: string;
  whois: any;
  dns: any;
  reputation: {
    score: number;
    level: string;
    color: string;
  };
  security: any;
}

interface CVEResult {
  id: string;
  descriptions: string;
  cvss: {
    score: number | null;
    severity: string;
    vector: string;
  };
  cwe: string[];
}

interface URLResult {
  url: string;
  overallAssessment: {
    threatScore: number;
    riskLevel: string;
    riskColor: string;
    indicators: string[];
  };
}

interface HashResult {
  input: { hash: string; hashType: string };
  aggregateResults: {
    detectionRate: number;
    classification: string;
    threatLevel: string;
    color: string;
  };
  engineResults: any;
}

interface ThreatData {
  iocs: any[];
  activeThreats: any[];
  campaigns: any[];
  aptGroups: any[];
  globalThreatLevel: any;
  statistics: any;
}

// Main Component
export default function OSINTDashboard() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isLoading, setIsLoading] = useState(false);
  
  // IP Analysis State
  const [ipInput, setIpInput] = useState('');
  const [ipResult, setIpResult] = useState<IPResult | null>(null);
  
  // Domain Analysis State
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

  // API Functions (declared before useEffect to avoid hoisting issues)
  const fetchThreatIntelligence = useCallback(async () => {
    try {
      const res = await fetch('/api/osint/threats');
      const data = await res.json();
      if (data.success) setThreatData(data.data);
    } catch (error) {
      console.error('Threat intel error:', error);
    }
  }, []);

  // Initialize threat data on component mount
  useEffect(() => {
    let isMounted = true;
    const initializeData = async () => {
      try {
        const res = await fetch('/api/osint/threats');
        const data = await res.json();
        if (isMounted && data.success) setThreatData(data.data);
      } catch (error) {
        if (isMounted) console.error('Threat intel error:', error);
      }
    };
    initializeData();
    return () => { isMounted = false; };
  }, []);

  const analyzeIP = async () => {
    if (!ipInput) return;
    setIsLoading(true);
    try {
      const res = await fetch('/api/osint/ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ipInput })
      });
      const data = await res.json();
      if (data.success) setIpResult(data.data);
    } catch (error) {
      console.error('IP analysis error:', error);
    }
    setIsLoading(false);
  };

  const analyzeDomain = async () => {
    if (!domainInput) return;
    setIsLoading(true);
    try {
      const res = await fetch('/api/osint/domain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domainInput })
      });
      const data = await res.json();
      if (data.success) setDomainResult(data.data);
    } catch (error) {
      console.error('Domain analysis error:', error);
    }
    setIsLoading(false);
  };

  const searchCVE = async () => {
    if (!cveInput) return;
    setIsLoading(true);
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
      }
    } catch (error) {
      console.error('CVE search error:', error);
    }
    setIsLoading(false);
  };

  const analyzeURL = async () => {
    if (!urlInput) return;
    setIsLoading(true);
    try {
      const res = await fetch('/api/osint/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput })
      });
      const data = await res.json();
      if (data.success) setUrlResult(data.data);
    } catch (error) {
      console.error('URL analysis error:', error);
    }
    setIsLoading(false);
  };

  const analyzeHash = async () => {
    if (!hashInput) return;
    setIsLoading(true);
    try {
      const res = await fetch('/api/osint/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: hashInput })
      });
      const data = await res.json();
      if (data.success) setHashResult(data.data);
    } catch (error) {
      console.error('Hash analysis error:', error);
    }
    setIsLoading(false);
  };

  const generateReport = async (type: string) => {
    setIsLoading(true);
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
    } catch (error) {
      console.error('Report generation error:', error);
    }
    setIsLoading(false);
  };

  // Helper function for threat level color
  const getThreatColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'critical':
      case 'dangerous':
      case 'severe':
        return 'text-red-500 bg-red-50 border-red-200';
      case 'high':
      case 'suspicious':
      case 'elevated':
        return 'text-orange-500 bg-orange-50 border-orange-200';
      case 'medium':
      case 'caution':
      case 'guarded':
        return 'text-yellow-500 bg-yellow-50 border-yellow-200';
      default:
        return 'text-green-500 bg-green-50 border-green-200';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-gradient-to-br from-red-600 to-orange-600 rounded-lg">
                <Shield className="h-6 w-6" />
              </div>
              <div>
                <h1 className="text-xl font-bold bg-gradient-to-r from-red-400 to-orange-400 bg-clip-text text-transparent">
                  NEXUS INTEL
                </h1>
                <p className="text-xs text-slate-400">OSINT & Threat Intelligence Platform</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              {threatData?.globalThreatLevel && (
                <Badge variant="outline" className={`${getThreatColor(threatData.globalThreatLevel.level)} px-3 py-1`}>
                  <Activity className="h-3 w-3 mr-1" />
                  Global Threat: {threatData.globalThreatLevel.level}
                </Badge>
              )}
              <Button variant="ghost" size="sm" onClick={fetchThreatIntelligence}>
                <RefreshCw className="h-4 w-4 mr-1" />
                Refresh
              </Button>
            </div>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-6">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid grid-cols-5 lg:grid-cols-10 gap-2 bg-slate-800/50 p-2 rounded-xl h-auto">
            <TabsTrigger value="dashboard" className="data-[state=active]:bg-red-600">
              <BarChart3 className="h-4 w-4 mr-1 hidden sm:inline" />
              Dashboard
            </TabsTrigger>
            <TabsTrigger value="ip" className="data-[state=active]:bg-red-600">
              <Globe2 className="h-4 w-4 mr-1 hidden sm:inline" />
              IP Intel
            </TabsTrigger>
            <TabsTrigger value="domain" className="data-[state=active]:bg-red-600">
              <Globe className="h-4 w-4 mr-1 hidden sm:inline" />
              Domain
            </TabsTrigger>
            <TabsTrigger value="cve" className="data-[state=active]:bg-red-600">
              <Bug className="h-4 w-4 mr-1 hidden sm:inline" />
              CVE
            </TabsTrigger>
            <TabsTrigger value="url" className="data-[state=active]:bg-red-600">
              <Link className="h-4 w-4 mr-1 hidden sm:inline" />
              URL
            </TabsTrigger>
            <TabsTrigger value="hash" className="data-[state=active]:bg-red-600">
              <Fingerprint className="h-4 w-4 mr-1 hidden sm:inline" />
              Hash
            </TabsTrigger>
            <TabsTrigger value="threats" className="data-[state=active]:bg-red-600">
              <Radar className="h-4 w-4 mr-1 hidden sm:inline" />
              Threats
            </TabsTrigger>
            <TabsTrigger value="reports" className="data-[state=active]:bg-red-600">
              <FileText className="h-4 w-4 mr-1 hidden sm:inline" />
              Reports
            </TabsTrigger>
            <TabsTrigger value="monitoring" className="data-[state=active]:bg-red-600">
              <Activity className="h-4 w-4 mr-1 hidden sm:inline" />
              Live
            </TabsTrigger>
            <TabsTrigger value="darkweb" className="data-[state=active]:bg-red-600">
              <Eye className="h-4 w-4 mr-1 hidden sm:inline" />
              Dark Web
            </TabsTrigger>
          </TabsList>

          {/* Dashboard Tab */}
          <TabsContent value="dashboard" className="space-y-6">
            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <Card className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-slate-400 text-sm">Active Threats</p>
                      <p className="text-3xl font-bold">{threatData?.activeThreats?.length || 12}</p>
                    </div>
                      <div className="p-3 bg-red-500/20 rounded-lg">
                        <AlertTriangle className="h-6 w-6 text-red-400" />
                      </div>
                  </div>
                  <div className="mt-4 flex items-center text-xs text-red-400">
                    <TrendingUp className="h-3 w-3 mr-1" />
                    +23% from last week
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-slate-400 text-sm">IOCs Tracked</p>
                      <p className="text-3xl font-bold">{threatData?.iocs?.length || 248}</p>
                    </div>
                    <div className="p-3 bg-orange-500/20 rounded-lg">
                      <Database className="h-6 w-6 text-orange-400" />
                    </div>
                  </div>
                  <div className="mt-4 flex items-center text-xs text-orange-400">
                    <Database className="h-3 w-3 mr-1" />
                    +45 new this week
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-slate-400 text-sm">Active Campaigns</p>
                      <p className="text-3xl font-bold">{threatData?.campaigns?.length || 4}</p>
                    </div>
                    <div className="p-3 bg-purple-500/20 rounded-lg">
                      <Target className="h-6 w-6 text-purple-400" />
                    </div>
                  </div>
                  <div className="mt-4 flex items-center text-xs text-purple-400">
                    <Radar className="h-3 w-3 mr-1" />
                    2 APT campaigns active
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-slate-400 text-sm">Threat Score</p>
                      <p className="text-3xl font-bold">{threatData?.globalThreatLevel?.score || 70}</p>
                    </div>
                    <div className="p-3 bg-blue-500/20 rounded-lg">
                      <Shield className="h-6 w-6 text-blue-400" />
                    </div>
                  </div>
                  <div className="mt-4 flex items-center text-xs text-blue-400">
                    <span className={`inline-block w-2 h-2 rounded-full mr-1 ${threatData?.globalThreatLevel?.color === '#dc2626' ? 'bg-red-500' : 'bg-yellow-500'}`} />
                    Level: {threatData?.globalThreatLevel?.level || 'Elevated'}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Main Dashboard Content */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Recent Alerts */}
              <Card className="bg-slate-800/50 border-slate-700 lg:col-span-2">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Bell className="h-5 w-5 text-red-400" />
                    Active Threat Alerts
                  </CardTitle>
                  <CardDescription>Real-time security alerts and notifications</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[400px] pr-4">
                    <div className="space-y-3">
                      {threatData?.activeThreats?.slice(0, 8).map((alert: any, idx: number) => (
                        <div key={idx} className={`p-4 rounded-lg border ${getThreatColor(alert.severity)}`}>
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                <Badge variant="outline" className={getThreatColor(alert.severity)}>
                                  {alert.severity.toUpperCase()}
                                </Badge>
                                <span className="text-xs text-slate-400">{alert.category}</span>
                              </div>
                              <p className="font-medium text-sm">{alert.title}</p>
                              <p className="text-xs text-slate-400 mt-1 line-clamp-2">{alert.description?.substring(0, 100)}...</p>
                            </div>
                            <Clock className="h-4 w-4 text-slate-500 ml-2 flex-shrink-0" />
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>

              {/* APT Groups & Quick Actions */}
              <div className="space-y-6">
                <Card className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Users className="h-5 w-5 text-purple-400" />
                      Active APT Groups
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {threatData?.aptGroups?.slice(0, 5).map((apt: any, idx: number) => (
                        <div key={idx} className="p-3 bg-slate-700/30 rounded-lg">
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-mono font-bold text-sm">{apt.id}</span>
                            <Badge variant="outline" className={getThreatColor(apt.threatLevel)}>
                              {apt.threatLevel}
                            </Badge>
                          </div>
                          <p className="text-xs text-slate-400">{apt.origin}</p>
                          <p className="text-xs text-slate-500 mt-1">{apt.aliases?.join(', ')}</p>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-gradient-to-br from-red-950/50 to-orange-950/50 border-red-800/50">
                  <CardContent className="p-6">
                    <h3 className="font-semibold mb-2">Quick Actions</h3>
                    <div className="grid grid-cols-2 gap-2">
                      <Button variant="secondary" size="sm" onClick={() => setActiveTab('ip')} className="bg-slate-700 hover:bg-slate-600">
                        <Globe2 className="h-3 w-3 mr-1" /> Analyze IP
                      </Button>
                      <Button variant="secondary" size="sm" onClick={() => setActiveTab('domain')} className="bg-slate-700 hover:bg-slate-600">
                        <Globe className="h-3 w-3 mr-1" /> Domain
                      </Button>
                      <Button variant="secondary" size="sm" onClick={() => setActiveTab('cve')} className="bg-slate-700 hover:bg-slate-600">
                        <Bug className="h-3 w-3 mr-1" /> CVE Search
                      </Button>
                      <Button variant="secondary" size="sm" onClick={() => setActiveTab('reports')} className="bg-slate-700 hover:bg-slate-600">
                        <FileText className="h-3 w-3 mr-1" /> Report
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>

            {/* Statistics Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <Card className="bg-slate-800/50 border-slate-700">
                <CardHeader className="pb-2">
                  <CardDescription>IOCs by Type</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {Object.entries(threatData?.statistics?.iocsByType || {}).map(([type, count]: [string, any]) => (
                      <div key={type} className="flex items-center justify-between text-sm">
                        <span className="uppercase font-mono">{type}</span>
                        <Badge variant="secondary">{count}</Badge>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-slate-800/50 border-slate-700">
                <CardHeader className="pb-2">
                  <CardDescription>Threat Severity Distribution</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {Object.entries(threatData?.statistics?.threatsBySeverity || {}).map(([severity, count]: [string, any]) => (
                      <div key={severity} className="flex items-center gap-2">
                        <span className="text-xs uppercase w-16">{severity}</span>
                        <Progress value={(count / (threatData?.activeThreats?.length || 1)) * 100} className="flex-1 h-2" />
                        <span className="text-xs text-slate-400 w-6">{count}</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-slate-800/50 border-slate-700">
                <CardHeader className="pb-2">
                  <CardDescription>TLP Classification</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {Object.entries(threatData?.statistics?.tlpDistribution || {}).map(([tlp, count]: [string, any]) => (
                      <div key={tlp} className="flex items-center justify-between text-sm">
                        <span className="font-semibold" style={{
                          color: tlp === 'RED' ? '#dc2626' : tlp === 'AMBER' ? '#f97316' : tlp === 'GREEN' ? '#22c55e' : '#6b7280'
                        }}>TLP:{tlp}</span>
                        <span>{count}</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-slate-800/50 border-slate-700">
                <CardHeader className="pb-2">
                  <CardDescription>Active Campaigns</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {threatData?.campaigns?.map((campaign: any, idx: number) => (
                      <div key={idx}>
                        <p className="font-medium text-sm truncate">{campaign.name}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge variant="outline" className={
                            campaign.status === 'active' ? 'text-red-400 border-red-400' : 'text-yellow-400 border-yellow-400'
                          }>
                            {campaign.status}
                          </Badge>
                          <span className="text-xs text-slate-400">{campaign.threatActor}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* IP Analysis Tab */}
          <TabsContent value="ip" className="space-y-6">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe2 className="h-5 w-5 text-blue-400" />
                  IP Address Intelligence
                </CardTitle>
                <CardDescription>Analyze IP addresses for geolocation, reputation, and threat indicators</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex gap-3">
                  <Input
                    placeholder="Enter IP address (e.g., 8.8.8.8)"
                    value={ipInput}
                    onChange={(e) => setIpInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeIP()}
                    className="bg-slate-700 border-slate-600"
                  />
                  <Button onClick={analyzeIP} disabled={isLoading}>
                    {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    Analyze
                  </Button>
                </div>
              </CardContent>
            </Card>

            {ipResult && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Geolocation */}
                <Card className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <MapPin className="h-5 w-5 text-green-400" />
                      Geolocation
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-slate-400 text-xs">Country</p>
                          <p className="font-semibold">{ipResult.geolocation.country}</p>
                        </div>
                        <div>
                          <p className="text-slate-400 text-xs">Country Code</p>
                          <p className="font-semibold">{ipResult.geolocation.countryCode}</p>
                        </div>
                        <div>
                          <p className="text-slate-400 text-xs">Region</p>
                          <p className="font-semibold">{ipResult.geolocation.region}</p>
                        </div>
                        <div>
                          <p className="text-slate-400 text-xs">City</p>
                          <p className="font-semibold">{ipResult.geolocation.city}</p>
                        </div>
                        <div>
                          <p className="text-slate-400 text-xs">Latitude</p>
                          <p className="font-mono text-sm">{ipResult.geolocation.latitude}</p>
                        </div>
                        <div>
                          <p className="text-slate-400 text-xs">Longitude</p>
                          <p className="font-mono text-sm">{ipResult.geolocation.longitude}</p>
                        </div>
                      </div>
                      <div className="mt-4 p-4 bg-slate-700/50 rounded-lg">
                        <div className="aspect-video bg-gradient-to-br from-slate-600 to-slate-700 rounded flex items-center justify-center">
                          <MapPin className="h-12 w-12 text-slate-400" />
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Network Info */}
                <Card className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Server className="h-5 w-5 text-purple-400" />
                      Network Information
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div>
                        <p className="text-slate-400 text-xs">ISP</p>
                        <p className="font-semibold">{ipResult.network.isp}</p>
                      </div>
                      <div>
                        <p className="text-slate-400 text-xs">Organization</p>
                        <p className="font-semibold">{ipResult.network.org}</p>
                      </div>
                      <div>
                        <p className="text-slate-400 text-xs">ASN</p>
                        <p className="font-mono text-sm">{ipResult.network.asn}</p>
                      </div>
                      <Separator className="bg-slate-700" />
                      <div className="grid grid-cols-2 gap-4">
                        <div className="flex items-center gap-2">
                          {ipResult.network.isProxy ? (
                            <XCircle className="h-4 w-4 text-red-400" />
                          ) : (
                            <CheckCircle2 className="h-4 w-4 text-green-400" />
                          )}
                          <span className="text-sm">Proxy/VPN</span>
                        </div>
                        <div className="flex items-center gap-2">
                          {ipResult.network.isHosting ? (
                            <XCircle className="h-4 w-4 text-red-400" />
                          ) : (
                            <CheckCircle2 className="h-4 w-4 text-green-400" />
                          )}
                          <span className="text-sm">Hosting IP</span>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Threat Assessment */}
                <Card className="bg-slate-800/50 border-slate-700 lg:col-span-2">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-red-400" />
                      Threat Assessment
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      <div className="text-center">
                        <div className="relative inline-flex items-center justify-center w-32 h-32">
                          <svg className="w-full h-full transform -rotate-90">
                            <circle cx="64" cy="64" r="56" fill="none" stroke="#334155" strokeWidth="8" />
                            <circle 
                              cx="64" cy="64" r="56" 
                              fill="none" 
                              stroke={ipResult.threat.color} 
                              strokeWidth="8"
                              strokeDasharray={`${(ipResult.threat.score / 100) * 352} 352`}
                              strokeLinecap="round"
                            />
                          </svg>
                          <div className="absolute inset-0 flex flex-col items-center justify-center">
                            <span className="text-3xl font-bold">{ipResult.threat.score}</span>
                            <span className="text-xs text-slate-400">Score</span>
                          </div>
                        </div>
                        <Badge variant="outline" className={`mt-2 ${getThreatColor(ipResult.threat.level)}`}>
                          {ipResult.threat.level}
                        </Badge>
                      </div>
                      
                      <div className="md:col-span-2 space-y-3">
                        <div>
                          <p className="text-slate-400 text-sm mb-2">Threat Indicators</p>
                          <div className="space-y-2">
                            {ipResult.threat.indicators.map((indicator, idx) => (
                              <div key={idx} className="flex items-center gap-2 p-2 bg-red-950/30 rounded border border-red-900/30">
                                <AlertTriangle className="h-4 w-4 text-red-400 flex-shrink-0" />
                                <span className="text-sm">{indicator}</span>
                              </div>
                            ))}
                            {ipResult.threat.indicators.length === 0 && (
                              <div className="flex items-center gap-2 p-2 bg-green-950/30 rounded border border-green-900/30">
                                <CheckCircle2 className="h-4 w-4 text-green-400" />
                                <span className="text-sm">No significant threats detected</span>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}
          </TabsContent>

          {/* Domain Analysis Tab */}
          <TabsContent value="domain" className="space-y-6">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5 text-cyan-400" />
                  Domain Intelligence
                </CardTitle>
                <CardDescription>WHOIS lookup, DNS records, and domain reputation analysis</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex gap-3">
                  <Input
                    placeholder="Enter domain (e.g., example.com)"
                    value={domainInput}
                    onChange={(e) => setDomainInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeDomain()}
                    className="bg-slate-700 border-slate-600"
                  />
                  <Button onClick={analyzeDomain} disabled={isLoading}>
                    {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    Analyze
                  </Button>
                </div>
              </CardContent>
            </Card>

            {domainResult && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* WHOIS Information */}
                <Card className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <FileText className="h-5 w-5 text-yellow-400" />
                      WHOIS Information
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3 text-sm">
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <p className="text-slate-400 text-xs">Registrar</p>
                          <p className="font-medium">{domainResult.whois.registrar}</p>
                        </div>
                        <div>
                          <p className="text-slate-400 text-xs">DNSSEC</p>
                          <p className="font-medium">{domainResult.whois.dnssec}</p>
                        </div>
                        <div className="col-span-2">
                          <p className="text-slate-400 text-xs">Created</p>
                          <p className="font-medium">{new Date(domainResult.whois.creationDate).toLocaleDateString()}</p>
                        </div>
                        <div className="col-span-2">
                          <p className="text-slate-400 text-xs">Expires</p>
                          <p className="font-medium">{new Date(domainResult.whois.expirationDate).toLocaleDateString()}</p>
                        </div>
                      </div>
                      <Separator className="bg-slate-700 my-3" />
                      <div>
                        <p className="text-slate-400 text-xs mb-1">Registrant</p>
                        <p>{domainResult.whois.registrant.organization}</p>
                        <p className="text-slate-500">{domainResult.whois.registrant.country}</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* DNS Records */}
                <Card className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Database className="h-5 w-5 text-indigo-400" />
                      DNS Records
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div>
                        <p className="text-slate-400 text-xs mb-2">A Records</p>
                        <div className="space-y-1">
                          {domainResult.dns.A.map((record: any, idx: number) => (
                            <code key={idx} className="block p-2 bg-slate-700/50 rounded text-xs font-mono">
                              {record.value}
                            </code>
                          ))}
                        </div>
                      </div>
                      <div>
                        <p className="text-slate-400 text-xs mb-2">MX Records</p>
                        <div className="space-y-1">
                          {domainResult.dns.MX.map((record: any, idx: number) => (
                            <code key={idx} className="block p-2 bg-slate-700/50 rounded text-xs font-mono">
                              Priority {record.priority}: {record.exchange}
                            </code>
                          ))}
                        </div>
                      </div>
                      <div>
                        <p className="text-slate-400 text-xs mb-2">NS Records</p>
                        <div className="space-y-1">
                          {domainResult.dns.NS.map((record: any, idx: number) => (
                            <code key={idx} className="block p-2 bg-slate-700/50 rounded text-xs font-mono">
                              {record.value}
                            </code>
                          ))}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Reputation & Security */}
                <Card className="bg-slate-800/50 border-slate-700 lg:col-span-2">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-emerald-400" />
                      Reputation & Security Analysis
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div>
                        <div className="flex items-center justify-between mb-3">
                          <span className="text-sm font-medium">Reputation Score</span>
                          <Badge variant="outline" className={getThreatColor(domainResult.reputation.level)}>
                            {domainResult.reputation.score}/100 - {domainResult.reputation.level}
                          </Badge>
                        </div>
                        <Progress value={domainResult.reputation.score} className="h-3" />
                        
                        <div className="mt-4 space-y-2">
                          {domainResult.reputation.factors.map((factor: string, idx: number) => (
                            <div key={idx} className="flex items-center gap-2 text-sm">
                              <div className="w-2 h-2 rounded-full bg-slate-500" />
                              {factor}
                            </div>
                          ))}
                        </div>
                      </div>
                      
                      <div>
                        <p className="text-sm font-medium mb-3">Security Checks</p>
                        <div className="space-y-2">
                          <div className="flex items-center justify-between p-2 bg-slate-700/30 rounded">
                            <span className="text-sm">SSL Certificate</span>
                            {domainResult.security.hasSSL ? (
                              <CheckCircle2 className="h-4 w-4 text-green-400" />
                            ) : (
                              <XCircle className="h-4 w-4 text-red-400" />
                            )}
                          </div>
                          <div className="flex items-center justify-between p-2 bg-slate-700/30 rounded">
                            <span className="text-sm">SPF Record</span>
                            {domainResult.security.hasSpf ? (
                              <CheckCircle2 className="h-4 w-4 text-green-400" />
                            ) : (
                              <XCircle className="h-4 w-4 text-red-400" />
                            )}
                          </div>
                          <div className="flex items-center justify-between p-2 bg-slate-700/30 rounded">
                            <span className="text-sm">DMARC</span>
                            {domainResult.security.hasDmarc ? (
                              <CheckCircle2 className="h-4 w-4 text-green-400" />
                            ) : (
                              <XCircle className="h-4 w-4 text-red-400" />
                            )}
                          </div>
                          <div className="flex items-center justify-between p-2 bg-slate-700/30 rounded">
                            <span className="text-sm">DNSSEC</span>
                            {domainResult.security.hasDnssec ? (
                              <CheckCircle2 className="h-4 w-4 text-green-400" />
                            ) : (
                              <XCircle className="h-4 w-4 text-red-400" />
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                    
                    {domainResult.security.issues.length > 0 && (
                      <>
                        <Separator className="bg-slate-700 my-4" />
                        <div>
                          <p className="text-sm font-medium mb-2 text-red-400">Security Issues Found</p>
                          <div className="space-y-2">
                            {domainResult.security.issues.map((issue: string, idx: number) => (
                              <div key={idx} className="flex items-start gap-2 p-2 bg-red-950/20 rounded border border-red-900/20">
                                <AlertTriangle className="h-4 w-4 text-red-400 mt-0.5 flex-shrink-0" />
                                <span className="text-sm">{issue}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </>
                    )}

                    {domainResult.security.strengths.length > 0 && (
                      <div className="mt-4">
                        <p className="text-sm font-medium mb-2 text-green-400">Security Strengths</p>
                        <div className="space-y-2">
                          {domainResult.security.strengths.map((strength: string, idx: number) => (
                            <div key={idx} className="flex items-start gap-2 p-2 bg-green-950/20 rounded border border-green-900/20">
                              <CheckCircle2 className="h-4 w-4 text-green-400 mt-0.5 flex-shrink-0" />
                              <span className="text-sm">{strength}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            )}
          </TabsContent>

          {/* CVE Search Tab */}
          <TabsContent value="cve" className="space-y-6">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bug className="h-5 w-5 text-red-400" />
                  Vulnerability Database (NVD)
                </CardTitle>
                <CardDescription>Search CVEs and vulnerabilities from the National Vulnerability Database</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex gap-3">
                  <Input
                    placeholder="Enter CVE ID (e.g., CVE-2024-1234) or keyword"
                    value={cveInput}
                    onChange={(e) => setCveInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && searchCVE()}
                    className="bg-slate-700 border-slate-600"
                  />
                  <Button onClick={searchCVE} disabled={isLoading}>
                    {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    Search
                  </Button>
                </div>
              </CardContent>
            </Card>

            {cveResults.length > 0 && (
              <div className="space-y-4">
                {/* Statistics Bar */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  <Card className="bg-slate-800/50 border-slate-700">
                    <CardContent className="p-4 text-center">
                      <p className="text-2xl font-bold">{cveResults.length}</p>
                      <p className="text-xs text-slate-400">Total Results</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-red-950/30 border-red-900/30">
                    <CardContent className="p-4 text-center">
                      <p className="text-2xl font-bold text-red-400">{cveResults.filter(c => c.cvss.severity === 'CRITICAL').length}</p>
                      <p className="text-xs text-slate-400">Critical</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-orange-950/30 border-orange-900/30">
                    <CardContent className="p-4 text-center">
                      <p className="text-2xl font-bold text-orange-400">{cveResults.filter(c => c.cvss.severity === 'HIGH').length}</p>
                      <p className="text-xs text-slate-400">High</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-yellow-950/30 border-yellow-900/30">
                    <CardContent className="p-4 text-center">
                      <p className="text-2xl font-bold text-yellow-400">{cveResults.filter(c => c.cvss.severity === 'MEDIUM').length}</p>
                      <p className="text-xs text-slate-400">Medium</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-green-950/30 border-green-900/30">
                    <CardContent className="p-4 text-center">
                      <p className="text-2xl font-bold text-green-400">{cveResults.filter(c => c.cvss.severity === 'LOW').length}</p>
                      <p className="text-xs text-slate-400">Low</p>
                    </CardContent>
                  </Card>
                </div>

                {/* Results List */}
                <div className="space-y-4">
                  {cveResults.map((cve, idx) => (
                    <Card key={idx} className="bg-slate-800/50 border-slate-700">
                      <CardContent className="p-6">
                        <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                          <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                              <h3 className="font-mono font-bold text-lg">{cve.id}</h3>
                              <Badge variant="outline" className={getThreatColor(c.cvss.severity)}>
                                {c.cvss.severity}
                              </Badge>
                              <Badge variant="secondary">
                                CVSS {c.cvss.score || 'N/A'}
                              </Badge>
                            </div>
                            <p className="text-slate-300 text-sm mb-3">{cve.descriptions}</p>
                            
                            <div className="flex flex-wrap gap-2 mb-3">
                              {cve.cwe.map((cwe, cweIdx) => (
                                <Badge key={cweIdx} variant="outline" className="text-xs">
                                  {cwe.split(':')[1] || cwe}
                                </Badge>
                              ))}
                            </div>

                            {cve.cvss.vector && (
                              <code className="block p-2 bg-slate-700/50 rounded text-xs font-mono text-slate-400">
                                Vector: {cve.cvss.vector}
                              </code>
                            )}
                          </div>
                          
                          <div className="flex-shrink-0">
                            {cve.cvss.score && (
                              <div className={`w-20 h-20 rounded-full flex items-center justify-center text-center ${
                                cve.cvss.score >= 9 ? 'bg-red-950/50 border-2 border-red-500' :
                                cve.cvss.score >= 7 ? 'bg-orange-950/50 border-2 border-orange-500' :
                                cve.cvss.score >= 4 ? 'bg-yellow-950/50 border-2 border-yellow-500' :
                                'bg-green-950/50 border-2 border-green-500'
                              }`}>
                                <div>
                                  <p className="text-2xl font-bold">{cve.cvss.score}</p>
                                  <p className="text-xs text-slate-400">CVSS</p>
                                </div>
                              </div>
                            )}
                          </div>
                        </div>

                        <Separator className="bg-slate-700 my-4" />

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                          <div>
                            <p className="text-slate-400 text-xs">Published</p>
                            <p>{new Date(cve.dates.published).toLocaleDateString()}</p>
                          </div>
                          <div>
                            <p className="text-slate-400 text-xs">Last Modified</p>
                            <p>{new Date(cve.dates.lastModified).toLocaleDateString()}</p>
                          </div>
                          <div>
                            <p className="text-slate-400 text-xs">Status</p>
                            <Badge variant="outline">{cve.status}</Badge>
                          </div>
                        </div>

                        {cve.references.length > 0 && (
                          <div className="mt-4">
                            <p className="text-slate-400 text-xs mb-2">References ({cve.references.length})</p>
                            <div className="flex flex-wrap gap-2">
                              {cve.references.slice(0, 3).map((ref, refIdx) => (
                                <a
                                  key={refIdx}
                                  href={ref.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-xs text-blue-400 hover:text-blue-300 underline truncate max-w-xs inline-block"
                                >
                                  {ref.url.replace(/^https?:\/\//, '')}
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
          </TabsContent>

          {/* URL Analysis Tab */}
          <TabsContent value="url" className="space-y-6">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Link className="h-5 w-5 text-pink-400" />
                  URL Security Analyzer
                </CardTitle>
                <CardDescription>Check URLs for phishing, malware, and other malicious content</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex gap-3">
                  <Input
                    placeholder="Enter full URL (e.g., https://example.com/page)"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeURL()}
                    className="bg-slate-700 border-slate-600"
                  />
                  <Button onClick={analyzeURL} disabled={isLoading}>
                    {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    Analyze
                  </Button>
                </div>
              </CardContent>
            </Card>

            {urlResult && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Overall Assessment */}
                <Card className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-purple-400" />
                      Security Assessment
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-center mb-6">
                      <div className="relative inline-flex items-center justify-center w-40 h-40">
                        <svg className="w-full h-full transform -rotate-90">
                          <circle cx="80" cy="80" r="70" fill="none" stroke="#334155" strokeWidth="10" />
                          <circle 
                            cx="80" cy="80" r="70" 
                            fill="none" 
                            stroke={urlResult.overallAssessment.riskColor} 
                            strokeWidth="10"
                            strokeDasharray={`${(urlResult.overallAssessment.threatScore / 100) * 440} 440`}
                            strokeLinecap="round"
                          />
                        </svg>
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                          <span className="text-4xl font-bold">{100 - urlResult.overallAssessment.threatScore}</span>
                          <span className="text-xs text-slate-400">Safety Score</span>
                        </div>
                      </div>
                      <Badge variant="outline" className={`mt-2 ${getThreatColor(urlResult.overallAssessment.riskLevel)}`} style={{ fontSize: '1rem', padding: '0.5rem 1rem' }}>
                        {urlResult.overallAssessment.riskLevel}
                      </Badge>
                    </div>

                    <div className="p-4 bg-slate-700/30 rounded-lg">
                      <p className="text-sm font-medium mb-2">Recommendation</p>
                      <p className="text-sm text-slate-300">{urlResult.overallAssessment.recommendation}</p>
                    </div>
                  </CardContent>
                </Card>

                {/* Detailed Analysis */}
                <Card className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Zap className="h-5 w-5 text-yellow-400" />
                      Analysis Details
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {/* URL Components */}
                      <div>
                        <p className="text-slate-400 text-xs mb-2">URL Components</p>
                        <div className="grid grid-cols-2 gap-2 text-sm">
                          <div className="p-2 bg-slate-700/30 rounded">
                            <p className="text-slate-400 text-xs">Protocol</p>
                            <p className="font-mono">{urlResult.analyzedUrl.protocol}</p>
                          </div>
                          <div className="p-2 bg-slate-700/30 rounded">
                            <p className="text-slate-400 text-xs">Hostname</p>
                            <p className="font-mono text-xs truncate">{urlResult.analyzedUrl.hostname}</p>
                          </div>
                        </div>
                      </div>

                      {/* Threat Indicators */}
                      {urlResult.overallAssessment.indicators.length > 0 && (
                        <div>
                          <p className="text-slate-400 text-xs mb-2">Threat Indicators</p>
                          <div className="space-y-2">
                            {urlResult.overallAssessment.indicators.map((indicator, idx) => (
                              <div key={idx} className="flex items-center gap-2 p-2 bg-red-950/30 rounded border border-red-900/30">
                                <XCircle className="h-4 w-4 text-red-400 flex-shrink-0" />
                                <span className="text-sm">{indicator}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Scan Engines */}
                      <div>
                        <p className="text-slate-400 text-xs mb-2">Scan Engines Used</p>
                        <div className="flex flex-wrap gap-1">
                          {urlResult.metadata.enginesUsed.map((engine, idx) => (
                            <Badge key={idx} variant="secondary" className="text-xs">
                              {engine}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}
          </TabsContent>

          {/* Hash Analysis Tab */}
          <TabsContent value="hash" className="space-y-6">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Fingerprint className="h-5 w-5 text-violet-400" />
                  Malware Hash Lookup
                </CardTitle>
                <CardDescription>Search file hashes across multiple antivirus engines and malware databases</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex gap-3">
                  <Input
                    placeholder="Enter MD5, SHA1, SHA256, or SHA512 hash"
                    value={hashInput}
                    onChange={(e) => setHashInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeHash()}
                    className="bg-slate-700 border-slate-600 font-mono"
                  />
                  <Button onClick={analyzeHash} disabled={isLoading}>
                    {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    Lookup
                  </Button>
                </div>
              </CardContent>
            </Card>

            {hashResult && (
              <div className="space-y-6">
                {/* Aggregate Results */}
                <Card className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <BarChart3 className="h-5 w-5 text-cyan-400" />
                      Aggregate Detection Results
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                      <div className="text-center">
                        <div className="relative inline-flex items-center justify-center w-28 h-28">
                          <svg className="w-full h-full transform -rotate-90">
                            <circle cx="56" cy="56" r="48" fill="none" stroke="#334155" strokeWidth="8" />
                            <circle 
                              cx="56" cy="56" r="48" 
                              fill="none" 
                              stroke={hashResult.aggregateResults.color} 
                              strokeWidth="8"
                              strokeDasharray={`${(hashResult.aggregateResults.detectionRate / 100) * 302} 302`}
                              strokeLinecap="round"
                            />
                          </svg>
                          <div className="absolute inset-0 flex flex-col items-center justify-center">
                            <span className="text-2xl font-bold">{hashResult.aggregateResults.detectionRate}%</span>
                            <span className="text-xs text-slate-400">Detection</span>
                          </div>
                        </div>
                      </div>

                      <div className="md:col-span-3 space-y-3">
                        <div className="grid grid-cols-2 gap-4">
                          <div className="p-3 bg-slate-700/30 rounded">
                            <p className="text-slate-400 text-xs">Classification</p>
                            <p className="font-semibold text-lg">{hashResult.aggregateResults.classification}</p>
                          </div>
                          <div className="p-3 bg-slate-700/30 rounded">
                            <p className="text-slate-400 text-xs">Threat Level</p>
                            <Badge variant="outline" className={getThreatColor(hashResult.aggregateResults.threatLevel)}>
                              {hashResult.aggregateResults.threatLevel}
                            </Badge>
                          </div>
                          <div className="p-3 bg-slate-700/30 rounded">
                            <p className="text-slate-400 text-xs">Engines Scanned</p>
                            <p className="font-semibold text-lg">{hashResult.aggregateResults.totalEnginesScanned}</p>
                          </div>
                          <div className="p-3 bg-slate-700/30 rounded">
                            <p className="text-slate-400 text-xs">Detections</p>
                            <p className="font-semibold text-lg text-red-400">{hashResult.aggregateResults.totalDetections}</p>
                          </div>
                        </div>

                        <div className="p-3 bg-slate-700/30 rounded">
                          <p className="text-slate-400 text-xs mb-1">Hash Type</p>
                          <code className="font-mono text-sm">{hashResult.input.hashType}</code>
                          <p className="font-mono text-xs text-slate-400 mt-1 break-all">{hashResult.input.hash}</p>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Engine Results Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* VirusTotal */}
                  <Card className="bg-slate-800/50 border-slate-700">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full bg-green-500" />
                        VirusTotal
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        <div className="flex justify-between text-sm">
                          <span>Detection Rate</span>
                          <span className="font-mono">{hashResult.engineResults.virusTotal.detections}/{hashResult.engineResults.virusTotal.enginesScanned}</span>
                        </div>
                        <Progress 
                          value={(hashResult.engineResults.virusTotal.detections / hashResult.engineResults.virusTotal.enginesScanned) * 100} 
                          className="h-2" 
                        />
                        
                        {hashResult.engineResults.virusTotal.detectingEngines.length > 0 && (
                          <div className="max-h-32 overflow-y-auto">
                            <p className="text-xs text-slate-400 mb-2">Detecting Engines:</p>
                            <div className="space-y-1">
                              {hashResult.engineResults.virusTotal.detectingEngines.slice(0, 5).map((engine: any, idx: number) => (
                                <div key={idx} className="flex items-center justify-between text-xs p-1 bg-red-950/20 rounded">
                                  <span>{engine.engine}</span>
                                  <span className="text-red-400">{engine.result.substring(0, 25)}...</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>

                  {/* MalwareBazaar */}
                  <Card className="bg-slate-800/50 border-slate-700">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full bg-blue-500" />
                        MalwareBazaar
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {hashResult.engineResults.malwareBazaar.fileDetails ? (
                          <>
                            <div className="grid grid-cols-2 gap-2 text-sm">
                              <div>
                                <p className="text-slate-400 text-xs">File Type</p>
                                <p>{hashResult.engineResults.malwareBazaar.fileDetails.fileType}</p>
                              </div>
                              <div>
                                <p className="text-slate-400 text-xs">Size</p>
                                <p>{hashResult.engineResults.malwareBazaar.fileDetails.fileSize}</p>
                              </div>
                            </div>
                            <div className="flex flex-wrap gap-1">
                              {hashResult.engineResults.malwareBazaar.fileDetails.tags.map((tag: string, idx: number) => (
                                <Badge key={idx} variant="outline" className="text-xs">{tag}</Badge>
                              ))}
                            </div>
                          </>
                        ) : (
                          <p className="text-sm text-slate-400">No additional details available</p>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Behavioral Analysis */}
                {hashResult.behaviorAnalysis && (
                  <Card className="bg-slate-800/50 border-slate-700">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Terminal className="h-5 w-5 text-red-400" />
                        Behavioral Analysis
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-sm text-slate-300 mb-4">{hashResult.behaviorAnalysis.summary}</p>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        {hashResult.behaviorAnalysis.networkActivity.length > 0 && (
                          <div>
                            <p className="text-slate-400 text-xs mb-2">Network Activity</p>
                            <div className="space-y-1">
                              {hashResult.behaviorAnalysis.networkActivity.slice(0, 3).map((activity: any, idx: number) => (
                                <div key={idx} className="p-2 bg-red-950/20 rounded text-xs">
                                  <p className="font-medium">{activity.action}</p>
                                  <p className="text-slate-400 font-mono">{activity.destination}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        
                        {hashResult.behaviorAnalysis.fileSystemActivity.length > 0 && (
                          <div>
                            <p className="text-slate-400 text-xs mb-2">File System</p>
                            <div className="space-y-1">
                              {hashResult.behaviorAnalysis.fileSystemActivity.slice(0, 3).map((activity: any, idx: number) => (
                                <div key={idx} className="p-2 bg-orange-950/20 rounded text-xs">
                                  <p className="font-medium">{activity.action}</p>
                                  <p className="text-slate-400 font-mono truncate">{activity.path}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        
                        {hashResult.behaviorAnalysis.registryActivity.length > 0 && (
                          <div>
                            <p className="text-slate-400 text-xs mb-2">Registry</p>
                            <div className="space-y-1">
                              {hashResult.behaviorAnalysis.registryActivity.slice(0, 3).map((activity: any, idx: number) => (
                                <div key={idx} className="p-2 bg-yellow-950/20 rounded text-xs">
                                  <p className="font-medium">{activity.action}</p>
                                  <p className="text-slate-400 font-mono truncate">{activity.path}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        
                        {hashResult.behaviorAnalysis.processActivity.length > 0 && (
                          <div>
                            <p className="text-slate-400 text-xs mb-2">Process</p>
                            <div className="space-y-1">
                              {hashResult.behaviorAnalysis.processActivity.slice(0, 3).map((activity: any, idx: number) => (
                                <div key={idx} className="p-2 bg-purple-950/20 rounded text-xs">
                                  <p className="font-medium">{activity.action}</p>
                                  <p className="text-slate-400 font-mono truncate">{activity.name}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Recommendations */}
                <Card className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <CheckCircle2 className="h-5 w-5 text-green-400" />
                      Recommendations
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-2">
                      {hashResult.recommendations.map((rec: string, idx: number) => (
                        <li key={idx} className="flex items-start gap-2 text-sm">
                          <div className="w-1.5 h-1.5 rounded-full bg-green-400 mt-2 flex-shrink-0" />
                          {rec}
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>
              </div>
            )}
          </TabsContent>

          {/* Threat Intelligence Tab */}
          <TabsContent value="threats" className="space-y-6">
            {/* Global Threat Level Banner */}
            {threatData?.globalThreatLevel && (
              <Card className={`bg-gradient-to-r ${
                threatData.globalThreatLevel.level === 'Severe' ? 'from-red-950 to-red-900' :
                threatData.globalThreatLevel.level === 'Elevated' ? 'from-orange-950 to-orange-900' :
                'from-yellow-950 to-yellow-900'
              } border-${threatData.globalThreatLevel.level === 'Severe' ? 'red' : 'orange'}-800`}>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-xl font-bold flex items-center gap-2">
                        <Activity className="h-6 w-6" />
                        Global Threat Level: {threatData.globalThreatLevel.level}
                      </h2>
                      <p className="text-slate-300 mt-1">{threatData.globalThreatLevel.recommendation}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-4xl font-bold">{threatData.globalThreatLevel.score}</p>
                      <p className="text-sm text-slate-300">Threat Score</p>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-3 gap-4 mt-4 pt-4 border-t border-white/10">
                    <div className="text-center">
                      <p className="text-2xl font-bold text-red-400">{threatData.globalThreatLevel.factors.criticalAlerts}</p>
                      <p className="text-xs text-slate-300">Critical Alerts</p>
                    </div>
                    <div className="text-center">
                      <p className="text-2xl font-bold text-orange-400">{threatData.globalThreatLevel.factors.highAlerts}</p>
                      <p className="text-xs text-slate-300">High Alerts</p>
                    </div>
                    <div className="text-center">
                      <p className="text-2xl font-bold text-yellow-400">{threatData.globalThreatLevel.factors.totalActiveThreats}</p>
                      <p className="text-xs text-slate-300">Active Threats</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* IOC Feed */}
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="flex items-center gap-2">
                    <Database className="h-5 w-5 text-blue-400" />
                    Live IOC Feed
                  </CardTitle>
                  <Button variant="outline" size="sm" onClick={fetchThreatIntelligence}>
                    <RefreshCw className="h-4 w-4 mr-1" />
                    Refresh IOCs
                  </Button>
                </div>
                <CardDescription>Latest Indicators of Compromise from multiple intelligence sources</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[500px]">
                  <div className="space-y-3">
                    {threatData?.iocs?.map((ioc: any, idx: number) => (
                      <div key={idx} className="p-4 bg-slate-700/30 rounded-lg border border-slate-600/50 hover:border-slate-500 transition-colors">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-2">
                              <Badge variant="outline" className="uppercase text-xs">
                                {ioc.type}
                              </Badge>
                              <Badge variant="secondary" className="text-xs">
                                TLP:{ioc.tlp}
                              </Badge>
                              <span className="text-xs text-slate-400">
                                Confidence: {ioc.confidence}%
                              </span>
                            </div>
                            <code className="block text-sm font-mono bg-slate-800 p-2 rounded mb-2 break-all">
                              {ioc.value}
                            </code>
                            <p className="text-sm text-slate-300">{ioc.description}</p>
                            
                            <div className="flex flex-wrap gap-1 mt-2">
                              {ioc.tags.map((tag: string, tagIdx: number) => (
                                <Badge key={tagIdx} variant="outline" className="text-xs text-blue-400 border-blue-400/30">
                                  {tag}
                                </Badge>
                              ))}
                            </div>
                          </div>
                          
                          <div className="ml-4 text-right text-xs text-slate-400">
                            <p>{ioc.source}</p>
                            <p className="mt-1">{new Date(ioc.lastSeen).toLocaleDateString()}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Reports Tab */}
          <TabsContent value="reports" className="space-y-6">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileText className="h-5 w-5 text-emerald-400" />
                  Executive Reports Generator
                </CardTitle>
                <CardDescription>Generate professional security reports for stakeholders and management</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <Button 
                    variant="outline" 
                    className="h-auto py-6 flex flex-col gap-2 bg-slate-700/50 hover:bg-slate-700"
                    onClick={() => generateReport('threat-assessment')}
                    disabled={isLoading}
                  >
                    <Shield className="h-8 w-8 text-red-400" />
                    <span>Threat Assessment</span>
                    <span className="text-xs text-slate-400">Comprehensive threat landscape analysis</span>
                  </Button>
                  
                  <Button 
                    variant="outline" 
                    className="h-auto py-6 flex flex-col gap-2 bg-slate-700/50 hover:bg-slate-700"
                    onClick={() => generateReport('incident-response')}
                    disabled={isLoading}
                  >
                    <AlertTriangle className="h-8 w-8 text-orange-400" />
                    <span>Incident Response</span>
                    <span className="text-xs text-slate-400">Post-incident analysis report</span>
                  </Button>
                  
                  <Button 
                    variant="outline" 
                    className="h-auto py-6 flex flex-col gap-2 bg-slate-700/50 hover:bg-slate-700"
                    onClick={() => generateReport('intelligence-briefing')}
                    disabled={isLoading}
                  >
                    <Radar className="h-8 w-8 text-purple-400" />
                    <span>Intel Briefing</span>
                    <span className="text-xs text-slate-400">Daily/weekly intelligence summary</span>
                  </Button>
                  
                  <Button 
                    variant="outline" 
                    className="h-auto py-6 flex flex-col gap-2 bg-slate-700/50 hover:bg-slate-700"
                    onClick={() => generateReport('executive-summary')}
                    disabled={isLoading}
                  >
                    <BarChart3 className="h-8 w-8 text-blue-400" />
                    <span>Executive Summary</span>
                    <span className="text-xs text-slate-400">High-level metrics dashboard</span>
                  </Button>
                </div>
              </CardContent>
            </Card>

            {reportData && (
              <Card className="bg-slate-800/50 border-slate-700">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="flex items-center gap-2">
                      <FileText className="h-5 w-5" />
                      {reportData.title}
                    </CardTitle>
                    <Button variant="outline" size="sm">
                      <Download className="h-4 w-4 mr-1" />
                      Export PDF
                    </Button>
                  </div>
                  <CardDescription>{reportData.subtitle}</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[600px] pr-4">
                    <div className="prose prose-invert max-w-none space-y-6">
                      {/* Executive Summary Section */}
                      {reportData.executiveSummary && (
                        <section className="p-6 bg-slate-700/30 rounded-lg">
                          <h2 className="text-xl font-bold mb-4">Executive Summary</h2>
                          <p className="text-slate-300 mb-4">{reportData.executiveSummary.overview}</p>
                          
                          {reportData.executiveSummary.keyFindings && (
                            <div>
                              <h3 className="font-semibold mb-2">Key Findings</h3>
                              <ul className="list-disc list-inside space-y-1 text-sm text-slate-300">
                                {reportData.executiveSummary.keyFindings.map((finding: string, idx: number) => (
                                  <li key={idx}>{finding}</li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {reportData.executiveSummary.riskRating && (
                            <div className="mt-4 p-4 bg-slate-800/50 rounded">
                              <div className="flex items-center justify-between">
                                <span>Risk Rating:</span>
                                <Badge variant="outline" className={getThreatColor(reportData.executiveSummary.riskRating.overall)}>
                                  {reportData.executiveSummary.riskRating.overall} ({reportData.executiveSummary.riskRating.score}/100)
                                </Badge>
                              </div>
                              <p className="text-sm text-slate-400 mt-2">Trend: {reportData.executiveSummary.riskRating.trend}</p>
                            </div>
                          )}
                        </section>
                      )}

                      {/* Sections */}
                      {reportData.sections?.map((section: any, idx: number) => (
                        <section key={idx} className="p-6 bg-slate-700/30 rounded-lg">
                          <h2 className="text-xl font-bold mb-4">{section.title}</h2>
                          <p className="text-slate-300 mb-4">{section.content}</p>
                          
                          {section.metrics && (
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 my-4">
                              {Object.entries(section.metrics).map(([key, value]: [string, any]) => (
                                <div key={key} className="p-3 bg-slate-800/50 rounded text-center">
                                  <p className="text-2xl font-bold">{value}</p>
                                  <p className="text-xs text-slate-400 capitalize">{key.replace(/([A-Z])/g, ' $1')}</p>
                                </div>
                              ))}
                            </div>
                          )}

                          {section.subsections?.map((subsection: any, subIdx: number) => (
                            <div key={subIdx} className="mt-4 p-4 bg-slate-800/30 rounded">
                              <h3 className="font-semibold mb-2">{subsection.name}</h3>
                              <p className="text-sm text-slate-300">{subsection.content}</p>
                              
                              {subsection.actors && (
                                <div className="mt-2 space-y-2">
                                  {subsection.actors.map((actor: any, actorIdx: number) => (
                                    <div key={actorIdx} className="p-2 bg-slate-700/30 rounded text-sm">
                                      <span className="font-mono font-bold">{actor.id}</span>
                                      <span className="text-slate-400 ml-2">{actor.origin}</span>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          ))}

                          {section.vectors && (
                            <div className="mt-4 space-y-3">
                              {section.vectors.map((vector: any, vIdx: number) => (
                                <div key={vIdx} className="p-3 bg-slate-800/30 rounded">
                                  <div className="flex items-center justify-between mb-1">
                                    <span className="font-medium">{vector.name}</span>
                                    <div className="flex items-center gap-2">
                                      <span className="text-sm">{vector.prevalence}%</span>
                                      <span className="text-xs">{vector.trend}</span>
                                    </div>
                                  </div>
                                  <Progress value={vector.prevalence} className="h-2 mt-1" />
                                  <p className="text-xs text-slate-400 mt-1">{vector.details}</p>
                                </div>
                              ))}
                            </div>
                          )}

                          {section.priorities && (
                            <div className="mt-4 space-y-4">
                              {section.priorities.map((priority: any, pIdx: number) => (
                                <div key={pIdx}>
                                  <h3 className="font-semibold text-sm mb-2">{priority.priority}</h3>
                                  <ul className="list-disc list-inside space-y-1 text-sm text-slate-300">
                                    {priority.actions.map((action: string, aIdx: number) => (
                                      <li key={aIdx}>{action}</li>
                                    ))}
                                  </ul>
                                </div>
                              ))}
                            </div>
                          )}
                        </section>
                      ))}

                      {/* Conclusion */}
                      {reportData.conclusion && (
                        <section className="p-6 bg-gradient-to-r from-slate-700/30 to-slate-800/30 rounded-lg">
                          <h2 className="text-xl font-bold mb-4">Conclusion</h2>
                          <p className="text-slate-300 mb-4">{reportData.conclusion.summary}</p>
                          <p className="text-sm text-slate-400"><strong>Next Steps:</strong> {reportData.conclusion.nextSteps}</p>
                        </section>
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Live Monitoring Tab */}
          <TabsContent value="monitoring" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Live Feed */}
              <Card className="bg-slate-800/50 border-slate-700 lg:col-span-2">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="flex items-center gap-2">
                      <Activity className="h-5 w-5 text-green-400 animate-pulse" />
                      Live Security Feed
                    </CardTitle>
                    <Badge variant="outline" className="text-green-400 border-green-400">
                      ● LIVE
                    </Badge>
                  </div>
                  <CardDescription>Real-time security events and alerts stream</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[500px]">
                    <div className="space-y-2 font-mono text-sm">
                      {generateLiveEvents().map((event, idx) => (
                        <div key={idx} className={`p-3 rounded border-l-4 ${
                          event.type === 'critical' ? 'bg-red-950/20 border-red-500' :
                          event.type === 'warning' ? 'bg-orange-950/20 border-orange-500' :
                          event.type === 'info' ? 'bg-blue-950/20 border-blue-500' :
                          'bg-slate-700/30 border-slate-500'
                        }`}>
                          <div className="flex items-center justify-between">
                            <span className="text-slate-400">[{event.timestamp}]</span>
                            <Badge variant="outline" className={`text-xs ${
                              event.type === 'critical' ? 'text-red-400 border-red-400' :
                              event.type === 'warning' ? 'text-orange-400 border-orange-400' :
                              event.type === 'info' ? 'text-blue-400 border-blue-400' :
                              'text-slate-400 border-slate-400'
                            }`}>
                              {event.type.toUpperCase()}
                            </Badge>
                          </div>
                          <p className="mt-1 text-white">{event.message}</p>
                          {event.source && <p className="text-xs text-slate-500 mt-1">Source: {event.source}</p>}
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>

              {/* System Status */}
              <div className="space-y-6">
                <Card className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Cpu className="h-5 w-5 text-cyan-400" />
                      System Status
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {[
                        { name: 'API Gateway', status: 'operational', uptime: '99.99%' },
                        { name: 'Threat Feeds', status: 'operational', uptime: '99.95%' },
                        { name: 'IOC Database', status: 'operational', uptime: '99.98%' },
                        { name: 'Analyzer Service', status: 'degraded', uptime: '98.5%' },
                        { name: 'Report Generator', status: 'operational', uptime: '99.99%' },
                      ].map((service, idx) => (
                        <div key={idx} className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <div className={`w-2 h-2 rounded-full ${
                              service.status === 'operational' ? 'bg-green-500' : 'bg-yellow-500'
                            }`} />
                            <span className="text-sm">{service.name}</span>
                          </div>
                          <span className="text-xs text-slate-400">{service.uptime}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-slate-800/50 border-slate-700">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Network className="h-5 w-5 text-purple-400" />
                      Traffic Overview
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Requests Today</span>
                        <span className="font-mono">128,459</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Blocked Requests</span>
                        <span className="font-mono text-red-400">2,341</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Avg Response Time</span>
                        <span className="font-mono">45ms</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Active Connections</span>
                        <span className="font-mono">1,247</span>
                      </div>
                      <Separator className="bg-slate-700" />
                      <div className="pt-2">
                        <p className="text-xs text-slate-400 mb-2">Bandwidth Usage</p>
                        <Progress value={67} className="h-2" />
                        <p className="text-xs text-slate-400 mt-1">6.7 GB / 10 GB</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          </TabsContent>

          {/* Dark Web Monitoring Tab */}
          <TabsContent value="darkweb" className="space-y-6">
            <Card className="bg-gradient-to-br from-slate-900 via-purple-950/20 to-slate-900 border-purple-800/30">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Eye className="h-5 w-5 text-purple-400" />
                  Dark Web Monitoring
                </CardTitle>
                <CardDescription>Monitor dark web marketplaces, forums, and leak sites for compromised credentials and data</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="p-4 bg-slate-800/50 rounded-lg text-center">
                    <p className="text-3xl font-bold text-red-400">24</p>
                    <p className="text-sm text-slate-400">Breaches Tracked</p>
                  </div>
                  <div className="p-4 bg-slate-800/50 rounded-lg text-center">
                    <p className="text-3xl font-bold text-orange-400">2.4M</p>
                    <p className="text-sm text-slate-400">Credentials Found</p>
                  </div>
                  <div className="p-4 bg-slate-800/50 rounded-lg text-center">
                    <p className="text-3xl font-bold text-yellow-400">156</p>
                    <p className="text-sm text-slate-400">Leak Sites Monitored</p>
                  </div>
                  <div className="p-4 bg-slate-800/50 rounded-lg text-center">
                    <p className="text-3xl font-bold text-purple-400">89</p>
                    <p className="text-sm text-slate-400">Alerts This Week</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Recent Leaks */}
              <Card className="bg-slate-800/50 border-slate-700">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-red-400" />
                    Recent Data Breaches
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {generateDarkWebLeaks().map((leak, idx) => (
                      <div key={idx} className="p-4 bg-slate-700/30 rounded-lg border border-red-900/20">
                        <div className="flex items-start justify-between">
                          <div>
                            <h4 className="font-semibold">{leak.company}</h4>
                            <p className="text-sm text-slate-400">{leak.description}</p>
                            <div className="flex items-center gap-3 mt-2 text-xs text-slate-500">
                              <span>Records: {leak.records.toLocaleString()}</span>
                              <span>Data Types: {leak.dataTypes.join(', ')}</span>
                            </div>
                          </div>
                          <Badge variant="outline" className="text-red-400 border-red-400 ml-2">
                            {leak.daysAgo}d ago
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Credential Monitoring */}
              <Card className="bg-slate-800/50 border-slate-700">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <UserCheck className="h-5 w-5 text-cyan-400" />
                    Credential Exposure Monitor
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="mb-4">
                    <Input
                      placeholder="Enter email domain to monitor (e.g., @company.com)"
                      className="bg-slate-700 border-slate-600"
                    />
                  </div>
                  
                  <div className="space-y-3">
                    <h4 className="font-medium text-sm">Recent Exposures Detected</h4>
                    {generateCredentialExposures().map((exposure, idx) => (
                      <div key={idx} className="p-3 bg-slate-700/30 rounded-lg">
                        <div className="flex items-center justify-between mb-1">
                          <code className="text-sm">{exposure.email}</code>
                          <Badge variant="outline" className={`text-xs ${
                            exposure.severity === 'high' ? 'text-red-400 border-red-400' : 'text-yellow-400 border-yellow-400'
                          }`}>
                            {exposure.severity}
                          </Badge>
                        </div>
                        <p className="text-xs text-slate-400">Found in: {exposure.source}</p>
                        <p className="text-xs text-slate-500">{exposure.dateFound}</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Marketplace Monitoring */}
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <ShoppingCart className="h-5 w-5 text-pink-400" />
                  Dark Web Marketplace Intelligence
                </CardTitle>
                <CardDescription>Track listings and trends in underground markets</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-slate-700">
                        <th className="text-left p-3 text-slate-400">Item</th>
                        <th className="text-left p-3 text-slate-400">Category</th>
                        <th className="text-left p-3 text-slate-400">Price</th>
                        <th className="text-left p-3 text-slate-400">Seller</th>
                        <th className="text-left p-3 text-slate-400">Rating</th>
                        <th className="text-left p-3 text-slate-400">Listed</th>
                      </tr>
                    </thead>
                    <tbody>
                      {generateMarketplaceListings().map((listing, idx) => (
                        <tr key={idx} className="border-b border-slate-700/50 hover:bg-slate-700/20">
                          <td className="p-3 font-medium">{listing.item}</td>
                          <td className="p-3">
                            <Badge variant="outline" className="text-xs">{listing.category}</Badge>
                          </td>
                          <td className="p-3 font-mono">{listing.price}</td>
                          <td className="p-3 text-slate-400">{listing.seller}</td>
                          <td className="p-3">
                            <div className="flex items-center gap-1">
                              <Star className="h-3 w-3 text-yellow-400 fill-yellow-400" />
                              <span>{listing.rating}</span>
                            </div>
                          </td>
                          <td className="p-3 text-slate-400 text-xs">{listing.listed}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 mt-12 py-6">
        <div className="container mx-auto px-4 text-center text-slate-400 text-sm">
          <p>NEXUS INTEL Platform v3.0 | OSINT & Threat Intelligence</p>
          <p className="mt-1 text-xs text-slate-500">Classification: CONFIDENTIAL | For Authorized Personnel Only</p>
        </div>
      </footer>
    </div>
  );
}

// Helper functions for generating mock data
function generateLiveEvents() {
  const events = [
    { timestamp: new Date().toISOString().split('T')[1].substring(0, 8), type: 'critical', message: 'Multiple login failures detected from IP 185.220.101.0/24', source: 'Auth Service' },
    { timestamp: new Date(Date.now() - 60000).toISOString().split('T')[1].substring(0, 8), type: 'warning', message: 'Suspicious SQL injection pattern blocked on /api/users endpoint', source: 'WAF' },
    { timestamp: new Date(Date.now() - 120000).toISOString().split('T')[1].substring(0, 8), type: 'info', message: 'New IOC feed updated: 45 indicators added from AlienVault OTX', source: 'TI Pipeline' },
    { timestamp: new Date(Date.now() - 180000).toISOString().split('T')[1].substring(0, 8), type: 'warning', message: 'Certificate expiration warning for api.internal.com in 14 days', source: 'Cert Monitor' },
    { timestamp: new Date(Date.now() - 240000).toISOString().split('T')[1].substring(0, 8), type: 'info', message: 'Scheduled vulnerability scan completed: 3 high, 12 medium findings', source: 'Scanner' },
    { timestamp: new Date(Date.now() - 300000).toISOString().split('T')[1].substring(0, 8), type: 'critical', message: 'Malware sample detected in upload queue - quarantined automatically', source: 'AV Engine' },
    { timestamp: new Date(Date.now() - 360000).toISOString().split('T')[1].substring(0, 8), type: 'info', message: 'User authentication successful: admin@company.com from 192.168.1.100', source: 'Auth Service' },
    { timestamp: new Date(Date.now() - 420000).toISOString().split('T')[1].substring(0, 8), type: 'warning', message: 'Unusual outbound traffic to newly registered domain xyz-temp.tk', source: 'DNS Monitor' },
    { timestamp: new Date(Date.now() - 480000).toISOString().split('T')[1].substring(0, 8), type: 'info', message: 'Backup completed successfully - 847GB transferred to offsite location', source: 'Backup Service' },
    { timestamp: new Date(Date.now() - 540000).toISOString().split('T')[1].substring(0, 8), type: 'warning', message: 'Rate limit threshold exceeded for IP 203.0.113.42 - temporary block applied', source: 'Rate Limiter' },
  ];
  return events.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

function generateDarkWebLeaks() {
  return [
    { company: 'TechCorp Global', description: 'Customer database with PII and payment card data exposed on BreachForums', records: 4500000, dataTypes: ['Email', 'Password', 'Credit Card'], daysAgo: 1 },
    { company: 'HealthFirst Medical', description: 'Patient records including SSN and medical history leaked after ransomware attack', records: 850000, dataTypes: ['SSN', 'Medical', 'PII'], daysAgo: 3 },
    { company: 'FinanceHub Inc.', description: 'Internal documents and client financial data shared on leak site', records: 125000, dataTypes: ['Financial', 'Documents'], daysAgo: 5 },
    { company: 'EduLearn Platform', description: 'Student and faculty credentials dumped on underground forum', records: 230000, dataTypes: ['Email', 'Password Hash'], daysAgo: 7 },
  ];
}

function generateCredentialExposures() {
  return [
    { email: 'john.doe@company.com', severity: 'high', source: 'LinkedIn2024 Dump', dateFound: '2 hours ago' },
    { email: 'sarah.smith@company.com', severity: 'high', source: 'BreachForums Compilation', dateFound: '1 day ago' },
    { email: 'mike.wilson@company.com', severity: 'medium', source: 'Antidata Public Leak', dateFound: '3 days ago' },
    { email: 'admin@company.com', severity: 'high', source: 'DarkWeb Market #7', dateFound: '5 days ago' },
  ];
}

function generateMarketplaceListings() {
  return [
    { item: 'Fortune 500 Email Database (2024)', category: 'Databases', price: '$2,500', seller: 'DataKing99', rating: '4.8/5', listed: '2 hours ago' },
    { item: 'Zero-Day Exploit: Chrome 120', category: 'Exploits', price: '$50,000', seller: 'ZeroDayPro', rating: '5.0/5', listed: '6 hours ago' },
    { item: 'Access Panel - RDP to US Bank', category: 'Access', price: '$350', seller: 'AccessBroker', rating: '4.2/5', listed: '1 day ago' },
    { item: 'Banking Trojan Builder v4.2', category: 'Malware', price: '$800', seller: 'MalDevMaster', rating: '4.6/5', listed: '2 days ago' },
    { item: 'US SSN + DOB Database (10M)', category: 'Databases', price: '$15,000', seller: 'IdentitySeller', rating: '4.9/5', listed: '3 days ago' },
  ];
}

function Star({ className }: { className?: string }) {
  return (
    <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
    </svg>
  );
}

function ShoppingCart({ className }: { className?: string }) {
  return (
    <svg className={className} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="9" cy="21" r="1"></circle>
      <circle cx="20" cy="21" r="1"></circle>
      <path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"></path>
    </svg>
  );
}
