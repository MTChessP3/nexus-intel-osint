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
  RefreshCw, ChevronRight, Eye, Brain, Cpu, Zap,
  Lock, TrendingUp, TrendingDown, ArrowRight, Copy, Loader2, Send
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
  const [aiQuery, setAiQuery] = useState('');
  
  // Result states
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
    loadInitialData();
  }, []);

  // ============= API FUNCTIONS =============
  
  const loadInitialData = async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      // Load threat intelligence
      const threatsRes = await fetch('/api/osint/threats');
      if (threatsRes.ok) {
        const threatsData = await threatsRes.json();
        if (threatsData.success) {
          setThreatData(threatsData.data);
        }
      }

      // Auto-run IP analysis
      const ipRes = await fetch('/api/osint/ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: '8.8.8.8' })
      });
      
      if (ipRes.ok) {
        const ipData = await ipRes.json();
        if (ipData.success) {
          setIpResult(ipData.data);
        }
      }

      // Load recent CVEs
      const cveRes = await fetch('/api/osint/cve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keyword: 'critical vulnerability 2024' })
      });
      
      if (cveRes.ok) {
        const cveData = await cveRes.json();
        if (cveData.success && cveData.data?.results) {
          setCveResults(cveData.data.results.slice(0, 5));
        }
      }

    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const analyzeIP = async () => {
    if (!ipInput.trim()) return;
    setIsLoading(true); setError(null); setSuccess(null);
    
    try {
      const res = await fetch('/api/osint/ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ipInput.trim() })
      });
      
      const data = await res.json();
      
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      if (data.success) {
        setIpResult(data.data);
        setSuccess(`IP ${data.data.query} analyzed - Risk Level: ${data.data.threat.level}`);
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
        setSuccess(`Domain ${data.data.domain} analyzed`);
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
        setSuccess(`Found ${data.data.results?.length || 1} CVE(s)`);
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
        setSuccess(`URL analyzed - Risk: ${data.data.overallAssessment.riskLevel}`);
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
        setSuccess(`Hash analysis complete`);
      } else throw new Error(data.error);
    } catch (err: any) { setError(err.message); }
    setIsLoading(false);
  };

  const runAIAnalysis = async () => {
    if (!aiQuery.trim()) return;
    setIsLoading(true); setError(null);
    
    try {
      const res = await fetch('/api/osint/ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: aiQuery.trim(), context: threatData })
      });
      const data = await res.json();
      if (data.success) {
        setAiAnalysis(data.data);
        setSuccess('AI Analysis completed');
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
        body: JSON.stringify({ reportType: type, data: { threatData, ipResult, cveResults } })
      });
      const data = await res.json();
      if (data.success) {
        setReportData(data.data.report);
        setSuccess(`${type} report generated`);
      } else throw new Error(data.error);
    } catch (err: any) { setError(err.message); }
    setIsLoading(false);
  };

  // ============= RENDER HELPERS =============
  
  const getThreatColor = (level: string) => {
    switch(level?.toUpperCase()) {
      case 'CRITICAL': case 'CRÍTICO': return 'text-red-400 bg-red-950 border-red-800';
      case 'HIGH': case 'ALTO': case 'ALTO RIESGO': case 'PELIGROSO': return 'text-orange-400 bg-orange-950 border-orange-800';
      case 'MEDIUM': case 'MEDIO': case 'SOSPECHOSO': case 'CAUTELA': return 'text-yellow-400 bg-yellow-950 border-yellow-800';
      case 'LOW': case 'BAJO': case 'SEGURO': case 'ACEPTABLE': return 'text-green-400 bg-green-950 border-green-800';
      default: return 'text-gray-400 bg-gray-900 border-gray-700';
    }
  };

  const formatTimestamp = (ts: string) => {
    if (!ts) return 'N/A';
    return new Date(ts).toLocaleString();
  };

  // ============= DASHBOARD TAB =============
  const renderDashboard = () => (
    <div className="space-y-6">
      {/* Header Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-gray-900/50 border-gray-800">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">Threat Level</p>
                <p className={`text-2xl font-bold mt-1 ${getThreatColor(threatData?.globalThreatLevel?.level).split(' ')[0]}`}>
                  {threatData?.globalThreatLevel?.level || 'LOADING'}
                </p>
              </div>
              <div className={`p-3 rounded-lg ${getThreatColor(threatData?.globalThreatLevel?.level)}`}>
                <Shield className="h-5 w-5" />
              </div>
            </div>
            <div className="mt-3">
              <div className="flex justify-between text-xs text-gray-500 mb-1">
                <span>Score</span>
                <span>{threatData?.globalThreatLevel?.score || 0}/100</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-1.5">
                <div 
                  className="h-1.5 rounded-full" 
                  style={{ 
                    width: `${threatData?.globalThreatLevel?.score || 0}%`,
                    backgroundColor: threatData?.globalThreatLevel?.color || '#6b7280'
                  }}
                />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gray-900/50 border-gray-800">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">Active IOCs</p>
                <p className="text-2xl font-bold mt-1 text-white">{threatData?.iocs?.length || 0}</p>
              </div>
              <div className="p-3 rounded-lg bg-blue-950 text-blue-400 border border-blue-800">
                <Fingerprint className="h-5 w-5" />
              </div>
            </div>
            <p className="text-xs text-gray-500 mt-3">Monitored indicators</p>
          </CardContent>
        </Card>

        <Card className="bg-gray-900/50 border-gray-800">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">Critical CVEs</p>
                <p className="text-2xl font-bold mt-1 text-red-400">{threatData?.statistics?.threatsBySeverity?.CRITICAL || 0}</p>
              </div>
              <div className="p-3 rounded-lg bg-red-950 text-red-400 border border-red-800">
                <Bug className="h-5 w-5" />
              </div>
            </div>
            <p className="text-xs text-gray-500 mt-3">CVSS &gt;= 9.0</p>
          </CardContent>
        </Card>

        <Card className="bg-gray-900/50 border-gray-800">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">Active Campaigns</p>
                <p className="text-2xl font-bold mt-1 text-orange-400">{threatData?.campaigns?.filter((c: any) => c.status === 'ACTIVE').length || 0}</p>
              </div>
              <div className="p-3 rounded-lg bg-orange-950 text-orange-400 border border-orange-800">
                <Target className="h-5 w-5" />
              </div>
            </div>
            <p className="text-xs text-gray-500 mt-3">Ongoing threats</p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Threats */}
        <Card className="bg-gray-900/30 border-gray-800 lg:col-span-2">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                Recent Critical Vulnerabilities
              </CardTitle>
              <Button variant="ghost" size="sm" className="text-gray-500 hover:text-white h-8" onClick={() => setActiveTab('cve')}>
                View All <ChevronRight className="h-4 w-4 ml-1" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {(threatData?.activeThreats || []).slice(0, 5).map((threat: any, idx: number) => (
                <div key={idx} className="flex items-start gap-3 p-3 rounded-lg bg-gray-900/50 border border-gray-800 hover:border-gray-700 transition-colors">
                  <div className={`px-2 py-1 rounded text-xs font-mono font-medium ${getThreatColor(threat.severity)}`}>
                    {threat.severity}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-200 font-mono">{threat.id}</p>
                    <p className="text-xs text-gray-500 mt-1 line-clamp-2">{threat.description}</p>
                  </div>
                  <div className="text-xs text-gray-600 whitespace-nowrap">
                    CVSS {threat.cvssScore || 'N/A'}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Active Campaigns */}
        <Card className="bg-gray-900/30 border-gray-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
              <Target className="h-4 w-4 text-red-500" />
              Active Campaigns
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {(threatData?.campaigns || []).filter((c: any) => c.status === 'ACTIVE').map((campaign: any, idx: number) => (
                <div key={idx} className="p-3 rounded-lg bg-gray-900/50 border border-gray-800">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono text-gray-400">{campaign.id}</span>
                    <Badge variant="outline" className="text-xs text-red-400 border-red-800 bg-red-950">
                      {campaign.severity}
                    </Badge>
                  </div>
                  <p className="text-sm font-medium text-gray-200">{campaign.name}</p>
                  <p className="text-xs text-gray-500 mt-1 line-clamp-2">{campaign.description}</p>
                  <div className="flex items-center gap-2 mt-2 text-xs text-gray-600">
                    <span>IOCs: {campaign.indicators}</span>
                    <span>•</span>
                    <span>{campaign.targetSectors?.[0]}</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* APT Groups & IOC Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* APT Groups */}
        <Card className="bg-gray-900/30 border-gray-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
              <Brain className="h-4 w-4 text-purple-500" />
              APT Groups Tracked
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {(threatData?.aptGroups || []).map((apt: any, idx: number) => (
                <div key={idx} className="flex items-center justify-between p-3 rounded-lg bg-gray-900/50 border border-gray-800">
                  <div className="flex items-center gap-3">
                    <div className={`w-2 h-2 rounded-full ${apt.status === 'ACTIVE' ? 'bg-red-500' : 'bg-gray-600'}`} />
                    <div>
                      <p className="text-sm font-medium text-gray-200">{apt.name}</p>
                      <p className="text-xs text-gray-500">{apt.country} • {apt.attributionConfidence} confidence</p>
                    </div>
                  </div>
                  <Badge variant="outline" className={apt.status === 'ACTIVE' ? 'text-red-400 border-red-800' : 'text-gray-500 border-gray-700'}>
                    {apt.status}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* IOC Types Breakdown */}
        <Card className="bg-gray-900/30 border-gray-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
              <Database className="h-4 w-4 text-cyan-500" />
              IOC Distribution
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {Object.entries(threatData?.statistics?.iocByType || {}).map(([type, count]: [string, any]) => (
                <div key={type} className="flex items-center justify-between">
                  <span className="text-sm text-gray-400 uppercase">{type}</span>
                  <div className="flex items-center gap-3">
                    <div className="w-24 bg-gray-800 rounded-full h-2">
                      <div 
                        className="h-2 rounded-full bg-cyan-600"
                        style={{ width: `${(count / (threatData?.statistics?.totalIOCs || 1)) * 100}%` }}
                      />
                    </div>
                    <span className="text-sm font-mono text-gray-300 w-8 text-right">{count}</span>
                  </div>
                </div>
              ))}
            </div>
            
            <Separator className="my-4 bg-gray-800" />
            
            <div className="grid grid-cols-2 gap-3">
              {Object.entries(threatData?.statistics?.iocByThreatLevel || {}).map(([level, count]: [string, any]) => (
                <div key={level} className="p-2 rounded bg-gray-900/50 border border-gray-800">
                  <p className="text-xs text-gray-500 uppercase">{level}</p>
                  <p className="text-lg font-bold text-gray-200">{count}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );

  // ============= IP INTEL TAB =============
  const renderIPIntel = () => (
    <div className="space-y-6">
      {/* IP Input */}
      <Card className="bg-gray-900/30 border-gray-800">
        <CardContent className="p-4">
          <div className="flex gap-3">
            <Input
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              placeholder="Enter IP address (e.g., 8.8.8.8)"
              className="bg-gray-900 border-gray-700 text-white placeholder-gray-500 font-mono"
              onKeyDown={(e) => e.key === 'Enter' && analyzeIP()}
            />
            <Button onClick={analyzeIP} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700 text-white">
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              Analyze
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* IP Results */}
      {ipResult && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Geolocation */}
          <Card className="bg-gray-900/30 border-gray-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
                <MapPin className="h-4 w-4 text-green-500" />
                Geolocation Data
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex justify-between items-center py-2 border-b border-gray-800">
                  <span className="text-sm text-gray-500">IP Address</span>
                  <span className="font-mono text-sm text-white">{ipResult.query}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-gray-800">
                  <span className="text-sm text-gray-500">Country</span>
                  <span className="text-sm text-white">{ipResult.geolocation.country}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-gray-800">
                  <span className="text-sm text-gray-500">Region / City</span>
                  <span className="text-sm text-white">{ipResult.geolocation.region}, {ipResult.geolocation.city}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-gray-800">
                  <span className="text-sm text-gray-500">Coordinates</span>
                  <span className="font-mono text-sm text-white">{ipResult.geolocation.latitude}, {ipResult.geolocation.longitude}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-gray-800">
                  <span className="text-sm text-gray-500">Timezone</span>
                  <span className="text-sm text-white">{ipResult.geolocation.timezone}</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Network Info */}
          <Card className="bg-gray-900/30 border-gray-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
                <Server className="h-4 w-4 text-blue-500" />
                Network Information
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex justify-between items-center py-2 border-b border-gray-800">
                  <span className="text-sm text-gray-500">ISP</span>
                  <span className="text-sm text-white">{ipResult.network.isp}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-gray-800">
                  <span className="text-sm text-gray-500">Organization</span>
                  <span className="text-sm text-white">{ipResult.network.org}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-gray-800">
                  <span className="text-sm text-gray-500">ASN</span>
                  <span className="font-mono text-sm text-white">{ipResult.network.asn}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-gray-800">
                  <span className="text-sm text-gray-500">Mobile</span>
                  <span className="text-sm text-white">{ipResult.network.isMobile ? 'Yes' : 'No'}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-gray-800">
                  <span className="text-sm text-gray-500">Proxy/VPN</span>
                  <span className="text-sm text-white">{ipResult.network.isProxy ? 'Detected' : 'None'}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-gray-800">
                  <span className="text-sm text-gray-500">Hosting</span>
                  <span className="text-sm text-white">{ipResult.network.isHosting ? 'Data Center' : 'Residential'}</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Threat Assessment */}
          <Card className="bg-gray-900/30 border-gray-800 lg:col-span-2">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
                <Shield className="h-4 w-4 text-red-500" />
                Threat Assessment
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Score Gauge */}
                <div className="text-center">
                  <div className={`inline-flex items-center justify-center w-24 h-24 rounded-full border-4 ${getThreatColor(ipResult.threat.level)}`}>
                    <div>
                      <p className="text-2xl font-bold text-white">{ipResult.threat.score}</p>
                      <p className="text-xs text-gray-400">/100</p>
                    </div>
                  </div>
                  <p className="mt-2 text-sm font-medium text-gray-300">{ipResult.threat.level}</p>
                </div>

                {/* Indicators */}
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Indicators</p>
                  <div className="space-y-1">
                    {ipResult.threat.indicators.map((indicator: string, idx: number) => (
                      <p key={idx} className="text-sm text-gray-300 flex items-start gap-2">
                        <span className="mt-1.5 w-1 h-1 rounded-full bg-gray-500 shrink-0" />
                        {indicator}
                      </p>
                    ))}
                  </div>
                </div>

                {/* Recommendations */}
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Recommendations</p>
                  <div className="space-y-1">
                    {ipResult.threat.recommendations.map((rec: string, idx: number) => (
                      <p key={idx} className="text-sm text-gray-300 flex items-start gap-2">
                        <ArrowRight className="h-3 w-3 mt-1 text-blue-500 shrink-0" />
                        {rec}
                      </p>
                    ))}
                  </div>
                </div>
              </div>

              <Separator className="my-4 bg-gray-800" />

              <div className="flex items-center justify-between text-xs text-gray-600">
                <span>Source: {ipResult.metadata.source}</span>
                <span>Analyzed: {formatTimestamp(ipResult.metadata.analyzedAt)}</span>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );

  // ============= DOMAIN TAB =============
  const renderDomain = () => (
    <div className="space-y-6">
      <Card className="bg-gray-900/30 border-gray-800">
        <CardContent className="p-4">
          <div className="flex gap-3">
            <Input
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              placeholder="Enter domain (e.g., google.com)"
              className="bg-gray-900 border-gray-700 text-white placeholder-gray-500 font-mono"
              onKeyDown={(e) => e.key === 'Enter' && analyzeDomain()}
            />
            <Button onClick={analyzeDomain} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700 text-white">
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Globe className="h-4 w-4" />}
              Analyze
            </Button>
          </div>
        </CardContent>
      </Card>

      {domainResult && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Reputation Score */}
          <Card className="bg-gray-900/30 border-gray-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-300">Reputation Assessment</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-center mb-4">
                <div className={`inline-flex items-center justify-center w-28 h-28 rounded-full border-4 ${getThreatColor(domainResult.reputation.level)}`}>
                  <div>
                    <p className="text-3xl font-bold text-white">{domainResult.reputation.score}</p>
                    <p className="text-xs text-gray-400">/100</p>
                  </div>
                </div>
                <p className="mt-2 text-lg font-medium text-gray-300">{domainResult.reputation.level}</p>
              </div>
              
              <div className="space-y-2">
                <p className="text-xs text-gray-500 uppercase tracking-wider">Indicators</p>
                {domainResult.reputation.indicators.map((ind: string, idx: number) => (
                  <p key={idx} className="text-sm text-gray-300 flex items-start gap-2">
                    <span className="mt-1.5 w-1 h-1 rounded-full bg-gray-500 shrink-0" />
                    {ind}
                  </p>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* DNS Records */}
          <Card className="bg-gray-900/30 border-gray-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
                <Server className="h-4 w-4" />
                DNS Records
              </CardTitle>
            </CardHeader>
            <CardContent>
              {domainResult.dns?.status === 'OK' ? (
                <div className="space-y-3">
                  <div>
                    <p className="text-xs text-gray-500 mb-1">A Records</p>
                    <div className="flex flex-wrap gap-1">
                      {domainResult.dns.aRecords?.map((r: string, idx: number) => (
                        <Badge key={idx} variant="outline" className="font-mono text-xs text-green-400 border-green-900 bg-green-950">
                          {r}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs text-gray-500 mb-1">MX Records</p>
                    <div className="flex flex-wrap gap-1">
                      {domainResult.dns.mxRecords?.map((r: string, idx: number) => (
                        <Badge key={idx} variant="outline" className="font-mono text-xs text-blue-400 border-blue-900 bg-blue-950">
                          {r}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs text-gray-500 mb-1">NS Records</p>
                    <div className="flex flex-wrap gap-1">
                      {domainResult.dns.nsRecords?.map((r: string, idx: number) => (
                        <Badge key={idx} variant="outline" className="font-mono text-xs text-purple-400 border-purple-900 bg-purple-950">
                          {r}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div className="flex gap-4 mt-3 pt-3 border-t border-gray-800">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${domainResult.dns.hasSPF ? 'bg-green-500' : 'bg-red-500'}`} />
                      <span className="text-xs text-gray-400">SPF: {domainResult.dns.hasSPF ? 'Configured' : 'Missing'}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${domainResult.dns.hasDMARC ? 'bg-green-500' : 'bg-red-500'}`} />
                      <span className="text-xs text-gray-400">DMARC: {domainResult.dns.hasDMARC ? 'Configured' : 'Missing'}</span>
                    </div>
                  </div>
                </div>
              ) : (
                <p className="text-sm text-gray-500">DNS lookup failed or unavailable</p>
              )}
            </CardContent>
          </Card>

          {/* WHOIS & Security */}
          <Card className="bg-gray-900/30 border-gray-800 lg:col-span-2">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
                <FileText className="h-4 w-4" />
                WHOIS & Security Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">WHOIS Information</p>
                  <div className="space-y-2">
                    <div className="flex justify-between py-1 border-b border-gray-800">
                      <span className="text-sm text-gray-500">Registrar</span>
                      <span className="text-sm text-white">{domainResult.whois?.registrar || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-gray-800">
                      <span className="text-sm text-gray-500">Created</span>
                      <span className="text-sm text-white">{domainResult.whois?.creationDate || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-gray-800">
                      <span className="text-sm text-gray-500">Expires</span>
                      <span className="text-sm text-white">{domainResult.whois?.expiryDate || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-gray-800">
                      <span className="text-sm text-gray-500">Age (days)</span>
                      <span className="text-sm text-white">{domainResult.whois?.ageDays || 'N/A'}</span>
                    </div>
                  </div>
                </div>
                
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">Security Checks</p>
                  <div className="space-y-2">
                    {domainResult.security?.riskFactors?.map((risk: string, idx: number) => (
                      <div key={idx} className="flex items-start gap-2 p-2 rounded bg-gray-900/50">
                        <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5 shrink-0" />
                        <span className="text-sm text-gray-300">{risk}</span>
                      </div>
                    )) || <p className="text-sm text-gray-500">No security issues detected</p>}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );

  // ============= CVE TAB =============
  const renderCVE = () => (
    <div className="space-y-6">
      <Card className="bg-gray-900/30 border-gray-800">
        <CardContent className="p-4">
          <div className="flex gap-3">
            <Input
              value={cveInput}
              onChange={(e) => setCveInput(e.target.value)}
              placeholder="Enter CVE ID (e.g., CVE-2024-3400) or keyword"
              className="bg-gray-900 border-gray-700 text-white placeholder-gray-500 font-mono"
              onKeyDown={(e) => e.key === 'Enter' && searchCVE()}
            />
            <Button onClick={searchCVE} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700 text-white">
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Bug className="h-4 w-4" />}
              Search
            </Button>
          </div>
        </CardContent>
      </Card>

      {cveResults.length > 0 && (
        <div className="space-y-3">
          {cveResults.map((cve, idx) => (
            <Card key={idx} className="bg-gray-900/30 border-gray-800">
              <CardContent className="p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <span className="font-mono font-semibold text-white">{cve.id}</span>
                      <Badge variant="outline" className={`${getThreatColor(cve.cvss?.severity)}`}>
                        {cve.cvss?.severity || 'UNKNOWN'}
                      </Badge>
                      <Badge variant="outline" className="text-gray-400 border-gray-700">
                        {cve.status}
                      </Badge>
                    </div>
                    <p className="text-sm text-gray-400 mb-3">{cve.descriptions}</p>
                    
                    {cve.cvss?.score && (
                      <div className="flex items-center gap-4 mb-3">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-gray-500">CVSS:</span>
                          <span className="font-mono font-bold text-white">{cve.cvss.score}</span>
                          <span className="text-xs text-gray-500">v{cve.cvss.version}</span>
                        </div>
                        {cve.cvss.vector && (
                          <span className="font-mono text-xs text-gray-500 truncate max-w-md">
                            {cve.cvss.vector}
                          </span>
                        )}
                      </div>
                    )}

                    {cve.cwe && cve.cwe.length > 0 && (
                      <div className="flex flex-wrap gap-1 mb-3">
                        {cve.cwe.map((cwe: string, cidx: number) => (
                          <Badge key={cidx} variant="outline" className="text-xs text-purple-400 border-purple-900 bg-purple-950">
                            {cwe}
                          </Badge>
                        ))}
                      </div>
                    )}

                    <div className="flex items-center gap-4 text-xs text-gray-600">
                      <span>Published: {cve.dates?.published ? formatTimestamp(cve.dates.published) : 'N/A'}</span>
                      {cve.dates?.daysSincePublished !== null && (
                        <span>({cve.dates.daysSincePublished} days ago)</span>
                      )}
                    </div>
                  </div>

                  {cve.references && cve.references.length > 0 && (
                    <div className="shrink-0">
                      <p className="text-xs text-gray-500 mb-1">References ({cve.references.length})</p>
                      <div className="space-y-1 max-h-20 overflow-hidden">
                        {cve.references.slice(0, 2).map((ref: any, ridx: number) => (
                          <a key={ridx} href={ref.url} target="_blank" rel="noopener" className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 truncate max-w-[200px]">
                            <ExternalLink className="h-3 w-3 shrink-0" />
                            {new URL(ref.url).hostname}
                          </a>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );

  // ============= AI ENGINE TAB =============
  const renderAIEngine = () => (
    <div className="space-y-6">
      <Card className="bg-gray-900/30 border-gray-800">
        <CardContent className="p-4">
          <div className="flex gap-3">
            <Input
              value={aiQuery}
              onChange={(e) => setAiQuery(e.target.value)}
              placeholder="Ask about threats, CVEs, APT groups, ransomware..."
              className="bg-gray-900 border-gray-700 text-white placeholder-gray-500"
              onKeyDown={(e) => e.key === 'Enter' && runAIAnalysis()}
            />
            <Button onClick={runAIAnalysis} disabled={isLoading} className="bg-purple-600 hover:bg-purple-700 text-white">
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Brain className="h-4 w-4" />}
              Analyze
            </Button>
          </div>
        </CardContent>
      </Card>

      {aiAnalysis && (
        <Card className="bg-gray-900/30 border-gray-800">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
                <Cpu className="h-4 w-4 text-purple-500" />
                AI Analysis Results
              </CardTitle>
              <Badge variant="outline" className="text-xs">
                Confidence: {aiAnalysis.confidence}%
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="prose prose-invert max-w-none">
              <div className="whitespace-pre-wrap text-sm text-gray-300 leading-relaxed">
                {aiAnalysis.fullResponse}
              </div>
            </div>
            
            {aiAnalysis.keyFindings && (
              <>
                <Separator className="my-4 bg-gray-800" />
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Key Findings</p>
                  <div className="space-y-1">
                    {aiAnalysis.keyFindings.map((finding: string, idx: number) => (
                      <p key={idx} className="text-sm text-gray-300 flex items-start gap-2">
                        <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                        {finding}
                      </p>
                    ))}
                  </div>
                </div>
              </>
            )}

            {aiAnalysis.recommendations && (
              <>
                <Separator className="my-4 bg-gray-800" />
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Recommendations</p>
                  <div className="space-y-1">
                    {aiAnalysis.recommendations.map((rec: string, idx: number) => (
                      <p key={idx} className="text-sm text-gray-300 flex items-start gap-2">
                        <Zap className="h-4 w-4 text-yellow-500 mt-0.5 shrink-0" />
                        {rec}
                      </p>
                    ))}
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );

  // ============= REPORTS TAB =============
  const renderReports = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-gray-900/30 border-gray-800 cursor-pointer hover:border-gray-700 transition-colors" onClick={() => generateReport('executive-summary')}>
          <CardContent className="p-4 text-center">
            <FileText className="h-8 w-8 mx-auto mb-2 text-blue-500" />
            <p className="font-medium text-white">Executive Summary</p>
            <p className="text-xs text-gray-500 mt-1">C-suite briefing document</p>
          </CardContent>
        </Card>
        
        <Card className="bg-gray-900/30 border-gray-800 cursor-pointer hover:border-gray-700 transition-colors" onClick={() => generateReport('threat-briefing')}>
          <CardContent className="p-4 text-center">
            <Shield className="h-8 w-8 mx-auto mb-2 text-red-500" />
            <p className="font-medium text-white">Threat Briefing</p>
            <p className="text-xs text-gray-500 mt-1">IOC and campaign report</p>
          </CardContent>
        </Card>
        
        <Card className="bg-gray-900/30 border-gray-800 cursor-pointer hover:border-gray-700 transition-colors" onClick={() => generateReport('full-assessment')}>
          <CardContent className="p-4 text-center">
            <BarChart3 className="h-8 w-8 mx-auto mb-2 text-green-500" />
            <p className="font-medium text-white">Full Assessment</p>
            <p className="text-xs text-gray-500 mt-1">Complete security posture</p>
          </CardContent>
        </Card>
      </div>

      {reportData && (
        <Card className="bg-gray-900/30 border-gray-800">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">{reportData.title}</CardTitle>
              <Button variant="outline" size="sm" className="text-xs border-gray-700 text-gray-400 hover:text-white">
                <Download className="h-3 w-3 mr-1" />
                Export PDF
              </Button>
            </div>
            <p className="text-xs text-gray-500 mt-1">{reportData.subtitle}</p>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-[600px] pr-4">
              <div className="space-y-4">
                {/* Executive Brief */}
                {reportData.executiveBrief && (
                  <div className="p-4 rounded-lg bg-gray-900/50 border border-gray-800">
                    <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Executive Overview</p>
                    <p className="text-sm text-gray-300 leading-relaxed">{reportData.executiveBrief.overview}</p>
                    
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
                      <div className="p-2 rounded bg-gray-900 border border-gray-800">
                        <p className="text-xs text-gray-500">Threat Level</p>
                        <p className="font-bold text-white">{reportData.executiveBrief.keyMetrics?.globalThreatLevel?.level}</p>
                      </div>
                      <div className="p-2 rounded bg-gray-900 border border-gray-800">
                        <p className="text-xs text-gray-500">Vulnerabilities</p>
                        <p className="font-bold text-white">{reportData.executiveBrief.keyMetrics?.activeVulnerabilities || 0}</p>
                      </div>
                      <div className="p-2 rounded bg-gray-900 border border-gray-800">
                        <p className="text-xs text-gray-500">Campaigns</p>
                        <p className="font-bold text-white">{reportData.executiveBrief.keyMetrics?.activeCampaigns || 0}</p>
                      </div>
                      <div className="p-2 rounded bg-gray-900 border border-gray-800">
                        <p className="text-xs text-gray-500">IOCs Monitored</p>
                        <p className="font-bold text-white">{reportData.executiveBrief.keyMetrics?.monitoredIOCs || 0}</p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Strategic Recommendations */}
                {reportData.strategicRecommendations && (
                  <div className="p-4 rounded-lg bg-gray-900/50 border border-gray-800">
                    <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">Strategic Recommendations</p>
                    <div className="space-y-3">
                      {reportData.strategicRecommendations.map((rec: any, idx: number) => (
                        <div key={idx} className="flex gap-3 p-3 rounded bg-gray-900/80 border border-gray-800">
                          <div className="shrink-0 w-6 h-6 rounded-full bg-blue-900 text-blue-400 flex items-center justify-center text-xs font-bold">
                            {rec.priority}
                          </div>
                          <div className="flex-1">
                            <p className="text-sm font-medium text-white">{rec.title}</p>
                            <p className="text-xs text-gray-400 mt-1">{rec.description}</p>
                            <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                              <span>Owner: {rec.owner}</span>
                              <span>Timeline: {rec.timeline}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );

  // ============= URL ANALYSIS TAB =============
  const renderURLAnalysis = () => (
    <div className="space-y-6">
      <Card className="bg-gray-900/30 border-gray-800">
        <CardContent className="p-4">
          <div className="flex gap-3">
            <Input
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter URL to analyze (e.g., https://example.com/page)"
              className="bg-gray-900 border-gray-700 text-white placeholder-gray-500 font-mono"
              onKeyDown={(e) => e.key === 'Enter' && analyzeURL()}
            />
            <Button onClick={analyzeURL} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700 text-white">
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Link className="h-4 w-4" />}
              Analyze
            </Button>
          </div>
        </CardContent>
      </Card>

      {urlResult && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="bg-gray-900/30 border-gray-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-300">URL Components</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <div className="flex justify-between py-1 border-b border-gray-800">
                  <span className="text-sm text-gray-500">Protocol</span>
                  <span className="font-mono text-sm text-white">{urlResult.parsedUrl.protocol}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-gray-800">
                  <span className="text-sm text-gray-500">Hostname</span>
                  <span className="font-mono text-sm text-white">{urlResult.parsedUrl.hostname}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-gray-800">
                  <span className="text-sm text-gray-500">Port</span>
                  <span className="font-mono text-sm text-white">{urlResult.parsedUrl.port}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-gray-800">
                  <span className="text-sm text-gray-500">Path</span>
                  <span className="font-mono text-sm text-white truncate max-w-[200px]">{urlResult.parsedUrl.path || '/'}</span>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gray-900/30 border-gray-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-gray-300">Overall Assessment</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-center mb-4">
                <div className={`inline-flex items-center justify-center w-24 h-24 rounded-full border-4 ${getThreatColor(urlResult.overallAssessment.riskLevel)}`}>
                  <div>
                    <p className="text-2xl font-bold text-white">{urlResult.overallAssessment.threatScore}</p>
                    <p className="text-xs text-gray-400">/100</p>
                  </div>
                </div>
                <p className="mt-2 text-sm font-medium text-gray-300">{urlResult.overallAssessment.riskLevel}</p>
                <p className="text-xs text-gray-500 mt-1">{urlResult.overallAssessment.verdict}</p>
              </div>
              
              <div className="space-y-2">
                <p className="text-xs text-gray-500 uppercase tracking-wider">Indicators</p>
                {urlResult.overallAssessment.indicators.map((ind: string, idx: number) => (
                  <p key={idx} className="text-sm text-gray-300 flex items-start gap-2">
                    <span className="mt-1.5 w-1 h-1 rounded-full bg-gray-500 shrink-0" />
                    {ind}
                  </p>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );

  // ============= HASH LOOKUP TAB =============
  const renderHashLookup = () => (
    <div className="space-y-6">
      <Card className="bg-gray-900/30 border-gray-800">
        <CardContent className="p-4">
          <div className="flex gap-3">
            <Input
              value={hashInput}
              onChange={(e) => setHashInput(e.target.value)}
              placeholder="Enter MD5, SHA1, or SHA256 hash"
              className="bg-gray-900 border-gray-700 text-white placeholder-gray-500 font-mono"
              onKeyDown={(e) => e.key === 'Enter' && analyzeHash()}
            />
            <Button onClick={analyzeHash} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700 text-white">
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Hash className="h-4 w-4" />}
              Lookup
            </Button>
          </div>
        </CardContent>
      </Card>

      {hashResult && (
        <Card className="bg-gray-900/30 border-gray-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
              <Fingerprint className="h-4 w-4" />
              Hash Analysis Results
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <p className="text-xs text-gray-500 mb-2">Input Hash</p>
                <div className="p-3 rounded bg-gray-900 border border-gray-800">
                  <p className="font-mono text-sm text-white break-all">{hashResult.input.hash}</p>
                  <p className="text-xs text-gray-500 mt-1">Type: {hashResult.input.hashType.toUpperCase()}</p>
                </div>
              </div>
              
              <div>
                <p className="text-xs text-gray-500 mb-2">Detection Status</p>
                <div className="flex items-center gap-3">
                  <div className={`px-3 py-2 rounded ${getThreatColor(hashResult.aggregateResults.threatLevel)}`}>
                    <p className="font-bold">{hashResult.aggregateResults.threatLevel}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">Detection Rate</p>
                    <p className="font-mono text-xl font-bold text-white">{hashResult.aggregateResults.detectionRate}%</p>
                  </div>
                </div>
              </div>
            </div>

            {hashResult.found && hashResult.details && (
              <>
                <Separator className="my-4 bg-gray-800" />
                <div>
                  <p className="text-xs text-gray-500 mb-2">Details</p>
                  <div className="p-3 rounded bg-gray-900/50 border border-gray-800 space-y-2">
                    <p className="text-sm"><span className="text-gray-500">Name:</span> <span className="text-white">{hashResult.details.name}</span></p>
                    <p className="text-sm"><span className="text-gray-500">Type:</span> <span className="text-white">{hashResult.details.type}</span></p>
                    <p className="text-sm"><span className="text-gray-500">Description:</span> <span className="text-gray-300">{hashResult.details.description}</span></p>
                  </div>
                </div>
              </>
            )}

            {!hashResult.found && (
              <div className="mt-4 p-4 rounded bg-gray-900/50 border border-gray-800 text-center">
                <CheckCircle2 className="h-8 w-8 mx-auto text-green-500 mb-2" />
                <p className="text-sm text-gray-300">Hash not found in any malware database</p>
                <p className="text-xs text-gray-500 mt-1">This file may be clean or not yet analyzed</p>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );

  // ============= MAIN RENDER =============
  return (
    <div className="min-h-screen bg-black text-white">
      {/* Header */}
      <header className="border-b border-gray-800 bg-black/95 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-600 to-cyan-600 flex items-center justify-center">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-white tracking-tight">NEXUS INTEL</h1>
                <p className="text-xs text-gray-500">OSINT Threat Intelligence Platform</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {error && (
                <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded bg-red-950 border border-red-800 text-red-400 text-xs">
                  <XCircle className="h-3 w-3" />
                  {error.substring(0, 50)}...
                </div>
              )}
              {success && (
                <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded bg-green-950 border border-green-800 text-green-400 text-xs">
                  <CheckCircle2 className="h-3 w-3" />
                  {success.substring(0, 60)}...
                </div>
              )}
              <Button 
                variant="ghost" 
                size="sm" 
                onClick={loadInitialData}
                disabled={isLoading}
                className="text-gray-400 hover:text-white"
              >
                <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-6">
        {/* Status Messages (Mobile) */}
        {error && (
          <div className="md:hidden mb-4 flex items-center gap-2 px-3 py-2 rounded bg-red-950 border border-red-800 text-red-400 text-sm">
            <XCircle className="h-4 w-4" />
            {error}
          </div>
        )}
        {success && (
          <div className="md:hidden mb-4 flex items-center gap-2 px-3 py-2 rounded bg-green-950 border border-green-800 text-green-400 text-sm">
            <CheckCircle2 className="h-4 w-4" />
            {success}
          </div>
        )}

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="bg-gray-900/50 border border-gray-800 w-full justify-start overflow-x-auto">
            <TabsTrigger value="dashboard" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white text-gray-400 text-xs px-3">
              Dashboard
            </TabsTrigger>
            <TabsTrigger value="ip" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white text-gray-400 text-xs px-3">
              IP Intel
            </TabsTrigger>
            <TabsTrigger value="domain" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white text-gray-400 text-xs px-3">
              Domain
            </TabsTrigger>
            <TabsTrigger value="cve" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white text-gray-400 text-xs px-3">
              CVE Search
            </TabsTrigger>
            <TabsTrigger value="url" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white text-gray-400 text-xs px-3">
              URL Analysis
            </TabsTrigger>
            <TabsTrigger value="hash" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white text-gray-400 text-xs px-3">
              Hash Lookup
            </TabsTrigger>
            <TabsTrigger value="ai" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white text-gray-400 text-xs px-3">
              AI Engine
            </TabsTrigger>
            <TabsTrigger value="reports" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white text-gray-400 text-xs px-3">
              Reports
            </TabsTrigger>
          </TabsList>

          {/* Tab Contents */}
          <TabsContent value="dashboard">{renderDashboard()}</TabsContent>
          <TabsContent value="ip">{renderIPIntel()}</TabsContent>
          <TabsContent value="domain">{renderDomain()}</TabsContent>
          <TabsContent value="cve">{renderCVE()}</TabsContent>
          <TabsContent value="url">{renderURLAnalysis()}</TabsContent>
          <TabsContent value="hash">{renderHashLookup()}</TabsContent>
          <TabsContent value="ai">{renderAIEngine()}</TabsContent>
          <TabsContent value="reports">{renderReports()}</TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 mt-12 py-6">
        <div className="container mx-auto px-4">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4 text-xs text-gray-600">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4" />
              <span>NEXUS INTEL OSINT Platform v4.0</span>
            </div>
            <div className="flex items-center gap-4">
              <span>Data sources: NIST NVD, ip-api.com, Google DNS</span>
              <span>•</span>
              <span>Classification: UNCLASSIFIED</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
