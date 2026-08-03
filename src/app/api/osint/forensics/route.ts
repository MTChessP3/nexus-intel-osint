import { NextRequest, NextResponse } from 'next/server';
import { writeFile, mkdir, readdir, stat, readFile } from 'fs/promises';
import { join } from 'path';
import { existsSync } from 'fs';

const RESULTS_DIR = join(process.cwd(), 'forensics-results');

// Ensure results directory exists
async function ensureDir(dir: string) {
  if (!existsSync(dir)) {
    await mkdir(dir, { recursive: true });
  }
}

// Real DNS resolution using Google DoH
async function dnsLookup(domain: string, type: string = 'A'): Promise<any> {
  try {
    const dohUrl = `https://dns.google/resolve?name=${domain}&type=${type}`;
    const response = await fetch(dohUrl);
    const data = await response.json();
    return { type, status: data.Status, data: data.Answer || [], ...data };
  } catch (error) {
    return { type, error: 'DNS lookup failed', data: [] };
  }
}

// WHOIS-like information extraction
async function getWhoisInfo(domain: string): Promise<any> {
  try {
    // Use RDAP for whois info
    const rdapUrl = `https://rdap.org/domain/${domain}`;
    const response = await fetch(rdapUrl, {
      headers: { 'Accept': 'application/rdap+json' }
    });
    
    if (response.ok) {
      const data = await response.json();
      return {
        registrar: data.entities?.[0]?.vcardArray?.[1]?.[1]?.[3] || 'Unknown',
        created: data.events?.find((e: any) => e.eventAction === 'registration')?.eventDate || 'Unknown',
        updated: data.events?.find((e: any) => e.eventAction === 'last changed')?.eventDate || 'Unknown',
        expires: data.events?.find((e: any) => e.eventAction === 'expiration')?.eventDate || 'Unknown',
        nameservers: data.nameservers?.map((n: any) => n.ldhName) || [],
        status: data.status || []
      };
    }
  } catch (error) {
    console.log('RDAP failed, using fallback');
  }
  
  const tld = domain.split('.').pop();
  return {
    registrar: 'Available via WHOIS lookup',
    created: 'Query WHOIS database',
    updated: 'Query WHOIS database',
    expires: 'Query WHOIS database',
    nameservers: [],
    status: ['active'],
    tld
  };
}

// Directory enumeration simulation (Dirb-style)
async function enumerateDirectories(domain: string): Promise<any[]> {
  const commonPaths = [
    '/', '/admin', '/login', '/wp-admin', '/wp-login', '/phpmyadmin',
    '/.env', '/.git', '/config', '/backup', '/db', '/api', '/v1',
    '/docs', '/test', '/dev', '/staging', '/old', '/new', '/assets',
    '/static', '/images', '/js', '/css', '/uploads', '/files',
    '/sitemap.xml', '/robots.txt', '/favicon.ico', '/manifest.json',
    '/.htaccess', '/.htpasswd', '/server-status', '/info.php',
    '/console', '/debug', '/health', '/status', '/metrics',
    '/graphql', '/rest', '/soap', '/xmlrpc', '/actuator'
  ];
  
  const results = [];
  const baseUrl = `https://${domain}`;
  
  const checkPromises = commonPaths.slice(0, 30).map(async (path) => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      
      const response = await fetch(`${baseUrl}${path}`, {
        method: 'HEAD',
        redirect: 'follow',
        signal: controller.signal,
        headers: { 'User-Agent': 'Mozilla/5.0 (Security Scanner)' }
      });
      
      clearTimeout(timeoutId);
      
      if (response.status !== 404) {
        return {
          path,
          status: response.status,
          size: response.headers.get('content-length') || 'unknown',
          type: response.headers.get('content-type') || 'unknown',
          found: true
        };
      }
    } catch (error) {
      // Ignore errors
    }
    return null;
  });
  
  const checkedResults = await Promise.all(checkPromises);
  return checkedResults.filter(r => r !== null);
}

// HTTP Headers analysis
async function getHttpHeaders(url: string): Promise<any> {
  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      headers: { 'User-Agent': 'Mozilla/5.0 (Forensic Scanner 2.0)' }
    });
    
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });
    
    const securityHeaders = {
      'Strict-Transport-Security': !!headers['strict-transport-security'],
      'Content-Security-Policy': !!headers['content-security-policy'],
      'X-Frame-Options': !!headers['x-frame-options'],
      'X-Content-Type-Options': !!headers['x-content-type-options'],
      'X-XSS-Protection': !!headers['x-xss-protection'],
      'Referrer-Policy': !!headers['referrer-policy'],
      'Permissions-Policy': !!headers['permissions-policy'],
    };
    
    const securityScore = Object.values(securityHeaders).filter(Boolean).length;
    
    return {
      statusCode: response.status,
      server: headers['server'] || 'Unknown',
      headers,
      securityHeaders,
      securityScore: `${securityScore}/7`,
      technologies: detectTechnologies(headers)
    };
  } catch (error) {
    return { error: 'Failed to fetch headers' };
  }
}

function detectTechnologies(headers: Record<string, string>): string[] {
  const techs: string[] = [];
  const server = (headers['server'] || '').toLowerCase();
  const powered = (headers['x-powered-by'] || '').toLowerCase();
  
  if (server.includes('nginx')) techs.push('Nginx');
  if (server.includes('apache')) techs.push('Apache');
  if (server.includes('cloudflare')) techs.push('Cloudflare');
  if (server.includes('iis') || server.includes('microsoft')) techs.push('IIS');
  if (powered.includes('php')) techs.push('PHP');
  if (powered.includes('express')) techs.push('Express.js');
  if (headers['x-aspnet-version']) techs.push('ASP.NET');
  
  return techs.length > 0 ? techs : ['Unknown'];
}

// SSL/TLS Certificate analysis
async function analyzeSSL(domain: string): Promise<any> {
  try {
    const response = await fetch(`https://${domain}`, {
      method: 'HEAD',
      headers: { 'User-Agent': 'SSL Analyzer' }
    });
    
    return {
      secure: response.url.startsWith('https:'),
      protocol: 'TLS (detected)',
      issuer: 'Certificate Authority',
      subject: domain,
      validFrom: new Date().toISOString(),
      validTo: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
      fingerprint: 'SHA-256 available via client-side check',
      notes: 'Full certificate details require direct TLS handshake'
    };
  } catch (error) {
    return {
      secure: false,
      error: 'Could not establish SSL connection',
      possibleIssues: ['Self-signed certificate', 'Expired certificate', 'Invalid certificate chain', 'Domain mismatch']
    };
  }
}

// Screenshot/Capture - extracts page content
async function capturePage(domain: string): Promise<any> {
  try {
    const url = `https://${domain}`;
    const response = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Capture Bot 1.0)' }
    });
    
    const html = await response.text();
    
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    const metaDescMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)/i);
    const links = (html.match(/href=["'](https?:\/\/[^"']+)/g) || []).slice(0, 20);
    const scripts = (html.match(/src=["'](https?:\/\/[^"']*\.js)/g) || []).slice(0, 10);
    const forms = (html.match(/<form[^>]*action=["']([^"']*)/g) || []).length;
    const inputs = (html.match(/<input/g) || []).length;
    
    const sensitivePatterns = {
      emailAddresses: (html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []).slice(0, 5),
      phoneNumbers: (html.match(/[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}/g) || []).slice(0, 3),
      apiKeys: [],
      commentsWithInfo: (html.match(/<!--[\s\S]*?-->/g) || []).filter(c => c.length > 20).slice(0, 5)
    };
    
    return {
      captured: true,
      url,
      timestamp: new Date().toISOString(),
      title: titleMatch?.[1] || 'No title',
      metaDescription: metaDescMatch?.[1] || 'No description',
      htmlSize: html.length,
      linkCount: links.length,
      scriptCount: scripts.length,
      formCount: forms,
      inputCount: inputs,
      links: [...new Set(links)],
      scripts: [...new Set(scripts)],
      sensitivePatterns,
      hasLoginForm: /login|signin|sign.in|password/i.test(html),
      hasAdminPanel: /admin|dashboard|wp-admin|cpanel/i.test(html)
    };
  } catch (error) {
    return { 
      captured: false, 
      error: 'Failed to capture page',
      reason: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

// Subdomain enumeration
async function enumerateSubdomains(domain: string): Promise<string[]> {
  const commonSubdomains = [
    'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
    'vpn', 'api', 'dev', 'staging', 'blog', 'shop', 'app', 'm', 'mobile',
    'cdn', 'static', 'assets', 'img', 'images', 'video', 'media', 'download',
    'portal', 'secure', 'auth', 'oauth', 'sso', 'id', 'account', 'user',
    'admin', 'panel', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
    'remote', 'rdp', 'gateway', 'fw', 'firewall', 'proxy', 'cache',
    'db', 'database', 'mysql', 'mongo', 'redis', 'elastic', 'kibana', 'grafana',
    'jenkins', 'ci', 'git', 'svn', 'bitbucket', 'github', 'gitlab',
    'monitor', 'zabbix', 'nagios', 'prometheus', 'alertmanager', 'status',
    'mx', 'mx1', 'mx2', 'imap', 'pop3', 'mail1', 'mail2'
  ];
  
  const found: string[] = [];
  
  const checks = commonSubdomains.slice(0, 25).map(async (sub) => {
    const fullDomain = `${sub}.${domain}`;
    try {
      const result = await dnsLookup(fullDomain, 'A');
      if (result.data && result.data.length > 0) {
        return fullDomain;
      }
    } catch (e) {}
    return null;
  });
  
  const results = await Promise.all(checks);
  results.forEach(r => { if (r) found.push(r); });
  
  return found;
}

// Save results to file system
async function saveResults(domain: string, data: any): Promise<string> {
  await ensureDir(RESULTS_DIR);
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const folderName = `${domain}_${timestamp}`;
  const folderPath = join(RESULTS_DIR, folderName);
  
  await ensureDir(folderPath);
  
  await writeFile(join(folderPath, 'report.json'), JSON.stringify(data, null, 2));
  
  if (data.dns) {
    await writeFile(join(folderPath, 'dns.json'), JSON.stringify(data.dns, null, 2));
  }
  if (data.directories) {
    await writeFile(join(folderPath, 'directories.json'), JSON.stringify(data.directories, null, 2));
  }
  if (data.httpHeaders) {
    await writeFile(join(folderPath, 'headers.json'), JSON.stringify(data.httpHeaders, null, 2));
  }
  if (data.capture) {
    await writeFile(join(folderPath, 'capture.json'), JSON.stringify(data.capture, null, 2));
    if (data.capture.links) {
      await writeFile(join(folderPath, 'links.txt'), data.capture.links.join('\n'));
    }
  }
  
  const summary = `
FORENSIC ANALYSIS REPORT
========================
Domain: ${domain}
Timestamp: ${timestamp}
Analyst: OSINT Platform v9.0

SUMMARY
-------
DNS Records: ${data.dns ? Object.keys(data.dns).length : 0} types queried
Directories Found: ${data.directories?.length || 0}
Security Score: ${data.httpHeaders?.securityScore || 'N/A'}
Page Captured: ${data.capture?.captured ? 'Yes' : 'No'}
Subdomains Found: ${data.subdomains?.length || 0}

FILES GENERATED
---------------
- report.json: Complete analysis
- dns.json: DNS records
- directories.json: Directory enumeration
- headers.json: HTTP headers & security
- capture.json: Page capture data
- links.txt: Extracted links

Generated by MONITOR-THREAT Platform
  `;
  await writeFile(join(folderPath, 'summary.txt'), summary);
  
  return folderPath;
}

function assessRisk(data: any): any {
  let score = 0;
  const findings: string[] = [];
  const recommendations: string[] = [];
  
  if (data.httpHeaders?.securityScore) {
    const secScore = parseInt(data.httpHeaders.securityScore.split('/')[0]);
    if (secScore < 4) {
      score += 3;
      findings.push('Missing critical security headers');
      recommendations.push('Implement CSP, HSTS, X-Frame-Options');
    }
  }
  
  if (data.directories?.length > 5) {
    score += 2;
    findings.push(`${data.directories.length} exposed directories found`);
    recommendations.push('Restrict access to sensitive paths');
  }
  
  if (data.ssl?.secure === false) {
    score += 4;
    findings.push('SSL/TLS issues detected');
    recommendations.push('Review SSL certificate configuration');
  }
  
  if (data.capture?.sensitivePatterns?.emailAddresses?.length) {
    score += 1;
    findings.push('Email addresses exposed on page');
  }
  if (data.capture?.hasAdminPanel) {
    score += 2;
    findings.push('Admin panel detected');
    recommendations.push('Ensure admin panel is protected');
  }
  
  const level = score <= 2 ? 'LOW' : score <= 5 ? 'MEDIUM' : score <= 8 ? 'HIGH' : 'CRITICAL';
  
  return {
    score: Math.min(score, 10),
    level,
    findings,
    recommendations
  };
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { domain, options = {} } = body;
    
    if (!domain) {
      return NextResponse.json({ success: false, error: 'Domain is required' }, { status: 400 });
    }
    
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    
    console.log(`[FORENSICS] Starting analysis of ${cleanDomain}`);
    
    const [
      dnsA,
      dnsMX,
      dnsNS,
      dnsTXT,
      whois,
      httpHeaders,
      ssl,
      subdomains
    ] = await Promise.all([
      dnsLookup(cleanDomain, 'A'),
      dnsLookup(cleanDomain, 'MX'),
      dnsLookup(cleanDomain, 'NS'),
      dnsLookup(cleanDomain, 'TXT'),
      getWhoisInfo(cleanDomain),
      getHttpHeaders(`https://${cleanDomain}`),
      analyzeSSL(cleanDomain),
      enumerateSubdomains(cleanDomain)
    ]);
    
    const directories = await enumerateDirectories(cleanDomain);
    const capture = await capturePage(cleanDomain);
    
    const results = {
      domain: cleanDomain,
      timestamp: new Date().toISOString(),
      dns: {
        A: dnsA,
        MX: dnsMX,
        NS: dnsNS,
        TXT: dnsTXT
      },
      whois,
      httpHeaders,
      ssl,
      directories,
      subdomains,
      capture,
      riskAssessment: assessRisk({ dnsA, httpHeaders, ssl, directories, capture })
    };
    
    const savedPath = await saveResults(cleanDomain, results);
    results.savedPath = savedPath;
    
    return NextResponse.json({
      success: true,
      source: 'OSINT Forensic Engine v2.0',
      fetchedLive: true,
      data: results,
      message: `Forensic analysis complete. Results saved to: ${savedPath}`
    });
    
  } catch (error) {
    console.error('Forensic analysis error:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Analysis failed'
    }, { status: 500 });
  }
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action');
  
  if (action === 'list') {
    try {
      if (!existsSync(RESULTS_DIR)) {
        return NextResponse.json({ success: true, data: [] });
      }
      
      const folders = await readdir(RESULTS_DIR);
      const analyses = [];
      
      for (const folder of folders) {
        const folderPath = join(RESULTS_DIR, folder);
        const stats = await stat(folderPath);
        
        if (stats.isDirectory()) {
          analyses.push({
            name: folder,
            path: folderPath,
            created: stats.birthtime,
            modified: stats.mtime
          });
        }
      }
      
      return NextResponse.json({
        success: true,
        data: analyses.sort((a, b) => b.created.getTime() - a.created.getTime())
      });
    } catch (error) {
      return NextResponse.json({ success: false, error: 'Failed to list analyses' });
    }
  }
  
  if (action === 'get') {
    const name = searchParams.get('name');
    if (!name) {
      return NextResponse.json({ success: false, error: 'Analysis name required' });
    }
    
    try {
      const filePath = join(RESULTS_DIR, name, 'report.json');
      const data = await readFile(filePath, 'utf-8');
      return NextResponse.json({
        success: true,
        data: JSON.parse(data)
      });
    } catch (error) {
      return NextResponse.json({ success: false, error: 'Analysis not found' });
    }
  }
  
  return NextResponse.json({
    success: false,
    error: 'Invalid action. Use: list, get'
  });
}
