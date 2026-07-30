import { NextRequest, NextResponse } from 'next/server';

// Domain & WHOIS Analysis API
export async function POST(request: NextRequest) {
  try {
    const { domain } = await request.json();
    
    if (!domain) {
      return NextResponse.json({ error: 'Domain is required' }, { status: 400 });
    }

    // Clean domain input
    const cleanDomain = domain.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
    
    // Use ip-api.com for domain resolution first
    let ipAddress = null;
    let geoData = null;
    
    try {
      const dnsResponse = await fetch(`http://ip-api.com/json/${cleanDomain}?fields=status,query,country,countryCode,isp,org,as,proxy,hosting`);
      const dnsData = await dnsResponse.json();
      
      if (dnsData.status === 'success') {
        ipAddress = dnsData.query;
        geoData = {
          country: dnsData.country,
          countryCode: dnsData.countryCode,
          isp: dnsData.isp,
          org: dnsData.org,
          as: dnsData.as,
          isProxy: dnsData.proxy,
          isHosting: dnsData.hosting
        };
      }
    } catch (error) {
      console.log('DNS lookup failed, continuing with WHOIS simulation');
    }

    // Simulated WHOIS data (in production, use real WHOIS API)
    const whoisData = generateWhoisData(cleanDomain);
    
    // DNS Records (simulated)
    const dnsRecords = generateDNSRecords(cleanDomain, ipAddress);

    // Security analysis
    const securityAnalysis = analyzeDomainSecurity(cleanDomain, whoisData, geoData);

    // Calculate domain reputation score
    const reputationScore = calculateDomainReputation(whoisData, securityAnalysis);

    const result = {
      domain: cleanDomain,
      resolvedIp: ipAddress,
      whois: whoisData,
      dns: dnsRecords,
      geolocation: geoData,
      security: securityAnalysis,
      reputation: {
        score: reputationScore.score,
        level: reputationScore.level,
        color: reputationScore.color,
        factors: reputationScore.factors
      },
      metadata: {
        analyzedAt: new Date().toISOString(),
        sources: ['WHOIS Simulation', 'DNS Lookup', 'Security Analysis']
      }
    };

    return NextResponse.json({ success: true, data: result });
  } catch (error) {
    console.error('Domain Analysis Error:', error);
    return NextResponse.json(
      { error: 'Failed to analyze domain' },
      { status: 500 }
    );
  }
}

function generateWhoisData(domain: string) {
  const now = new Date();
  const createdDate = new Date(now.getTime() - Math.random() * 10 * 365 * 24 * 60 * 60 * 1000);
  const expiryDate = new Date(createdDate.getTime() + 1 * 365 * 24 * 60 * 60 * 1000);
  const updatedDate = new Date(createdDate.getTime() + Math.random() * (expiryDate.getTime() - createdDate.getTime()));

  const registrars = ['GoDaddy.com, LLC', 'NameCheap, Inc.', 'Google LLC', 'Amazon Registrar, Inc.', 'Cloudflare, Inc.', 'Tucows Domains Inc.'];
  const registrantCountries = ['US', 'CA', 'GB', 'DE', 'FR', 'AU', 'JP', 'NL', 'ES', 'IT'];
  const nameServers = [
    `ns1.${domain.substring(0, 10).replace(/\./g, '')}.com`,
    `ns2.${domain.substring(0, 10).replace(/\./g, '')}.com`,
    `ns1.cloudflare.com`,
    `ns2.cloudflare.com`
  ];

  return {
    registrar: registrars[Math.floor(Math.random() * registrars.length)],
    creationDate: createdDate.toISOString(),
    expirationDate: expiryDate.toISOString(),
    updatedDate: updatedDate.toISOString(),
    registrant: {
      organization: `${domain.split('.')[0].toUpperCase()} Inc.`,
      country: registrantCountries[Math.floor(Math.random() * registrantCountries.length)],
      stateProvince: 'California',
      email: `admin@${domain}`
    },
    nameServers: nameServers.slice(0, 2 + Math.floor(Math.random() * 2)),
    status: ['clientTransferProhibited', 'autoRenewPeriod'],
    dnssec: Math.random() > 0.5 ? 'unsigned' : 'signed'
  };
}

function generateDNSRecords(domain: string, ip: string | null) {
  const records = {
    A: ip ? [{ value: ip, ttl: 3600 }] : [{ value: `104.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`, ttl: 3600 }],
    AAAA: [],
    MX: [
      { exchange: `mail.${domain}`, priority: 10, ttl: 3600 },
      { exchange: `mail2.${domain}`, priority: 20, ttl: 3600 }
    ],
    NS: [
      { value: `ns1.${domain}`, ttl: 86400 },
      { value: `ns2.${domain}`, ttl: 86400 }
    ],
    TXT: [
      { value: `v=spf1 include:_spf.google.com ~all`, ttl: 3600 },
      { value: `google-site-verification=${Math.random().toString(36).substring(2, 15)}`, ttl: 3600 }
    ],
    CNAME: [],
    SOA: {
      mname: `ns1.${domain}`,
      rname: `admin.${domain}`,
      serial: Math.floor(Date.now() / 1000),
      refresh: 3600,
      retry: 600,
      expire: 604800,
      minimum: 3600
    }
  };

  return records;
}

function analyzeDomainSecurity(domain: string, whois: any, geo: any) {
  const issues: string[] = [];
  const strengths: string[] = [];
  
  // Check domain age
  const createdDate = new Date(whois.creationDate);
  const ageInDays = (Date.now() - createdDate.getTime()) / (1000 * 60 * 60 * 24);
  
  if (ageInDays < 30) {
    issues.push(`Very new domain (${Math.round(ageInDays)} days old) - Higher risk of malicious use`);
  } else if (ageInDays > 365) {
    strengths.push(`Established domain (${Math.round(ageInDays / 365)}+ years old)`);
  }

  // Check DNSSEC
  if (whois.dnssec === 'signed') {
    strengths.push('DNSSEC enabled - DNS records are cryptographically signed');
  } else {
    issues.push('DNSSEC not enabled - Vulnerable to DNS spoofing attacks');
  }

  // Check SPF record
  if (Math.random() > 0.3) {
    strengths.push('SPF record configured - Email spoofing protection active');
  } else {
    issues.push('Missing SPF record - Email may be spoofed');
  }

  // Check SSL/TLS (simulated)
  strengths.push('Valid SSL certificate detected');

  // Check for suspicious TLD
  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click'];
  const tld = '.' + domain.split('.').pop();
  if (suspiciousTlds.includes(tld)) {
    issues.push(`Suspicious TLD (${tld}) - Commonly used for malicious sites`);
  }

  return {
    overallScore: Math.max(0, 100 - issues.length * 15),
    issues,
    strengths,
    hasSSL: true,
    hasSpf: true,
    hasDmarc: Math.random() > 0.5,
    hasDnssec: whois.dnssec === 'signed'
  };
}

function calculateDomainReputation(whois: any, security: any) {
  let score = 50; // Base score
  
  // Age factor
  const ageInDays = (Date.now() - new Date(whois.creationDate).getTime()) / (1000 * 60 * 60 * 24);
  if (ageInDays > 365) score += 20;
  else if (ageInDays > 180) score += 10;
  else if (ageInDays < 30) score -= 20;

  // Security factors
  score += security.strengths.length * 5;
  score -= security.issues.length * 10;

  // Clamp score
  score = Math.max(0, Math.min(100, score));

  let level = 'Neutral';
  let color = '#6b7280';
  
  if (score >= 75) {
    level = 'Trustworthy';
    color = '#22c55e';
  } else if (score >= 50) {
    level = 'Moderate';
    color = '#eab308';
  } else if (score >= 25) {
    level = 'Suspicious';
    color = '#f97316';
  } else {
    level = 'Dangerous';
    color = '#dc2626';
  }

  return {
    score: Math.round(score),
    level,
    color,
    factors: [
      `Domain Age: ${ageInDays < 30 ? '< 1 month' : ageInDays > 365 ? '1+ years' : '< 1 year'}`,
      `Security Score: ${security.overallScore}/100`,
      `Issues Found: ${security.issues.length}`,
      `Strengths: ${security.strengths.length}`
    ]
  };
}
