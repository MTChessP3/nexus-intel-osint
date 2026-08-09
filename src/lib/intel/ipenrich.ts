// IP enrichment engine — passive OSINT + active fingerprinting.
// All sources are free and require no API key:
//   - DNSBL reputation (Spamhaus ZEN, SpamCop, Barracuda)
//   - Tor exit node detection (tor.dan.me.uk DNSBL)
//   - Malicious URL history (URLhaus / abuse.ch)
//   - Certificate / pivoting search (crt.sh Certificate Transparency)
//   - Active TCP port scan + service banner grab (Node net)
//   - OS fingerprint heuristic derived from exposed services

import net from 'net';
import { promises as dns } from 'dns';

export interface DnsblResult {
  name: string;
  zone: string;
  listed: boolean;
  records: string[];
}

export interface UrlhausResult {
  queryStatus: string;
  host: string;
  urlCount: number;
  urls: { url: string; threat: string; dateAdded: string }[];
}

export interface CertificateResult {
  commonName: string;
  nameValue: string;
  issuerName: string;
  notBefore: string;
  notAfter: string;
}

export interface PortResult {
  port: number;
  service: string;
  state: 'open' | 'closed' | 'filtered';
  banner: string | null;
}

export interface IpReputation {
  dnsbl: DnsblResult[];
  torExit: boolean;
  urlhaus: UrlhausResult;
}

export interface IpPivot {
  certificates: CertificateResult[];
}

export interface IpScan {
  os: string;
  ports: PortResult[];
}

const DNSBL_ZONES = [
  { name: 'Spamhaus ZEN', zone: 'zen.spamhaus.org' },
  { name: 'SpamCop', zone: 'bl.spamcop.net' },
  { name: 'Barracuda', zone: 'b.barracudacentral.org' },
  { name: 'SORBS', zone: 'dnsbl.sorbs.net' },
];

const TOR_DNSBL_ZONE = 'tor.dan.me.uk';

const SCAN_PORTS: { port: number; service: string }[] = [
  { port: 21, service: 'FTP' },
  { port: 22, service: 'SSH' },
  { port: 23, service: 'Telnet' },
  { port: 25, service: 'SMTP' },
  { port: 53, service: 'DNS' },
  { port: 80, service: 'HTTP' },
  { port: 110, service: 'POP3' },
  { port: 143, service: 'IMAP' },
  { port: 443, service: 'HTTPS' },
  { port: 445, service: 'SMB' },
  { port: 993, service: 'IMAPS' },
  { port: 995, service: 'POP3S' },
  { port: 3306, service: 'MySQL' },
  { port: 3389, service: 'RDP' },
  { port: 5432, service: 'PostgreSQL' },
  { port: 5900, service: 'VNC' },
  { port: 6379, service: 'Redis' },
  { port: 8080, service: 'HTTP-Alt' },
  { port: 8443, service: 'HTTPS-Alt' },
  { port: 9090, service: 'Web-Admin' },
];

function reverseOctets(ip: string): string {
  return ip.split('.').reverse().join('.');
}

async function resolveWithTimeout(hostname: string, timeoutMs: number): Promise<string[]> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve([]), timeoutMs);
    dns
      .resolve4(hostname)
      .then((records) => {
        clearTimeout(timer);
        resolve(records);
      })
      .catch(() => {
        clearTimeout(timer);
        resolve([]);
      });
  });
}

async function queryDnsbl(ip: string): Promise<DnsblResult[]> {
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return [];
  const reversed = reverseOctets(ip);
  const results = await Promise.all(
    DNSBL_ZONES.map(async (entry) => {
      const records = (await resolveWithTimeout(`${reversed}.${entry.zone}`, 6000)).filter((r) =>
        r.startsWith('127.0.0.')
      );
      return { name: entry.name, zone: entry.zone, listed: records.length > 0, records };
    })
  );
  return results;
}

async function checkTorExit(ip: string): Promise<boolean> {
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return false;
  const records = await resolveWithTimeout(`${reverseOctets(ip)}.${TOR_DNSBL_ZONE}`, 6000);
  return records.length > 0;
}

async function lookupUrlhaus(ip: string): Promise<UrlhausResult> {
  const empty: UrlhausResult = {
    queryStatus: 'no_results',
    host: ip,
    urlCount: 0,
    urls: [],
  };
  try {
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'NEXUS-INTEL/1.0',
      },
      body: `host=${encodeURIComponent(ip)}`,
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) return empty;
    const data = await response.json();
    if (data.query_status === 'ok') {
      return {
        queryStatus: 'ok',
        host: data.host || ip,
        urlCount: data.url_count || 0,
        urls: (data.urls || []).map((u: any) => ({
          url: u.url,
          threat: u.threat || 'malware',
          dateAdded: u.date_added || '',
        })),
      };
    }
    return empty;
  } catch {
    return empty;
  }
}

async function lookupCrt(ip: string): Promise<CertificateResult[]> {
  try {
    const response = await fetch(`https://crt.sh/?q=${encodeURIComponent(ip)}&output=json`, {
      signal: AbortSignal.timeout(12000),
      headers: { 'User-Agent': 'NEXUS-INTEL/1.0' },
    });
    if (!response.ok) return [];
    const data = await response.json();
    if (!Array.isArray(data)) return [];
    const seen = new Set<string>();
    const certs: CertificateResult[] = [];
    for (const c of data) {
      const names = String(c.name_value || '')
        .split('\n')
        .map((n) => n.trim())
        .filter(Boolean);
      for (const name of names) {
        if (seen.has(name)) continue;
        seen.add(name);
        certs.push({
          commonName: c.common_name || name,
          nameValue: name,
          issuerName: c.issuer_name || '',
          notBefore: c.not_before || '',
          notAfter: c.not_after || '',
        });
      }
      if (certs.length >= 30) break;
    }
    return certs;
  } catch {
    return [];
  }
}

function checkPort(ip: string, target: { port: number; service: string }): Promise<PortResult> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let settled = false;
    const finish = (state: PortResult['state'], banner?: string | null) => {
      if (!settled) {
        settled = true;
        sock.destroy();
        resolve({ port: target.port, service: target.service, state, banner: banner || null });
      }
    };
    const connectTimer = setTimeout(() => finish('filtered'), 1800);
    sock.setTimeout(1800);
    sock.setEncoding('utf8');
    let data = '';
    sock.on('data', (chunk) => {
      data += chunk;
    });
    sock.once('connect', () => {
      clearTimeout(connectTimer);
      sock.setTimeout(3000);
      setTimeout(() => {
        const banner = data
          .slice(0, 240)
          .replace(/[\r\n\t]+/g, ' ')
          .trim();
        finish('open', banner || null);
      }, 500);
    });
    sock.on('error', () => {
      clearTimeout(connectTimer);
      finish('closed');
    });
    sock.on('timeout', () => {
      clearTimeout(connectTimer);
      finish('filtered');
    });
    sock.connect(target.port, ip);
  });
}

async function scanPorts(ip: string): Promise<IpScan> {
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
    return { os: 'Unknown (IPv6 not scanned)', ports: [] };
  }
  const results = await Promise.all(SCAN_PORTS.map((target) => checkPort(ip, target)));
  const open = results.filter((r) => r.state === 'open');
  const openPorts = new Set(open.map((r) => r.port));
  let os = 'Unknown';
  if (openPorts.has(3389)) os = 'Windows (RDP)';
  else if (openPorts.has(445) && !openPorts.has(22)) os = 'Windows (SMB)';
  else if (openPorts.has(22) && openPorts.has(80) && openPorts.has(443)) os = 'Linux/Unix server';
  else if (openPorts.has(22)) os = 'Linux/Unix';
  else if (openPorts.has(53)) os = 'DNS server (BIND/Unbound)';
  else if (openPorts.has(3306) || openPorts.has(5432) || openPorts.has(6379)) os = 'Database server';
  else if (openPorts.has(80) || openPorts.has(443) || openPorts.has(8080) || openPorts.has(8443)) os = 'Web server';
  return { os, ports: results };
}

export async function enrichIP(ip: string, opts: { scan?: boolean } = {}): Promise<{
  reputation: IpReputation;
  pivot: IpPivot;
  scan: IpScan;
}> {
  const [dnsbl, torExit, urlhaus, certificates] = await Promise.all([
    queryDnsbl(ip),
    checkTorExit(ip),
    lookupUrlhaus(ip),
    lookupCrt(ip),
  ]);

  const reputation: IpReputation = { dnsbl, torExit, urlhaus };

  let scan: IpScan = { os: 'Unknown', ports: [] };
  if (opts.scan !== false) {
    scan = await scanPorts(ip);
  }

  return { reputation, pivot: { certificates }, scan };
}
