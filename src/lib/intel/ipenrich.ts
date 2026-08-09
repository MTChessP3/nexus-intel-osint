// IP enrichment engine — passive OSINT + active fingerprinting.
// All sources are free and require no API key:
//   - DNSBL reputation (Spamhaus ZEN, SpamCop, Barracuda, SORBS, Abusix, DroneBL, ...)
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
  blocked: boolean;
  records: string[];
  message?: string;
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
  // Tier 1 — major global lists
  { name: 'Spamhaus ZEN', zone: 'zen.spamhaus.org' },
  { name: 'SpamCop', zone: 'bl.spamcop.net' },
  { name: 'Barracuda', zone: 'b.barracudacentral.org' },
  { name: 'SORBS', zone: 'dnsbl.sorbs.net' },
  { name: 'Abusix Combined', zone: 'combined.mail.abusix.zone' },
  { name: 'Abusix Black', zone: 'black.mail.abusix.zone' },
  { name: 'Spamrats Dyna', zone: 'dyna.spamrats.com' },
  { name: 'Spamrats Spam', zone: 'spam.spamrats.com' },
  { name: 'Spamrats NoPtr', zone: 'noptr.spamrats.com' },
  { name: 'DroneBL', zone: 'dnsbl.dronebl.org' },
  { name: 'blocklist.de', zone: 'bl.blocklist.de' },
  { name: 'S5H', zone: 'all.s5h.net' },
  { name: 'PSBL', zone: 'psbl.surriel.com' },
  { name: 'Hostkarma', zone: 'hostkarma.junkemailfilter.com' },
  { name: 'Mailspike', zone: 'bl.mailspike.net' },
  { name: 'abuse.ch DNSBL', zone: 'dnsbl.abuse.ch' },
  { name: 'DShield', zone: 'dnsbl.dshield.org' },
  { name: 'Backscatterer', zone: 'ips.backscatterer.org' },
  { name: 'SPFBL', zone: 'dnsbl.spfbl.net' },
  // UCEPROTECT levels (Level 1-3 list increasingly broad ISP/ASN ranges)
  { name: 'UCEPROTECT L0', zone: 'dnsbl-0.uceprotect.net' },
  { name: 'UCEPROTECT L1', zone: 'dnsbl-1.uceprotect.net' },
  { name: 'UCEPROTECT L2', zone: 'dnsbl-2.uceprotect.net' },
  { name: 'UCEPROTECT L3', zone: 'dnsbl-3.uceprotect.net' },
  // Unsubscribe / Lashback
  { name: 'UBL (Lashback)', zone: 'ubl.unsubscore.com' },
  // Polspam family
  { name: 'Polspam BL', zone: 'bl.rbl.polspam.pl' },
  { name: 'Polspam H1', zone: 'bl-h1.rbl.polspam.pl' },
  { name: 'Polspam H2', zone: 'bl-h2.rbl.polspam.pl' },
  { name: 'Polspam H3', zone: 'bl-h3.rbl.polspam.pl' },
  { name: 'Polspam H4', zone: 'bl-h4.rbl.polspam.pl' },
  { name: 'Polspam Dyn', zone: 'dyn.rbl.polspam.pl' },
  { name: 'Polspam RBLIP4', zone: 'rblip4.rbl.polspam.pl' },
  // Regional / specialty IP lists
  { name: 'rbldns.ru', zone: 'rbl.rbldns.ru' },
  { name: 'Scientific Spam', zone: 'bl.scientificspam.net' },
  { name: 'NordSpam', zone: 'bl.nordspam.com' },
  { name: 'JustSpam', zone: 'dnsbl.justspam.org' },
  { name: 'ZapBL', zone: 'dnsbl.zapbl.net' },
  { name: 'Suomispam', zone: 'bl.suomispam.net' },
  { name: 'V4BL', zone: 'ip.v4bl.org' },
  { name: 'V4BL-Free', zone: 'free.v4bl.org' },
  { name: 'pofon.foobar.hu', zone: 'pofon.foobar.hu' },
  { name: 'Virusfree BAD', zone: 'bad.virusfree.cz' },
  { name: 'fabel.dk', zone: 'spamsources.fabel.dk' },
  { name: 'ImproWare', zone: 'spamrbl.imp.ch' },
  { name: "Woody's SMTP", zone: 'blacklist.woody.ch' },
  { name: 'OXL Risk DB', zone: 'ip.dnsbl.risk.oxl.app' },
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

async function resolveTxtWithTimeout(hostname: string, timeoutMs: number): Promise<string[]> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve([]), timeoutMs);
    dns
      .resolveTxt(hostname)
      .then((chunks) => {
        clearTimeout(timer);
        resolve(chunks.map((c) => c.join('')));
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
      const all = await resolveWithTimeout(`${reversed}.${entry.zone}`, 4000);
      // A listing is signaled by a 127.0.x.x return code (e.g. 127.0.0.2, 127.0.2.3 Polspam H3).
      // 127.255.255.x is an ERROR code (e.g. "query via public/open resolver") — not a listing.
      const records = all.filter((r) => /^127\.0\.\d+\.\d+$/.test(r));
      const blocked = records.length === 0 && all.some((r) => /^127\.255\.255\.\d+$/.test(r));
      const listed = records.length > 0;
      let message: string | undefined;
      if (listed) {
        const txt = await resolveTxtWithTimeout(`${reversed}.${entry.zone}`, 3000);
        message = txt.filter(Boolean).join(' | ') || undefined;
      }
      return { name: entry.name, zone: entry.zone, listed, blocked, records, message };
    })
  );
  return results;
}

async function checkTorExit(ip: string): Promise<boolean> {
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return false;
  const records = await resolveWithTimeout(`${reverseOctets(ip)}.${TOR_DNSBL_ZONE}`, 4000);
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
      signal: AbortSignal.timeout(8000),
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
      signal: AbortSignal.timeout(4000),
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
    const connectTimer = setTimeout(() => finish('filtered'), 1200);
    sock.setTimeout(1200);
    sock.setEncoding('utf8');
    let data = '';
    sock.on('data', (chunk) => {
      data += chunk;
    });
    sock.once('connect', () => {
      clearTimeout(connectTimer);
      sock.setTimeout(2500);
      setTimeout(() => {
        const banner = data
          .slice(0, 240)
          .replace(/[\r\n\t]+/g, ' ')
          .trim();
        finish('open', banner || null);
      }, 300);
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
  const scanPromise =
    opts.scan !== false ? scanPorts(ip) : Promise.resolve<IpScan>({ os: 'Unknown', ports: [] });

  const [dnsbl, torExit, urlhaus, certificates, scan] = await Promise.all([
    queryDnsbl(ip),
    checkTorExit(ip),
    lookupUrlhaus(ip),
    lookupCrt(ip),
    scanPromise,
  ]);

  const reputation: IpReputation = { dnsbl, torExit, urlhaus };

  return { reputation, pivot: { certificates }, scan };
}
