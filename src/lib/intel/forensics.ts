// Web Forensic Analysis Engine — real-time resource analysis for a target URL/domain.
// Produces a per-analysis "resource container": fuzzing tree, artifacts (auto-downloaded
// files), phishing kits, exposed databases and attribution metadata.

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) NEXUS-Forensic/3.0';

export interface ForensicResource {
  id: string;
  name: string;
  domain: string;
  timestamp: string;
  risk: { level: string; score: number };
  ip: string | null;
  fuzzingTree: { path: string; url: string; status: number | null; size: number | null; contentType: string | null; sensitive: boolean; name: string }[];
  artifacts: { url: string; status: number | null; size: number | null; type: string; kind: string }[];
  phishingKits: { url: string; name: string; status: number | null; size: number | null; kind: string }[];
  databases: { url: string; name: string; status: number | null; size: number | null; kind: string }[];
  attribution: {
    emails: string[];
    telegramIds: string[];
    trackingIds: string[];
    apiKeys: string[];
    comments: string[];
    toolSignatures: string[];
    links: string[];
  };
  dns: Record<string, any>;
  whois: any;
  subdomains: string[];
  httpHeaders: any;
  ssl: any;
  capture: any;
  infrastructure: { nodes: { id: string; label: string; kind: string; meta?: string }[]; edges: { source: string; target: string; label?: string }[] };
  verdict: string;
}

// Paths probed during directory fuzzing, grouped by category (phishing / admin / backup / database)
const FUZZ_PATHS: { path: string; category: 'kit' | 'admin' | 'db' | 'backup' | 'config' | 'common' }[] = [
  { path: 'admin', category: 'admin' }, { path: 'admin/', category: 'admin' },
  { path: 'administrator', category: 'admin' }, { path: 'wp-admin', category: 'admin' },
  { path: 'panel', category: 'admin' }, { path: 'cpanel', category: 'admin' },
  { path: 'login', category: 'admin' }, { path: 'dashboard', category: 'admin' },
  { path: 'backup', category: 'backup' }, { path: 'backup/', category: 'backup' },
  { path: 'backups', category: 'backup' }, { path: 'db', category: 'db' },
  { path: 'database', category: 'db' }, { path: 'dump.sql', category: 'db' },
  { path: 'db.sql', category: 'db' }, { path: 'database.sql', category: 'db' },
  { path: 'backup.sql', category: 'db' }, { path: 'data.sql', category: 'db' },
  { path: '.sql', category: 'db' }, { path: 'db.sql.gz', category: 'db' },
  { path: 'db.sql.zip', category: 'db' }, { path: 'dump.db', category: 'db' },
  { path: 'backup.db', category: 'db' }, { path: 'app.db', category: 'db' },
  { path: 'users.db', category: 'db' }, { path: 'database.db', category: 'db' },
  { path: 'config.php', category: 'config' }, { path: 'config.php.bak', category: 'config' },
  { path: 'settings.php', category: 'config' }, { path: 'wp-config.php', category: 'config' },
  { path: 'configuration.php', category: 'config' }, { path: '.env', category: 'config' },
  { path: '.env.backup', category: 'config' }, { path: 'config.inc.php', category: 'config' },
  { path: 'config.yml', category: 'config' }, { path: 'config.json', category: 'config' },
  { path: 'composer.json', category: 'config' }, { path: 'package.json', category: 'config' },
  { path: 'phpinfo.php', category: 'config' }, { path: 'test.php', category: 'config' },
  { path: 'index.php~', category: 'backup' }, { path: 'index.php.bak', category: 'backup' },
  { path: 'main.zip', category: 'kit' }, { path: 'site.zip', category: 'kit' },
  { path: 'update.zip', category: 'kit' }, { path: 'theme.zip', category: 'kit' },
  { path: 'backup.zip', category: 'kit' }, { path: 'panel.zip', category: 'kit' },
  { path: 'panel.rar', category: 'kit' }, { path: 'kit.zip', category: 'kit' },
  { path: 'phishing.zip', category: 'kit' }, { path: 'template.zip', category: 'kit' },
  { path: 'assets.zip', category: 'kit' }, { path: 'files.zip', category: 'kit' },
  { path: '.rar', category: 'kit' }, { path: '.tar.gz', category: 'kit' },
  { path: 'vendor', category: 'common' }, { path: 'uploads/', category: 'common' },
  { path: 'images/', category: 'common' }, { path: 'css/', category: 'common' },
  { path: 'js/', category: 'common' }, { path: 'assets/', category: 'common' },
  { path: 'tmp/', category: 'common' }, { path: 'temp/', category: 'common' },
  { path: 'logs/', category: 'common' }, { path: 'error_log', category: 'common' },
  { path: '.git/config', category: 'config' }, { path: '.git/HEAD', category: 'config' },
  { path: 'info.php', category: 'config' }, { path: 'index.html.bak', category: 'backup' },
  { path: 'index.htm.bak', category: 'backup' }, { path: 'db.zip', category: 'db' },
  { path: 'dump.zip', category: 'db' }, { path: 'sql.zip', category: 'db' },
];

const KIT_EXT = /\.(zip|rar|tar\.gz|tgz|7z)$/i;
const DB_EXT = /\.(sql|db|sqlite|sqlite3|bak|dump|mysql)$/i;

function trackExtOf(kind: string, path: string): string {
  if (DB_EXT.test(path)) return 'databases';
  if (KIT_EXT.test(path)) return 'phishing_kits';
  if (kind === 'config') return 'config';
  if (kind === 'admin') return 'admin';
  return 'fuzzing';
}

export async function runForensicAnalysis(input: string): Promise<ForensicResource> {
  const domain = input.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  const baseUrl = `https://${domain}`;
  const timestamp = new Date().toISOString();
  const name = `analisis_${domain}_${Date.now()}`;
  const id = Buffer.from(name).toString('base64url').slice(0, 32);

  // ---- DNS reconnaissance (Google DoH) ----
  const dns: Record<string, any> = {};
  const ipSet = new Set<string>();
  try {
    const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];
    const settled = await Promise.allSettled(
      types.map((t) =>
        fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${t}`, {
          headers: { Accept: 'application/dns-json' },
          signal: AbortSignal.timeout(8000),
        }).then((r) => r.json())
      )
    );
    settled.forEach((res, i) => {
      dns[types[i]] = res.status === 'fulfilled' ? res.value : { Status: 2, Answer: [] };
    });
    (dns.A?.Answer || []).forEach((a: any) => a.data && ipSet.add(a.data));
  } catch { /* dns unavailable */ }

  // ---- Subdomains (crt.sh) ----
  const subdomains: string[] = [];
  try {
    const crt = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
      signal: AbortSignal.timeout(12000),
      headers: { 'User-Agent': UA },
    });
    if (crt.ok) {
      const rows = await crt.json();
      const seen = new Set<string>();
      for (const r of (rows || []).slice(0, 120)) {
        for (const nameRaw of String(r.name_value || '').split('\n')) {
          const n = nameRaw.trim().toLowerCase();
          if (n.endsWith(domain) && !n.includes('*') && !seen.has(n)) {
            seen.add(n);
            subdomains.push(n);
          }
        }
      }
    }
  } catch { /* crt.sh unavailable */ }

  // ---- HTTP header capture ----
  let httpHeaders: any = {};
  try {
    const res = await fetch(baseUrl, { headers: { 'User-Agent': UA }, redirect: 'follow', signal: AbortSignal.timeout(15000) });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k] = v));
    const securityHeaders = {
      'Strict-Transport-Security': !!headers['strict-transport-security'],
      'Content-Security-Policy': !!headers['content-security-policy'],
      'X-Frame-Options': !!headers['x-frame-options'],
      'X-Content-Type-Options': !!headers['x-content-type-options'],
      'Referrer-Policy': !!headers['referrer-policy'],
      'Permissions-Policy': !!headers['permissions-policy'],
    };
    httpHeaders = {
      statusCode: res.status,
      server: headers['server'] || 'Unknown',
      headers,
      securityHeaders,
      securityScore: `${Object.values(securityHeaders).filter(Boolean).length}/6`,
    };
  } catch { httpHeaders = { statusCode: 0, error: 'Failed to fetch', securityHeaders: {} }; }

  // ---- SSL probe ----
  let ssl: any = {};
  try {
    const res = await fetch(baseUrl, { method: 'HEAD', headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(10000) });
    ssl = { secure: res.url.startsWith('https:'), protocol: 'TLS (verified)', subject: domain };
  } catch { ssl = { secure: false, error: 'Could not establish HTTPS connection' }; }

  // ---- Page capture + source attribution ----
  let capture: any = { captured: false };
  const attribution = { emails: [] as string[], telegramIds: [] as string[], trackingIds: [] as string[], apiKeys: [] as string[], comments: [] as string[], toolSignatures: [] as string[], links: [] as string[] };
  try {
    const res = await fetch(baseUrl, { headers: { 'User-Agent': UA }, redirect: 'follow', signal: AbortSignal.timeout(15000) });
    const html = await res.text();
    const title = (html.match(/<title[^>]*>([^<]+)<\/title>/i) || [])[1] || 'No title found';
    const links = [...new Set((html.match(/href=["'](?:https?:\/\/[^"']+)/g) || []).map((m) => m.replace(/^href=["']/, '')))];
    capture = { captured: true, url: res.url, title, htmlSize: html.length, status: res.status, hasLoginForm: /login|signin|password/i.test(html), hasAdminPanel: /admin|dashboard|wp-admin|cpanel/i.test(html) };

    attribution.emails = [...new Set((html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []).filter((e) => !e.endsWith('.png') && !e.endsWith('.jpg') && !e.endsWith('.svg') && !e.endsWith('.gif') && !e.endsWith('.webp')))].slice(0, 10);
    attribution.telegramIds = [...new Set((html.match(/(?:t\.me\/|telegram\.me\/|@)([a-zA-Z0-9_]{4,32})/g) || []))].slice(0, 10);
    attribution.comments = (html.match(/<!--[\s\S]*?-->/g) || []).filter((c) => c.length > 15).slice(0, 8);
    attribution.links = links.slice(0, 20);

    const gaLinks = links.filter((l) => l.includes('google-analytics.com') || l.includes('googletagmanager.com') || l.includes('adsense') || l.includes('googleadservices'));
    for (const l of gaLinks.slice(0, 10)) {
      const m = l.match(/[?&](?:id|tid|client|zone|site)=([A-Za-z0-9\-_]+)/);
      if (m) attribution.trackingIds.push(`GA/AdSense: ${m[1]}`);
    }
    const gid = html.match(/G-[A-Z0-9]{6,12}/g) || [];
    const uaid = html.match(/UA-\d{4,10}-\d{1,4}/g) || [];
    attribution.trackingIds.push(...[...new Set([...gid, ...uaid])].map((x) => `GoogleAnalytics: ${x}`));
    const aw = html.match(/AW-\d{6,12}/g) || [];
    attribution.trackingIds.push(...[...new Set(aw)].map((x) => `AdWords: ${x}`));

    const keyPatterns = [
      [/AIza[0-9A-Za-z\-_]{35}/g, 'Google API key'],
      [/sk-(?:live|test)_[0-9a-zA-Z]{20,40}/g, 'Stripe key'],
      [/AKIA[0-9A-Z]{16}/g, 'AWS access key'],
      [/ghp_[0-9A-Za-z]{36,40}/g, 'GitHub token'],
      [/xox[baprs]-[0-9A-Za-z\-]{10,60}/g, 'Slack token'],
      [/pk_live_[0-9a-zA-Z]{20,40}/g, 'Stripe publishable'],
    ];
    for (const [re, label] of keyPatterns) {
      const found = html.match(re) || [];
      attribution.apiKeys.push(...[...new Set(found)].map((k) => `${label}`).slice(0, 3));
    }

    if (/<!--\s*Created with (Wix|WordPress|Joomla|Drupal|WebSite X5|Mobirise)/i.test(html)) {
      attribution.toolSignatures.push('Site builder signature detected');
    }
    const wp = /wp-content|wp-includes|wp-json/i.test(html);
    if (wp) attribution.toolSignatures.push('WordPress detected');
    if (/cPanel|WHM/i.test(html)) attribution.toolSignatures.push('cPanel detected');
    if (/Plesk/i.test(html)) attribution.toolSignatures.push('Plesk detected');
    if (/Elementor/i.test(html)) attribution.toolSignatures.push('Elementor detected');
    if (/SiteGround|SG-Client/i.test(html)) attribution.toolSignatures.push('SiteGround hosting signature');
    if (/Hostinger|hPanel/i.test(html)) attribution.toolSignatures.push('Hostinger hosting signature');
    if (/Cloudflare/i.test(html)) attribution.toolSignatures.push('Cloudflare proxy detected');
  } catch { /* capture failed */ }

  // ---- Directory fuzzing (sequential, bounded) ----
  const fuzzingTree: ForensicResource['fuzzingTree'] = [];
  const artifacts: ForensicResource['artifacts'] = [];
  const phishingKits: ForensicResource['phishingKits'] = [];
  const databases: ForensicResource['databases'] = [];

  const batchSize = 8;
  for (let i = 0; i < FUZZ_PATHS.length; i += batchSize) {
    const batch = FUZZ_PATHS.slice(i, i + batchSize);
    const settled = await Promise.allSettled(
      batch.map(async (p) => {
        const url = `${baseUrl}/${p.path}`;
        const res = await fetch(url, { method: 'GET', redirect: 'manual', headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(8000) });
        return { p, res, url };
      })
    );
    for (const s of settled) {
      if (s.status !== 'fulfilled') continue;
      const { p, res, url } = s.value;
      const status = res.status;
      const size = Number(res.headers.get('content-length')) || null;
      const contentType = res.headers.get('content-type');
      const sensitive = p.category !== 'common';
      const entry = { path: p.path, url, status, size, contentType, sensitive, name: p.path.split('/').pop() || p.path };
      fuzzingTree.push(entry);
      if (status === 200 || status === 403) {
        const kind = trackExtOf(p.category, p.path);
        artifacts.push({ url, status, size, type: p.category, kind });
        if (kind === 'phishing_kits') {
          phishingKits.push({ url, name: p.path.split('/').pop() || p.path, status, size, kind: 'archive' });
        } else if (kind === 'databases') {
          databases.push({ url, name: p.path.split('/').pop() || p.path, status, size, kind: 'database' });
        }
      }
    }
  }

  // ---- Infrastructure graph ----
  const nodes: ForensicResource['infrastructure']['nodes'] = [];
  const edges: ForensicResource['infrastructure']['edges'] = [];
  nodes.push({ id: domain, label: domain, kind: 'domain' });
  const ipList = [...ipSet];
  ipList.slice(0, 8).forEach((ip) => nodes.push({ id: ip, label: ip, kind: 'ip', meta: 'A record' }));
  (dns.MX?.Answer || []).slice(0, 5).forEach((m: any, idx: number) => {
    const host = String(m.data || '').replace(/\s*\d+\s*$/, '');
    nodes.push({ id: host, label: host, kind: 'mx', meta: `MX prio ${m.preference ?? idx}` });
    edges.push({ source: domain, target: host, label: 'MX' });
  });
  subdomains.slice(0, 8).forEach((s) => {
    nodes.push({ id: s, label: s, kind: 'subdomain' });
    edges.push({ source: domain, target: s, label: 'DNS' });
  });
  (dns.NS?.Answer || []).slice(0, 4).forEach((n: any) => {
    const host = String(n.data || '');
    nodes.push({ id: host, label: host, kind: 'ns', meta: 'nameserver' });
    edges.push({ source: domain, target: host, label: 'NS' });
  });

  // ---- Risk scoring ----
  let score = 0;
  const signals: string[] = [];
  if (phishingKits.length > 0) { score += 40; signals.push(`${phishingKits.length} phishing kit file(s) exposed`); }
  if (databases.length > 0) { score += 35; signals.push(`${databases.length} exposed database file(s)`); }
  if (attribution.apiKeys.length > 0) { score += 10; signals.push('Hardcoded API keys in page source'); }
  if (httpHeaders?.securityScore) {
    const n = parseInt(String(httpHeaders.securityScore).split('/')[0]);
    if (n < 3) score += 5;
  }
  if (attribution.telegramIds.length > 0) { score += 8; signals.push('Telegram contact IDs in page'); }
  if (score === 0 && (capture?.hasLoginForm || capture?.hasAdminPanel)) score = 2;
  const level = score >= 60 ? 'CRITICAL' : score >= 40 ? 'HIGH' : score >= 15 ? 'MEDIUM' : 'LOW';

  return {
    id, name, domain, timestamp,
    risk: { level, score },
    ip: ipList[0] || null,
    fuzzingTree, artifacts, phishingKits, databases,
    attribution, dns, whois: null,
    subdomains: subdomains.slice(0, 30),
    httpHeaders, ssl, capture,
    infrastructure: { nodes: nodes.slice(0, 60), edges: edges.slice(0, 80) },
    verdict: score === 0 ? 'No critical indicators found' : signals.join('; '),
  };
}

export const FORENSICS_PATHS = FUZZ_PATHS.map((p) => p.path);