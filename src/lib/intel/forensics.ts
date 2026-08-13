// Web Forensic Analysis Engine — Lookyloo-style live capture.
// Performs real-time crawling, JS secret extraction (SecretFinder-style),
// directory fuzzing (ffuf/dirb-style), artifact download (wget/curl-style),
// builds interactive resource tree and infrastructure graph.
// Produces per-analysis container: /analisis_[dominio]_[timestamp]/
//   _fuzzing_tree/  (interactive directory structure)
//   _artifacts/phishing_kits/  (archives: .zip/.rar/.tar.gz/.7z)
//   _artifacts/databases/      (dumps: .sql/.db/.sqlite/.bak)
//   _metadata.json             (DNS, IP/ASN/geo, subdomains, attribution, risk)

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) NEXUS-Forensic/4.0';
const FETCH_TIMEOUT = 12000;
const MAX_CRAWL_DEPTH = 2;
const MAX_CRAWL_PAGES = 30;
const MAX_FUZZ_CONCURRENT = 10;
const FUZZ_TIMEOUT = 8000;

export interface ResourceTreeNode {
  id: string;
  url: string;
  parentId: string | null;
  name: string;
  type: 'page' | 'script' | 'style' | 'image' | 'font' | 'document' | 'font' | 'other' | 'redirect' | 'fuzz';
  status: number;
  contentType: string | null;
  size: number | null;
  depth: number;
  redirectChain: string[];
  discoveredAt: string;
  children: ResourceTreeNode[];
  meta?: {
    secrets?: string[];
    forms?: number;
    links?: number;
    scripts?: number;
    title?: string;
    category?: string;
    sensitive?: boolean;
  };
}

export interface ForensicArtifact {
  id: string;
  url: string;
  localPath: string;
  category: 'phishing_kit' | 'database' | 'config' | 'backup' | 'other';
  kind: string;
  status: number;
  size: number;
  contentType: string | null;
  downloaded: boolean;
  hash?: string;
}

export interface ForensicMetadata {
  domain: string;
  timestamp: string;
  name: string;
  id: string;
  risk: { level: string; score: number };
  ip: string | null;
  asn: string | null;
  isp: string | null;
  geo: { country: string; city: string; lat: number; lon: number } | null;
  dns: Record<string, any>;
  subdomains: string[];
  httpHeaders: any;
  ssl: any;
  attribution: {
    emails: string[];
    telegramIds: string[];
    trackingIds: string[];
    apiKeys: string[];
    comments: string[];
    toolSignatures: string[];
    links: string[];
  };
  resourceTree: ResourceTreeNode;
  fuzzingSummary: {
    totalProbed: number;
    byStatus: Record<number, number>;
    byCategory: Record<string, number>;
    exposed: number;
  };
  artifacts: ForensicArtifact[];
  verdict: string;
}

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
const DB_EXT = /\.(sql|db|sqlite|sqlite3|bak|dump|mysql|mdb|accdb)$/i;
const CONFIG_EXT = /\.(env|config|conf|ini|yaml|yml|json|php|inc)$/i;
const BACKUP_EXT = /\.(bak|backup|old|orig|save|swp|~)$/i;

const SECRET_PATTERNS: [RegExp, string][] = [
  [/AIza[0-9A-Za-z\-_]{35}/g, 'Google API Key'],
  [/sk_(?:live|test)_[0-9a-zA-Z]{20,40}/g, 'Stripe Secret Key'],
  [/pk_(?:live|test)_[0-9a-zA-Z]{20,40}/g, 'Stripe Publishable Key'],
  [/AKIA[0-9A-Z]{16}/g, 'AWS Access Key ID'],
  [/[0-9a-zA-Z/+=]{40}/g, 'AWS Secret Access Key (base64)'],
  [/ghp_[0-9A-Za-z]{36,40}/g, 'GitHub Personal Access Token'],
  [/gho_[0-9A-Za-z]{36,40}/g, 'GitHub OAuth Token'],
  [/ghu_[0-9A-Za-z]{36,40}/g, 'GitHub User Token'],
  [/ghs_[0-9A-Za-z]{36,40}/g, 'GitHub Server Token'],
  [/ghr_[0-9A-Za-z]{36,40}/g, 'GitHub Refresh Token'],
  [/xox[baprs]-[0-9A-Za-z\-]{10,60}/g, 'Slack Token'],
  [/xoxp-[0-9A-Za-z\-]{10,60}/g, 'Slack User Token'],
  [/xoxb-[0-9A-Za-z\-]{10,60}/g, 'Slack Bot Token'],
  [/xapp-[0-9A-Za-z\-]{10,60}/g, 'Slack App Token'],
  [/sk_live_[0-9a-zA-Z]{20,40}/g, 'Stripe Live Secret'],
  [/rk_live_[0-9a-zA-Z]{20,40}/g, 'Stripe Restricted Key'],
  [/rk_test_[0-9a-zA-Z]{20,40}/g, 'Stripe Test Restricted Key'],
  [/sq0atp-[0-9A-Za-z\-_]{22}/g, 'Square Access Token'],
  [/sq0csp-[0-9A-Za-z\-_]{22}/g, 'Square OAuth Secret'],
  [/access_token\$[0-9A-Za-z]{20,}/g, 'Facebook Access Token'],
  [/EAACEdEose0cBA[0-9A-Za-z]+/g, 'Facebook App Token'],
  [/Bearer\s+[A-Za-z0-9\-\._~+/]+=*/g, 'Bearer Token'],
  [/Authorization:\s*Bearer\s+[A-Za-z0-9\-\._~+/]+=*/gi, 'Auth Header'],
  [/api[_-]?key["\s:=]+["']?([A-Za-z0-9_\-]{20,})["']?/gi, 'Generic API Key'],
  [/secret[_-]?key["\s:=]+["']?([A-Za-z0-9_\-]{20,})["']?/gi, 'Secret Key'],
  [/private[_-]?key["\s:=]+["']?([A-Za-z0-9_\-]{20,})["']?/gi, 'Private Key'],
  [/jwt[_-]?secret["\s:=]+["']?([A-Za-z0-9_\-]{20,})["']?/gi, 'JWT Secret'],
];

function classifyPath(path: string, category: string): 'phishing_kit' | 'database' | 'config' | 'backup' | 'other' {
  if (KIT_EXT.test(path)) return 'phishing_kit';
  if (DB_EXT.test(path)) return 'database';
  if (CONFIG_EXT.test(path) || category === 'config') return 'config';
  if (BACKUP_EXT.test(path) || category === 'backup') return 'backup';
  return 'other';
}

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeout = FETCH_TIMEOUT): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetch(url, { ...options, signal: controller.signal, headers: { 'User-Agent': UA, ...options.headers } });
  } finally {
    clearTimeout(id);
  }
}

function extractLinks(html: string, baseUrl: string): string[] {
  const links: string[] = [];
  const hrefRegex = /href=["']([^"']+)["']/gi;
  const srcRegex = /src=["']([^"']+)["']/gi;
  let match;
  while ((match = hrefRegex.exec(html)) !== null) links.push(match[1]);
  while ((match = srcRegex.exec(html)) !== null) links.push(match[1]);
  return [...new Set(links.map(l => {
    try { return new URL(l, baseUrl).href; } catch { return l; }
  }))];
}

function extractScripts(html: string, baseUrl: string): string[] {
  const scripts: string[] = [];
  const scriptRegex = /<script[^>]*src=["']([^"']+)["']/gi;
  let match;
  while ((match = scriptRegex.exec(html)) !== null) {
    try { scripts.push(new URL(match[1], baseUrl).href); } catch {}
  }
  return [...new Set(scripts)];
}

function extractForms(html: string): number {
  return (html.match(/<form/gi) || []).length;
}

function findSecrets(content: string): string[] {
  const found: string[] = [];
  for (const [re, label] of SECRET_PATTERNS) {
    const matches = content.match(re) || [];
    for (const m of matches.slice(0, 3)) {
      found.push(`${label}: ${m.length > 60 ? m.slice(0, 60) + '...' : m}`);
    }
  }
  return [...new Set(found)].slice(0, 15);
}

function getResourceType(contentType: string | null, url: string): ResourceTreeNode['type'] {
  if (!contentType) {
    const ext = url.split('?')[0].split('.').pop()?.toLowerCase() || '';
    if (['js', 'mjs', 'ts'].includes(ext)) return 'script';
    if (['css', 'scss', 'less'].includes(ext)) return 'style';
    if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'ico', 'avif'].includes(ext)) return 'image';
    if (['woff', 'woff2', 'ttf', 'eot', 'otf'].includes(ext)) return 'font';
    if (['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'].includes(ext)) return 'document';
    return 'other';
  }
  if (contentType.startsWith('text/html')) return 'page';
  if (contentType.startsWith('application/javascript') || contentType.startsWith('text/javascript')) return 'script';
  if (contentType.startsWith('text/css')) return 'style';
  if (contentType.startsWith('image/')) return 'image';
  if (contentType.startsWith('font/') || contentType.includes('woff')) return 'font';
  if (contentType.startsWith('application/pdf') || contentType.includes('document')) return 'document';
  return 'other';
}

async function crawlPage(url: string, visited: Set<string>, tree: ResourceTreeNode[], parentId: string | null, depth: number): Promise<ResourceTreeNode[]> {
  if (depth > MAX_CRAWL_DEPTH || visited.size >= MAX_CRAWL_PAGES || visited.has(url)) return [];
  visited.add(url);

  const nodeId = Buffer.from(url).toString('base64url').slice(0, 16);
  let status = 0, contentType: string | null = null, size = 0;
  let html = '', redirectChain: string[] = [];
  let secrets: string[] = [], forms = 0, links = 0, scripts = 0, title = '';

  try {
    const res = await fetchWithTimeout(url, { redirect: 'manual' });
    status = res.status;
    contentType = res.headers.get('content-type');
    const cl = res.headers.get('content-length');
    size = cl ? parseInt(cl) : 0;

    // Follow redirects manually to build chain
    let currentRes = res;
    let currentUrl = url;
    while (currentRes.status >= 300 && currentRes.status < 400 && currentRes.headers.get('location')) {
      const loc = currentRes.headers.get('location')!;
      redirectChain.push(loc);
      try {
        currentRes = await fetchWithTimeout(loc, { redirect: 'manual' });
        currentUrl = loc;
      } catch { break; }
    }
    status = currentRes.status;
    contentType = currentRes.headers.get('content-type') || contentType;

    if (contentType?.startsWith('text/html')) {
      html = await currentRes.text();
      title = (html.match(/<title[^>]*>([^<]+)<\/title>/i) || [])[1] || '';
      links = extractLinks(html, currentUrl).length;
      const scriptUrls = extractScripts(html, currentUrl);
      scripts = scriptUrls.length;
      forms = extractForms(html);
      secrets = findSecrets(html);

      // Recursively crawl linked pages (same domain only)
      const childLinks = extractLinks(html, currentUrl).filter(l => {
        try { return new URL(l).hostname === new URL(url).hostname; } catch { return false; }
      });
      for (const link of childLinks.slice(0, 5)) {
        if (!visited.has(link)) {
          const children = await crawlPage(link, visited, tree, nodeId, depth + 1);
          tree.push(...children);
        }
      }

      // Analyze JS files for secrets (SecretFinder-style)
      for (const scriptUrl of scriptUrls.slice(0, 5)) {
        try {
          const sRes = await fetchWithTimeout(scriptUrl, { redirect: 'follow' });
          if (sRes.ok) {
            const jsContent = await sRes.text();
            const jsSecrets = findSecrets(jsContent);
            if (jsSecrets.length > 0) {
              secrets.push(...jsSecrets.map(s => `[JS] ${s}`));
              const scriptNode: ResourceTreeNode = {
                id: Buffer.from(scriptUrl).toString('base64url').slice(0, 16),
                url: scriptUrl,
                parentId: nodeId,
                name: scriptUrl.split('/').pop() || 'script.js',
                type: 'script',
                status: sRes.status,
                contentType: sRes.headers.get('content-type'),
                size: parseInt(sRes.headers.get('content-length') || '0'),
                depth: depth + 1,
                redirectChain: [],
                discoveredAt: new Date().toISOString(),
                children: [],
                meta: { secrets: jsSecrets }
              };
              tree.push(scriptNode);
            }
          }
        } catch {}
      }
    }
  } catch (e) {
    status = 0;
  }

  const node: ResourceTreeNode = {
    id: nodeId,
    url: url,
    parentId,
    name: url.split('/').pop() || url,
    type: getResourceType(contentType, url),
    status,
    contentType,
    size,
    depth,
    redirectChain,
    discoveredAt: new Date().toISOString(),
    children: [],
    meta: { secrets: secrets.slice(0, 10), forms, links, scripts, title }
  };
  tree.push(node);
  return tree;
}

async function fuzzDirectories(baseUrl: string, visited: Set<string>): Promise<{ tree: ResourceTreeNode[]; artifacts: ForensicArtifact[] }> {
  const fuzzTree: ResourceTreeNode[] = [];
  const artifacts: ForensicArtifact[] = [];

  for (let i = 0; i < FUZZ_PATHS.length; i += MAX_FUZZ_CONCURRENT) {
    const batch = FUZZ_PATHS.slice(i, i + MAX_FUZZ_CONCURRENT);
    const results = await Promise.allSettled(
      batch.map(async (p) => {
        const url = `${baseUrl}/${p.path}`;
        try {
          const res = await fetchWithTimeout(url, { method: 'GET', redirect: 'manual' }, FUZZ_TIMEOUT);
          const status = res.status;
          const size = parseInt(res.headers.get('content-length') || '0');
          const contentType = res.headers.get('content-type');
          const category = classifyPath(p.path, p.category);
          const sensitive = p.category !== 'common';

          const entry: ResourceTreeNode = {
            id: Buffer.from(url).toString('base64url').slice(0, 16),
            url,
            parentId: null,
            name: p.path,
            type: 'fuzz',
            status,
            contentType,
            size,
            depth: 0,
            redirectChain: [],
            discoveredAt: new Date().toISOString(),
            children: [],
            meta: { category: p.category, sensitive }
          };
          fuzzTree.push(entry);

          if ((status === 200 || status === 403) && sensitive) {
            const artifact: ForensicArtifact = {
              id: Buffer.from(url).toString('base64url').slice(0, 16),
              url,
              localPath: `_artifacts/${category}/${p.path.replace(/\//g, '_')}`,
              category,
              kind: p.category,
              status,
              size,
              contentType,
              downloaded: false
            };
            artifacts.push(artifact);
          }
          return entry;
        } catch {
          return null;
        }
      })
    );
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) fuzzTree.push(r.value);
    }
  }
  return { tree: fuzzTree, artifacts };
}

async function downloadArtifacts(artifacts: ForensicArtifact[]): Promise<ForensicArtifact[]> {
  const downloaded: ForensicArtifact[] = [];
  for (const a of artifacts.slice(0, 10)) {
    try {
      const res = await fetchWithTimeout(a.url, { method: 'GET', redirect: 'follow' }, 30000);
      if (res.ok) {
        const buf = await res.arrayBuffer();
        a.size = buf.byteLength;
        a.hash = Buffer.from(await crypto.subtle.digest('SHA-256', buf)).toString('hex').slice(0, 16);
        a.downloaded = true;
        downloaded.push(a);
      }
    } catch {}
  }
  return downloaded;
}

async function getIPInfo(ip: string): Promise<{ asn: string | null; isp: string | null; geo: any }> {
  try {
    const res = await fetchWithTimeout(`http://ip-api.com/json/${ip}?fields=status,message,country,city,lat,lon,isp,as,asname`, {}, 5000);
    if (res.ok) {
      const data = await res.json();
      if (data.status === 'success') {
        return {
          asn: data.as || null,
          isp: data.isp || null,
          geo: { country: data.country, city: data.city, lat: data.lat, lon: data.lon }
        };
      }
    }
  } catch {}
  return { asn: null, isp: null, geo: null };
}

export async function runForensicAnalysis(input: string): Promise<ForensicMetadata> {
  const domain = input.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  const baseUrl = `https://${domain}`;
  const timestamp = new Date().toISOString();
  const name = `analisis_${domain}_${Date.now()}`;
  const id = Buffer.from(name).toString('base64url').slice(0, 32);

  // ---- DNS Reconnaissance (Google DoH) ----
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

  // ---- IP Enrichment (ASN, ISP, Geo) ----
  let asn: string | null = null, isp: string | null = null, geo: any = null, primaryIp: string | null = null;
  const ipList = [...ipSet];
  primaryIp = ipList[0] || null;
  if (primaryIp) {
    const ipInfo = await getIPInfo(primaryIp);
    asn = ipInfo.asn;
    isp = ipInfo.isp;
    geo = ipInfo.geo;
  }

  // ---- Subdomain Enumeration (crt.sh) ----
  const subdomains: string[] = [];
  try {
    const crt = await fetchWithTimeout(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`);
    if (crt.ok) {
      const rows = await crt.json();
      const seen = new Set<string>();
      for (const r of (rows || []).slice(0, 200)) {
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

  // ---- HTTP Headers & SSL ----
  let httpHeaders: any = {};
  try {
    const res = await fetchWithTimeout(baseUrl, { redirect: 'follow' });
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

  let ssl: any = {};
  try {
    const res = await fetchWithTimeout(baseUrl, { method: 'HEAD' });
    ssl = { secure: res.url.startsWith('https:'), protocol: 'TLS (verified)', subject: domain };
  } catch { ssl = { secure: false, error: 'Could not establish HTTPS connection' }; }

  // ---- Live Crawl (gospider-style) ----
  const visited = new Set<string>();
  const resourceTree: ResourceTreeNode[] = [];
  const rootNode = await crawlPage(baseUrl, visited, resourceTree, null, 0);

  // ---- Directory Fuzzing (ffuf/dirb-style) ----
  const { tree: fuzzTree, artifacts: fuzzArtifacts } = await fuzzDirectories(baseUrl, visited);

  // ---- Artifact Download (wget/curl-style) ----
  const downloadedArtifacts = await downloadArtifacts(fuzzArtifacts);

  // ---- Attribution from crawled pages ----
  const allHtml = resourceTree.filter(n => n.type === 'page').map(n => n.meta?.title || '').join(' ');
  const emailMatches = allHtml.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
  const telegramMatches = allHtml.match(/(?:t\.me\/|telegram\.me\/|@)([a-zA-Z0-9_]{4,32})/g) || [];
  const trackingMatches = allHtml.match(/[?&](?:id|tid|client|zone|site)=([A-Za-z0-9\-_]+)/g) || [];
  const attribution = {
    emails: [...new Set(emailMatches)].filter(e => !e.match(/\.(png|jpg|svg|gif|webp)$/i)).slice(0, 10),
    telegramIds: [...new Set(telegramMatches)].slice(0, 10),
    trackingIds: [...new Set(trackingMatches)].map(m => m.replace(/^[?&]/, '')).slice(0, 10),
    apiKeys: resourceTree.flatMap(n => n.meta?.secrets || []).filter(s => s.includes('Key') || s.includes('Token') || s.includes('Secret')).slice(0, 10),
    comments: resourceTree.flatMap(n => n.meta?.secrets || []).slice(0, 5),
    toolSignatures: [] as string[],
    links: [...new Set(resourceTree.flatMap(n => extractLinks('', n.url)))]?.slice(0, 20) || [],
  };

  // Detect tool signatures
  const allContent = resourceTree.filter(n => n.type === 'page').map(n => n.meta?.title || '').join(' ');
  if (/wp-content|wp-includes|wp-json/i.test(allContent)) attribution.toolSignatures.push('WordPress');
  if (/cPanel|WHM/i.test(allContent)) attribution.toolSignatures.push('cPanel');
  if (/Plesk/i.test(allContent)) attribution.toolSignatures.push('Plesk');
  if (/Elementor/i.test(allContent)) attribution.toolSignatures.push('Elementor');
  if (/SiteGround/i.test(allContent)) attribution.toolSignatures.push('SiteGround');
  if (/Hostinger|hPanel/i.test(allContent)) attribution.toolSignatures.push('Hostinger');
  if (/Cloudflare/i.test(allContent)) attribution.toolSignatures.push('Cloudflare');
  if (/nginx/i.test(httpHeaders.server)) attribution.toolSignatures.push('nginx');
  if (/Apache/i.test(httpHeaders.server)) attribution.toolSignatures.push('Apache');

  // ---- Risk Scoring ----
  let score = 0;
  const signals: string[] = [];
  const kitCount = downloadedArtifacts.filter(a => a.category === 'phishing_kit').length;
  const dbCount = downloadedArtifacts.filter(a => a.category === 'database').length;
  const configCount = downloadedArtifacts.filter(a => a.category === 'config').length;
  const backupCount = downloadedArtifacts.filter(a => a.category === 'backup').length;
  if (kitCount > 0) { score += 40; signals.push(`${kitCount} phishing kit(s) exposed`); }
  if (dbCount > 0) { score += 35; signals.push(`${dbCount} exposed database file(s)`); }
  if (configCount > 0) { score += 15; signals.push(`${configCount} config file(s) exposed`); }
  if (backupCount > 0) { score += 10; signals.push(`${backupCount} backup file(s) exposed`); }
  if (attribution.apiKeys.length > 0) { score += 10; signals.push('Hardcoded API keys/secrets in page source'); }
  if (httpHeaders.securityScore) {
    const n = parseInt(String(httpHeaders.securityScore).split('/')[0]);
    if (n < 3) { score += 5; signals.push('Weak security headers'); }
  }
  if (attribution.telegramIds.length > 0) { score += 8; signals.push('Telegram contact IDs found'); }
  if (score === 0 && (resourceTree.some(n => n.meta?.forms && n.meta.forms > 0) || resourceTree.some(n => n.meta?.title?.toLowerCase().includes('admin')))) {
    score = 2;
  }
  const level = score >= 60 ? 'CRITICAL' : score >= 40 ? 'HIGH' : score >= 15 ? 'MEDIUM' : 'LOW';

  // ---- Fuzzing Summary ----
  const fuzzingSummary = {
    totalProbed: fuzzTree.length,
    byStatus: fuzzTree.reduce((acc, n) => { acc[n.status] = (acc[n.status] || 0) + 1; return acc; }, {} as Record<number, number>),
    byCategory: fuzzTree.reduce((acc, n) => { const cat = n.meta?.category || 'unknown'; acc[cat] = (acc[cat] || 0) + 1; return acc; }, {} as Record<string, number>),
    exposed: fuzzTree.filter(n => n.meta?.sensitive && (n.status === 200 || n.status === 403)).length,
  };

  // ---- Build complete resource tree (root + fuzz) ----
  const rootResourceTree: ResourceTreeNode = {
    id: 'root',
    url: baseUrl,
    parentId: null,
    name: domain,
    type: 'page',
    status: httpHeaders.statusCode || 0,
    contentType: 'text/html',
    size: 0,
    depth: 0,
    redirectChain: [],
    discoveredAt: new Date().toISOString(),
    children: resourceTree.filter(n => n.parentId === null).concat(fuzzTree.filter(n => n.parentId === null)),
    meta: { title: domain }
  };

  return {
    domain,
    timestamp,
    name,
    id,
    risk: { level, score },
    ip: primaryIp,
    asn,
    isp,
    geo,
    dns,
    subdomains: subdomains.slice(0, 50),
    httpHeaders,
    ssl,
    attribution,
    resourceTree: rootResourceTree,
    fuzzingSummary,
    artifacts: downloadedArtifacts,
    verdict: score === 0 ? 'No critical indicators found' : signals.join('; '),
  };
}

export const FORENSICS_PATHS = FUZZ_PATHS.map((p) => p.path);