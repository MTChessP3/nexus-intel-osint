# 🛡️ NEXUS INTEL - OSINT & Threat Intelligence Platform

<p align="center">
  <img src="https://img.shields.io/badge/Next.js-16-black?style=flat-square&logo=next.js" alt="Next.js">
  <img src="https://img.shields.io/badge/React-19-black?style=flat-square&logo=react" alt="React">
  <img src="https://img.shields.io/badge/TypeScript-5-black?style=flat-square&logo=typescript" alt="TypeScript">
  <img src="https://img.shields.io/badge/Tailwind_CSS-4-black?style=flat-square&logo=tailwindcss" alt="Tailwind CSS">
  <img src="https://img.shields.io/badge/shadcn%2FUI-latest-black?style=flat-square" alt="shadcn/ui">
</p>

<p align="center">
  <strong>Plataforma profesional de Inteligencia de Amenazas y OSINT</strong><br>
  Análisis de IPs, Dominios, CVEs, URLs, Hashes y más con resultados en tiempo real
</p>

---

## ✨ Características Principales

### 🔍 **Módulos de Análisis**

| Módulo | Descripción | API Utilizada |
|--------|-------------|---------------|
| **IP Intelligence** | Geolocalización, detección proxy/VPN, threat scoring | ip-api.com |
| **Domain Analysis** | WHOIS, DNS records, reputación, seguridad | DNS Lookup |
| **CVE Database** | Búsqueda de vulnerabilidades NIST NVD | NVD API v2.0 |
| **URL Analyzer** | Detección phishing, typosquatting, SSL | Heuristics Engine |
| **Hash Lookup** | Análisis malware multi-engine | VirusTotal/MalwareBazaar style |

### 📊 **Inteligencia de Amenazas**

- **IOC Feed** en tiempo real (IPs, dominios, URLs, hashes, emails)
- **Alertas activas** clasificadas por severidad
- **Campañas APT** monitoreadas
- **Nivel de amenaza global** calculado
- **Grupos APT** perfilados (APT28, APT29, Lazarus, FIN7, etc.)

### 📄 **Informes Ejecutivos**

- **Threat Assessment Report** - Análisis completo del landscape
- **Incident Response Report** - Post-incidente
- **Intel Briefing** - Resumen diario/semanal
- **Executive Summary** - Métricas para C-level

### 👁️ **Monitoreo Especializado**

- **Live Feed** de eventos de seguridad
- **Dark Web Monitoring** (brechas, credenciales, marketplaces)
- **Estado del sistema** en tiempo real

---

## 🚀 Despliegue Rápido

### Opción 1: Vercel (Recomendado)

```bash
# 1. Clonar el repositorio
git clone <tu-repo-url>
cd nexus-intel

# 2. Instalar dependencias
npm install

# 3. Desplegar en Vercel
npx vercel --prod
```

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=<tu-repo-url>)

### Opción 2: GitHub + Vercel Automático

1. **Push** este repositorio a GitHub
2. Ve a [vercel.com/new](https://vercel.com/new)
3. Importa el repositorio
4. Añade las variables de entorno (ver sección Configuración)
5. ¡Listo! Vercel despliega automáticamente en cada push

### Opción 3: Local

```bash
# Instalar
bun install        # o: npm install

# Desarrollo
npm run dev

# Producción
npm run build && npm start
```

Abre [http://localhost:3000](http://localhost:3000)

---

## 📁 Estructura del Proyecto

```
src/
├── app/
│   ├── api/osint/        # APIs RESTful
│   │   ├── ip/           # IP Intelligence (ip-api.com)
│   │   ├── domain/       # Domain/DNS (Google DoH + RDAP)
│   │   ├── url/          # URL Scanner
│   │   ├── hash/         # Malware Hash (MalwareBazaar/VT)
│   │   ├── cve/          # CVE/NVD Search
│   │   ├── threats/      # Threat Feeds (CISA, Abuse.ch)
│   │   ├── darkweb/      # Dark Web Intel
│   │   ├── mobile/       # Mobile Security
│   │   ├── forensics/    # Domain Forensics
│   │   ├── ai/           # AI Analyst (Groq)
│   │   ├── iocs/         # IOC Manager (persistente)
│   │   ├── sources/      # Intelligence Sources CRUD
│   │   ├── export/       # Export JSON/CSV/STIX 2.1
│   │   └── reports/      # Report Generator
│   ├── page.tsx          # Dashboard Principal
│   ├── layout.tsx        # Layout raíz
│   └── globals.css       # Estilos globales
└── lib/
    ├── kv.ts             # Persistencia Vercel KV (+ fallback memoria)
    ├── store.ts          # Store de IOCs/análisis/alertas
    ├── sources.ts        # Registro de fuentes de inteligencia
    ├── intel/            # Motor de enriquecimiento compartido
    ├── agents/           # Agentes (enrichment/analysis/reporter)
    └── ai.ts             # Cliente IA OpenAI-compatible (Groq)
```

---

## 🎯 Guía de Uso Rápido

### Analizar una IP
1. Ve a la pestaña **"IP Intel"**
2. Ingresa: `8.8.8.8` o `1.1.1.1`
3. Click **"Analyze"**
4. Obtén geolocalización, ISP, threat score

### Buscar Vulnerabilidades
1. Ve a la pestaña **"CVE"**
2. Busca: `CVE-2024-1234` o `ransomware`
3. Ver CVSS scores, CWE, referencias

### Generar Informe Ejecutivo
1. Ve a la pestaña **"Reports"**
2. Click **"Threat Assessment"**
3. Espera generación automática
4. Exporta PDF

### Monitorear IOCs
1. Ve a **"Threats"**
2. Feed en tiempo actualizado
3. Filtra por tipo (ip, domain, hash)
4. Click **"Refresh"** para actualizar

---

## 🔧 Configuración

### Variables de Entorno

Copia `.env.example` a `.env` y completa los valores. **La plataforma funciona sin ninguna
clave** — IA y persistencia usan modos de respaldo claramente etiquetados — pero para
funcionalidad completa configura:

```env
# ===== IA (OpenAI-compatible, por defecto Groq) =====
# Clave gratuita: https://console.groq.com/keys
GROQ_API_KEY=            # O AI_API_KEY
AI_BASE_URL=https://api.groq.com/openai/v1
AI_MODEL=llama-3.3-70b-versatile
AI_TEMPERATURE=0.3
AI_MAX_TOKENS=2000

# ===== Persistencia (Vercel KV / Upstash Redis) =====
# Crea un store KV en el dashboard de Vercel (se inyecta automáticamente) o Upstash.
KV_REST_API_URL=
KV_REST_API_TOKEN=

# ===== Fuentes opcionales =====
NVD_API_KEY=             # https://nvd.nist.gov/developers/request-an-api-key
VIRUSTOTAL_API_KEY=      # https://www.virustotal.com/gui/my-apikey
```

> **En Vercel**: añade `GROQ_API_KEY`, `KV_REST_API_URL`, `KV_REST_API_TOKEN`
> (y opcionalmente `NVD_API_KEY`, `VIRUSTOTAL_API_KEY`) en **Settings → Environment Variables**.

### APIs Externas Utilizadas

| Servicio | Uso | Costo |
|----------|-----|-------|
| ip-api.com | Geolocalización IP | Gratis (45 req/min) |
| Google DoH + RDAP | DNS records + WHOIS | Gratis |
| NIST NVD | Base CVEs | Gratis (mejor con key) |
| MalwareBazaar (Abuse.ch) | Hashes de malware | Gratis |
| CISA KEV / Abuse.ch SSLBL | Feeds de amenazas | Gratis |
| Groq (Llama 3.3) | Análisis IA, resúmenes, agentes | Gratis con key |
| VirusTotal | Reputación de hashes | Opcional con key |

### Registro de fuentes

La pestaña **Intelligence Sources** permite listar, probar (connectivity check),
activar/desactivar y **añadir fuentes personalizadas** (GET/POST con API key opcional).
Las fuentes built-in se siembran automáticamente y no pueden borrarse.

---

## 🧪 Pruebas

```bash
# 1. Levanta el servidor de desarrollo
bun run dev        # o: npm run dev

# 2. En otra terminal, ejecuta la suite de tests de API
node tests/api-tests.mjs
```

Los 29 tests cubren todos los módulos (IP, Domain, URL, Hash, CVE, Threat Feeds,
Dark Web, AI, IOC CRUD, Export JSON/CSV/STIX, Reports, Sources, Forensics, Mobile).
Ver `TESTING.md` para el checklist manual y los comandos CI (`tsc`, `lint`, `build`).

---

## 🎨 Diseño UI

- **Tema**: Oscuro profesional (Dark Mode)
- **Framework**: shadcn/ui + Tailwind CSS 4
- **Responsive**: Mobile-first design
- **Componentes**: Accesibles (ARIA compliant)
- **Animaciones**: Transiciones suaves Framer Motion

---

## 📈 Roadmap

- [x] Persistencia de IOCs, análisis y reportes (Vercel KV)
- [x] Agentes de IA (enrichment, analysis, reporter) con Groq
- [x] Registro de fuentes de inteligencia personalizadas
- [x] Exportación STIX 2.1 de IOCs
- [x] Historial de reportes generados
- [ ] Alertas por email/SMS/Webhook
- [ ] Safe Browsing API para verificación de URLs
- [ ] YARA rules generator
- [ ] MISP integration
- [ ] Multi-tenant support
- [ ] SSO / LDAP auth

---

## 🤝 Contribuir

1. Fork el repositorio
2. Crear rama feature (`git checkout -b feature/amazing`)
3. Commit cambios (`git commit -m 'Add amazing feature'`)
4. Push a la rama (`git push origin feature/amazing`)
5. Abrir Pull Request

---

## 📄 Licencia

MIT License - Libre para uso personal y comercial

---

## ⚡ Stack Tecnológico

- **Frontend**: Next.js 16, React 19, TypeScript 5
- **Estilos**: Tailwind CSS 4, shadcn/ui
- **APIs**: Next.js Route Handlers
- **Icons**: Lucide React
- **Deploy**: Vercel (recomendado)

---

<div align="center">

**🛡️ NEXUS INTEL** - Plataforma OSINT & Threat Intelligence Profesional

*Hecho con ❤️ para la comunidad de ciberseguridad*

</div>
