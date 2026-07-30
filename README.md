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

1. **Fork** este repositorio
2. Ve a [vercel.com/new](https://vercel.com/new)
3. Importa tu fork
4. ¡Listo! Vercel despliegue automáticamente

### Opción 3: Docker

```bash
docker build -t nexus-intel .
docker run -p 3000:3000 nexus-intel
```

### Opción 4: Local

```bash
# Instalar
npm install

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
│   │   ├── ip/route.ts   # IP Intelligence API
│   │   ├── domain/route.ts # Domain Analysis API
│   │   ├── cve/route.ts  # CVE/NVD Search API
│   │   ├── url/route.ts  # URL Security API
│   │   ├── hash/route.ts # Malware Hash API
│   │   ├── threats/route.ts # Threat Intel API
│   │   └── reports/route.ts # Report Generator API
│   ├── page.tsx          # Dashboard Principal
│   ├── layout.tsx        # Layout raíz
│   └── globals.css       # Estilos globales
├── components/
│   └── ui/               # Componentes shadcn/ui
├── hooks/                # Custom React hooks
└── lib/                  # Utilidades
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

### Variables de Entorno (Opcionales)

```env
# Para producción, crear .env.local
NEXT_PUBLIC_API_KEY=tu-api-key  # Opcional, para APIs premium
NEXT_PUBLIC_ANALYTICS_ID=id     # Opcional, para analytics
```

### APIs Externas Utilizadas

| Servicio | Uso | Costo |
|----------|-----|-------|
| ip-api.com | Geolocalización IP | Gratis (45 req/min) |
| NIST NVD | Base CVEs | Gratis (sin límite) |
| Page Reader | Contenido web | Incluido SDK |

---

## 🎨 Diseño UI

- **Tema**: Oscuro profesional (Dark Mode)
- **Framework**: shadcn/ui + Tailwind CSS 4
- **Responsive**: Mobile-first design
- **Componentes**: Accesibles (ARIA compliant)
- **Animaciones**: Transiciones suaves Framer Motion

---

## 📈 Roadmap

- [ ] Integración VirusTotal API real
- [ ] Alertas por email/SMS/Webhook
- [ ] Historial de análisis guardado
- [ ] Exportación STIX/TAXII de IOCs
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
