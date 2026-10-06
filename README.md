# nowii·sentinel — Security Operations Center

[![License: MIT](https://img.shields.io/badge/License-MIT-06b6d4.svg)](https://opensource.org/licenses/MIT)
[![HTML5](https://img.shields.io/badge/HTML5-E34F26?logo=html5&logoColor=white)](https://developer.mozilla.org/it/docs/Web/HTML)
[![CSS3](https://img.shields.io/badge/CSS3-1572B6?logo=css3&logoColor=white)](https://developer.mozilla.org/it/docs/Web/CSS)
[![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?logo=javascript&logoColor=black)](https://developer.mozilla.org/it/docs/Web/JavaScript)

Una piattaforma **Security Operations Center (SOC)** enterprise costruita con **HTML, CSS e JavaScript puri**. Nessuna dipendenza esterna, nessun backend.

## ✨ Funzionalità

- **Attack surface map** live con archi di attacco da 12 paesi in tempo reale
- **Live threat feed** con streaming attacchi e controlli pausa/riprendi
- **Threat severity ring** canvas con distribuzione per severità
- **Threat intelligence** con tabella filtrabile, sort e bulk actions
- **Incident response** completo con workflow NIST 800-61 (open → investigating → contained → resolved)
- **Vulnerability management** con CVE, scoring CVSS v3.1 e status tracking
- **Log analyzer** in stile terminal con streaming, filtri e auto-scroll
- **Response playbooks** SOAR con step eseguibili
- **Compliance dashboard** per 6 framework (ISO 27001, SOC 2, GDPR, PCI DSS, NIST CSF, HIPAA)
- **Command Palette** (⌘K) con ricerca su threat, incident, CVE, comandi
- **Multi-tenant** con switcher workspace
- **Centro notifiche** con badge contatore e mark-as-read
- **Export CSV/JSON** reale di threat, log e dati completi
- **Auto-response** per blocco automatico IP malevoli
- **Sound alerts** per minacce critiche
- **Tema chiaro/scuro** con densità personalizzabile
- **Onboarding tour** alla prima apertura
- **MITRE ATT&CK** tagging sulle tecniche di attacco
- **Scorciatoie tastiera** complete

## 🛠 Tecnologie

- HTML5
- CSS3 (Grid, Flexbox, animazioni, backdrop-filter, custom properties)
- JavaScript (ES6+, Canvas 2D API, localStorage, MutationObserver, Event Delegation)
- Web Audio API (alert sonori)
- Clipboard API (copy IOC)

## 📖 Scorciatoie

| Tasto | Azione |
|---|---|
| `⌘ K` / `Ctrl K` | Command Palette |
| `1` - `7` | Naviga tra le viste |
| `R` | Aggiorna dati |
| `T` | Cambia tema |
| `N` | Nuovo incidente |
| `P` | Pausa/riprendi feed |
| `?` | Aiuto e scorciatoie |
| `ESC` | Chiudi modali |

## 🚀 Deploy

Basta aprire `index.html` nel browser. Per GitHub Pages:

1. Settings → Pages
2. Branch: `main`, cartella `/` (root)
3. Salva

Demo live: `https://nowii-core.github.io/nowii-sentinel/`

## 🎯 Cosa dimostra

- Comprensione dei workflow SOC reali (threat hunting, incident response, vulnerability management)
- Conoscenza di framework di sicurezza (MITRE ATT&CK, NIST, ISO 27001, SOC 2, GDPR)
- Capacità di costruire interfacce dati-intensive con canvas custom e gestione stato complessa
- Attenzione al dettaglio enterprise (multi-tenant, RBAC, audit, notifiche, onboarding)

## 📫 Contatti

- GitHub: [@nowii-core](https://github.com/nowii-core)
