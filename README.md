# ThreatCheck

> Browser extension for instant IOC lookups across 29 threat intelligence platforms.

Select any indicator of compromise on any web page - or highlight an entire paragraph from a threat report - and instantly extract and look up every IOC across multiple platforms. No copy-pasting between tabs.

## Screenshots

<img width="1409" height="907" alt="Capture d&#39;écran 2026-04-08 152430 - Copie" src="https://github.com/user-attachments/assets/ac429f8c-906d-480b-a980-d98f2ea8106a" />

---
<img width="634" height="650" alt="Capture d&#39;écran 2026-04-08 152159" src="https://github.com/user-attachments/assets/62957fcf-50e4-4325-8bf7-0cdaa55ecbbf" />

---

<img width="1091" height="1006" alt="Capture d&#39;écran 2026-04-08 155228 - Copie" src="https://github.com/user-attachments/assets/197206d7-6e44-4d24-8547-22888aa8afd1" />

---
<img width="571" height="468" alt="Capture d&#39;écran 2026-04-08 165304" src="https://github.com/user-attachments/assets/de583c60-76e1-464f-88e8-6a3c43c993fa" />

---

<img width="1076" height="357" alt="Capture d&#39;écran 2026-04-08 165348" src="https://github.com/user-attachments/assets/3cde34ab-c0e1-46ee-94d7-639aa4826db2" />

---

<img width="625" height="250" alt="Capture d&#39;écran 2026-04-08 165443" src="https://github.com/user-attachments/assets/d57ac298-e957-4e9f-8421-04d5342e3a55" />

---

<img width="1377" height="1061" alt="image" src="https://github.com/user-attachments/assets/47f520c9-df05-487b-b689-7b4fa1a10fe2" />

---

## How it works

1. **Select** any text on any web page
2. A popup appears with detected IOC(s) and relevant lookup services
3. Click any service to open the lookup, or view auto-check results inline

ThreatCheck handles defanged indicators (`hxxps://evil[.]com`, `admin[at]evil[.]com`), bare URLs without protocol, and bulk extraction with auto-deduplication from paragraphs.

When you select a URL, ThreatCheck automatically extracts both the full URL and the domain, letting you choose which to investigate.

## Supported IOC types

| Type | Examples |
|------|---------|
| IPv4 / IPv6 | `192.168.1.1`, `2001:db8::1` |
| Domain | `evil.com`, `c2-server.example.net` |
| URL | `https://evil.com/payload`, `evil.com/path` |
| Hash | MD5, SHA-1, SHA-256 |
| Email | `admin@evil.com` |
| CVE | `CVE-2024-1234` |
| Windows Event ID | `4624`, `4688` |
| Error codes | `AADSTS50076`, `0x80070005` |

Domain detection uses the complete IANA TLD list (1,285 TLDs) to avoid false positives.

## Services (29)

### Threat Intelligence
| Service | IOC Types | API |
|---------|-----------|-----|
| VirusTotal | IP, Domain, Hash, URL, Email | Optional - enables auto-check with detection ratios, ASN, comments |
| AbuseIPDB | IP, Domain | Optional - enables auto-check with abuse score and report categories |
| AlienVault OTX | IP, Domain, Hash, URL | - |
| ThreatFox | Hash, IP | - |
| MalwareBazaar | Hash | - |
| Pulsedive | IP, Domain, URL | - |
| Recorded Future | IP, Domain, Hash, URL, Email, CVE | Optional - enables auto-check with risk scores and evidence |
| OpenCTI | IP, Domain, Hash, URL, Email, CVE | Optional - enables auto-check with relationships and reports |

### Network Intelligence
| Service | IOC Types | API |
|---------|-----------|-----|
| IPInfo | IP | - |
| Spur | IP | Optional - enables auto-check with VPN/proxy/TOR detection |
| Shodan | IP | - |
| Censys | IP | - |
| ZoomEye | IP | - |
| GreyNoise | IP | - |
| Spamhaus | IP, Domain | - |
| TOR Archive | IP | - |

### URL / Domain
| Service | IOC Types | API |
|---------|-----------|-----|
| URLScan | URL, Domain | Optional - enables auto-check with scan history |
| Wayback Machine | URL, Domain | - |
| DNSDumpster | Domain | Required - shows A, MX, NS, TXT, CNAME records with banners |
| Validin | Domain, IP | Optional - enables auto-check with DNS history |
| MXToolbox | Domain, Email | - |
| WHOIS | Domain | - |

### Code & Leaks
| Service | IOC Types | API |
|---------|-----------|-----|
| GitHub Code Search | Hash, Domain, IP, Email | - |
| LeakCheck | Email | Required - shows breach data with exposed passwords per source |

### Vulnerability
| Service | IOC Types | API |
|---------|-----------|-----|
| NVD (NIST) | CVE | - |
| MITRE CVE | CVE | - |
| Exploit-DB | CVE | - |

### Documentation
| Service | IOC Types | API |
|---------|-----------|-----|
| Microsoft Docs | Event ID, Error codes | - |

## API auto-enrichment

Most services work as direct links with no configuration needed. For deeper enrichment, you can optionally configure API keys in the extension settings. When configured, results appear directly in the popup without opening external tabs.

| Service | What you get |
|---------|-------------|
| **VirusTotal** | Detection ratio (5/72), top engine detections, ASN, reputation, domain creation date, community comments |
| **AbuseIPDB** | Abuse confidence score, report count, ISP, usage type, TOR status, report category breakdown |
| **Recorded Future** | Risk score, evidence rules with timestamps, threat context, RF Intelligence Search button |
| **OpenCTI** | Score, relationships (threat actors, malware, campaigns), reports with descriptions, source attribution |
| **Spur** | VPN/proxy/TOR tunnel detection, operator name, entry/exit IPs, client profile, infrastructure type |
| **URLScan** | Historical scan results with page details, domain, IP, server info |
| **DNSDumpster** | Host records with IPs, PTR, ASN, banners (HTTP server, TLS, apps), MX, NS, TXT, CNAME |
| **LeakCheck** | Per-breach data with cleartext passwords, usernames, emails, phone numbers, source and date |
| **Validin** | DNS history records |

## Features

- **Auto-refanging** - `hxxps://evil[.]com` and `admin[at]evil[.]com` are automatically converted to real IOCs
- **Defang copy** - one-click copy in safe format (`.` to `[.]`, `http` to `hxxp`, `@` to `[at]`)
- **Bulk extraction** - select a paragraph, all IOCs are extracted and deduplicated in a checklist
- **URL + domain splitting** - selecting a URL shows both the full URL and extracted domain as choices
- **Expandable context panels** - click any score badge to see full details without leaving the page
- **Copy list / Copy defanged** - bulk panel lets you copy all selected IOCs raw or defanged
- **Right-click context menu** - "Look up on ThreatCheck" in the right-click menu
- **Keyboard shortcut** - `Alt+T` to trigger lookup on selected text
- **Welcome page** - guided setup on first install

## Installation

### From source (Chrome / Edge / Brave)

1. Download or clone this repository
2. Open `chrome://extensions` (or `edge://extensions`)
3. Enable "Developer mode"
4. Click "Load unpacked"
5. Select the extension folder

### From Chrome Store
*publication in progress**

### Configuration

After installation, a welcome page guides you through setup. Most services work immediately with no configuration.

To enable API auto-enrichment:
1. Click the ThreatCheck icon in the toolbar
2. Click "Configure services & API keys"
3. Add your API keys for the services you want

Each service can be individually enabled or disabled.

## Privacy

- **No data collection** - ThreatCheck does not collect, store, or transmit any data
- **No telemetry** - no analytics, no tracking, no usage metrics
- **No ads** - no advertisements of any kind
- **API keys stay local** - keys are stored in your browser's local extension storage only
- **API calls go direct** - when you use API features, calls go directly from your browser to the service (VirusTotal, AbuseIPDB, etc.) with no intermediary

The only network requests ThreatCheck makes are the ones you explicitly trigger by selecting an IOC, and only to the services you have enabled.

## Development

The extension is built with vanilla JavaScript - no build step, no frameworks, no dependencies.

```
threatcheck/
  manifest.json       # MV3 extension manifest
  content.js          # IOC detection, popup UI, service registry
  background.js       # Service worker for API calls
  styles.css          # Popup and panel styles
  options.html/js     # Settings page
  popup.html/js       # Toolbar popup
  welcome.html        # Onboarding page
  icons/              # Extension icons
```

## License

MIT

## Links

- [GitHub](https://github.com/mthcht/threatcheck)
- [Report a bug](https://github.com/mthcht/threatcheck/issues)
