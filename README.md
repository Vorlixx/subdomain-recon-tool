# 🕸️ Subdomain & Attack Surface Recon Tool

A modular, high-performance reconnaissance toolkit written in Python that
discovers subdomains, identifies live hosts, scans common service ports,
fingerprints web technologies and generates professional reports — all
from a single command. 🚀

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)
![CLI](https://img.shields.io/badge/CLI-argparse-brightgreen)
![Async](https://img.shields.io/badge/Async-httpx%20%2B%20asyncio-important)

> ⚖️ **Legal notice:** Use this tool only against systems you own or are
> explicitly authorized to test. Unauthorized scanning may be illegal.

---

## ✨ Features

| Phase | Capability |
|-------|------------|
| 1️⃣ Enumeration | Passive discovery via **crt.sh** certificate transparency logs + active **DNS brute-force** with wildcard-record detection |
| 2️⃣ Live check | Concurrent **HTTPS/HTTP probing** (HTTPS first, automatic HTTP fallback) with status, title, redirect chain and headers capture |
| 3️⃣ Port scan | Fast **TCP connect-based scanner** across 34 common service ports (customizable with `-p`) |
| 4️⃣ Fingerprinting | **Technology detection** (20 header rules + 40 body rules) and **banner grabbing** for non-HTTP services (SSH, FTP, SMTP, MySQL, Redis, ...) |
| 5️⃣ Reporting | Machine-readable **JSON** + self-contained **HTML dashboard** (dark theme, stat cards, live filtering) + colorful **Rich CLI** output |

Additional highlights:

- ⚡ **High throughput**: `asyncio` for HTTP probing, `ThreadPoolExecutor` for DNS brute-force, port scanning and banner grabbing.
- 🛡️ **Robust error handling**: per-operation timeouts, connection errors, SSL/TLS failures and DNS edge cases (NXDOMAIN, NoAnswer, NoNameservers, lifetime timeouts) never crash the scan.
- 📦 **Bounded resources**: body samples capped at 200 KB, crt.sh results capped at 500 entries, configurable concurrency everywhere.
- 🃏 **Wildcard protection**: a random-token probe detects catch-all DNS records so phantom subdomains are filtered out.
- 💾 **Portable output**: the HTML report is fully self-contained — no CDN assets, no internet connection required to view it.

---

## 📂 Project structure

```
subdomain-recon-tool/
├── main.py                      # CLI entry point (argparse) — orchestrates the 5 phases
├── requirements.txt             # Python dependencies
├── wordlists/
│   └── subdomains.txt           # 210 common subdomain labels (editable)
├── recon/
│   ├── __init__.py              # package metadata / version
│   ├── models.py                # Subdomain & ReconReport dataclasses (shared state)
│   ├── subdomain_enum.py        # Module 1: crt.sh passive + DNS brute-force
│   ├── live_check.py            # Module 2: HTTP(S) probing + TCP port scanning
│   ├── fingerprint.py           # Module 3: tech fingerprinting + banner grabbing
│   └── reporter.py              # Module 4: Rich CLI, JSON and HTML reporters
└── recon_output/                # generated reports (JSON + HTML) — created at runtime
```

### 🧠 Design notes

- **One object per host**: every enrichment step writes into a single
  `Subdomain` dataclass, keeping the modules decoupled and the report
  consistent.
- **Modularity**: each module can be imported and used standalone from
  your own scripts (see [Library usage](#-library-usage)).
- **Type-safe**: full type hints + docstrings throughout; Python 3.9+.

---

## ⚙️ Installation

Requires **Python 3.9+** (tested on 3.13).

```bash
git clone https://github.com/<your-user>/subdomain-recon-tool.git
cd subdomain-recon-tool
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
python main.py -d example.com
```

The same scan with an explicit wordlist and custom output directory:

```bash
python main.py -d example.com -w wordlists/subdomains.txt -o ./recon_output
```

Passive-only reconnaissance (no traffic to the target's DNS):

```bash
python main.py -d example.com --passive-only --no-port-scan
```

Full control example — custom ports, tighter timeouts, more HTTP concurrency:

```bash
python main.py -d example.com -p 80 443 8080 8443 22 --timeout 5 --http-concurrency 50 --threads 100 -v
```

### 🎛️ Command line options

| Option | Description | Default |
|--------|-------------|---------|
| `-d, --domain` | Target root domain (required) | — |
| `-w, --wordlist` | Brute-force wordlist path (one label per line) | `wordlists/subdomains.txt` |
| `-o, --output` | Directory for JSON/HTML reports | `recon_output` |
| `-t, --threads` | DNS brute-force concurrency | `50` |
| `--http-concurrency` | Max concurrent HTTP(S) probes | `20` |
| `--timeout` | DNS/HTTP/socket timeout (seconds) | `3.0` |
| `-r, --resolver` | DNS resolver for active enumeration | `8.8.8.8` |
| `-p, --ports` | Ports to scan (space-separated) | built-in 34-port set |
| `--passive-only` | Skip DNS brute-force (crt.sh only) | off |
| `--active-only` | Skip crt.sh (brute-force only) | off |
| `--no-port-scan` | Skip TCP port scanning | off |
| `--no-fingerprint` | Skip fingerprinting & banner grabbing | off |
| `--no-color` | Disable ANSI colors | off |
| `-v, --verbose` | Verbose / debug logging | off |
| `--version` | Show version and exit | — |

### 📁 Output files

After a scan the output directory contains:

- 📄 **`report.json`** — full machine-readable results (schema below).
- 🖥️ **`report.html`** — self-contained dashboard: stat cards (subdomains,
  alive hosts, unique IPs, open ports, technologies), an alive/dead
  distribution bar, and a filterable table (search box + alive/source
  dropdowns). Open it in any browser, no server required.

### 🧾 JSON report schema

```json
{
  "domain": "example.com",
  "scan_started_at": "2026-08-17T12:00:00+00:00",
  "scan_duration_seconds": 12.4,
  "tool": { "name": "subdomain-recon-tool", "version": "1.0.1" },
  "stats": {
    "total_subdomains": 3,
    "alive_hosts": 1,
    "resolved_hosts": 2,
    "unique_ips": 2,
    "open_ports": 5,
    "technologies_found": 4,
    "passive_findings": 2,
    "active_findings": 1,
    "duration_seconds": 12.4
  },
  "subdomains": [
    {
      "name": "www.example.com",
      "source": "crt.sh, bruteforce",
      "resolved_ips": ["93.184.216.34"],
      "alive": true,
      "http_status": 200,
      "page_title": "Example Domain",
      "final_url": "https://www.example.com/",
      "server_header": "ECS (dcb/7F83)",
      "response_headers": { "content-type": "text/html; charset=UTF-8" },
      "body_sample": "<!doctype html>...",
      "open_ports": [80, 443],
      "port_banners": {},
      "technologies": ["Amazon CloudFront", "Nginx"]
    }
  ]
}
```

---

## 🔍 How it works

1. **Enumeration** — crt.sh is queried for certificates matching
   `%.<domain>`; names are de-duplicated and wildcard prefixes stripped.
   In parallel, each wordlist label is resolved against your chosen DNS
   server. A random-label probe first detects wildcard DNS so catch-all
   records do not flood the results.
2. **Live checking** — every resolved host is requested over HTTPS first;
   on timeout/TLS/connection failure it falls back to HTTP. The final URL,
   status code, `<title>`, headers and a 200 KB body sample are captured.
3. **Port scanning** — unique IPs are scanned with a connect-based scanner
   (34 default ports, parallel workers, per-port timeout). Open ports are
   mapped back to every subdomain sharing that IP.
4. **Fingerprinting** — response headers and body are matched against
   curated regex rules (Nginx, Apache, WordPress, React, Vue, Laravel,
   Cloudflare, ...). Open non-HTTP ports are probed for service banners
   (SSH, FTP, SMTP, MySQL, Redis, ...).
5. **Reporting** — everything is aggregated into `Subdomain` objects and
   written out as JSON + HTML; the CLI prints a summary table and stats.

---

## 🧑‍💻 Library usage

Every module is importable on its own:

```python
import asyncio
from recon.subdomain_enum import SubdomainEnumerator
from recon.live_check import LiveHostChecker
from recon.fingerprint import TechnologyFingerprinter

async def recon(domain: str):
    enumerator = SubdomainEnumerator(domain, max_workers=50)
    subdomains = await enumerator.enumerate_all()

    await LiveHostChecker(timeout=3.0, concurrency=20).check_many(subdomains)

    for subdomain in subdomains:
        subdomain.technologies = TechnologyFingerprinter().fingerprint(subdomain)

    return subdomains

hosts = asyncio.run(recon("example.com"))
```

---

## 🧬 Customizing fingerprint rules

Fingerprint rules live in `recon/fingerprint.py`:

- `HEADER_RULES`: `{header_name: [(regex, technology), ...]}`
- `BODY_RULES`: `[(regex, technology), ...]`

Add your own entry, for example:

```python
BODY_RULES.append((re.compile(r"myapp-version=\d+", re.I), "MyApp"))
```

---

## ⚡ Performance & reliability notes

- DNS brute-force scales with `--threads`; HTTP probing with `--http-concurrency`.
- Every network operation has a bounded timeout; slow or dead services are skipped, never fatal.
- crt.sh is a free public service and can be slow or rate-limited — passive requests are retried up to 3 times with exponential backoff, and failures are logged as warnings that never abort the scan.
- Body samples are capped at 200 KB per host to keep memory usage flat on large engagements.

---

## 🔐 Security & TLS notes

- The live-host checker connects with certificate validation disabled
  (`verify=False`). This is deliberate: internal and staging hosts often use
  self-signed or expired certificates, and the tool only inspects response
  metadata (status code, title, headers) — it never transmits credentials.
  If you need strict validation, set `verify=True` in `recon/live_check.py`.
- 🚫 Only run this tool against systems you own or are explicitly authorized
  to test. Unauthorized scanning is illegal in most jurisdictions and can
  be treated as an attack.

---

## 📜 License

MIT — use it, learn from it, improve it. See `LICENSE` for details. 🎉
