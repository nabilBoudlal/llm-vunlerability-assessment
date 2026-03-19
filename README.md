# LLM-based Vulnerability Assessment — ReAct Agent

A ReAct-based agent that autonomously researches vulnerabilities from Nmap and Nessus scan outputs, querying eight external security intelligence sources and producing structured Excel reports with clickable CVE hyperlinks. Every CVE identifier in the output is traceable to a live tool observation — fabricated identifiers are architecturally impossible.

---

## Overview

Traditional vulnerability scanners enumerate findings efficiently but leave risk interpretation entirely to the analyst. This prototype assigns that interpretive role to a language model acting as an **autonomous research orchestrator**: it reads a normalised scan, decides which intelligence sources to query, iterates until all services are covered, and produces a structured report grounded exclusively in retrieved evidence.

The system implements the **ReAct pattern** (Yao et al., 2022) — alternating Thought, Action, and Observation steps — with deterministic Python-level safety nets that correct known LLM failure modes without constraining the model's research strategy.

---

## Architecture

```
Nmap XML / Nessus CSV
        │
        ▼
  ParserFactory + Version Normaliser
        │
        ▼
  LLM Orchestrator  ◄──────────────────────┐
  (Llama 70B / 8B)                          │
        │  Thought → Action                 │
        ▼                                   │
  Toolbox (8 APIs)                          │
   lookup_cpe · search_nvd                  │  pushback if
   get_cve · check_kev                      │  coverage incomplete
   search_exploitdb · search_osv            │
   search_circl · search_epss               │
        │  Observation                      │
        └──────────► LLM                    │
                       │ FINAL_ANSWER       │
                       ▼                    │
              Coverage Validator ───────────┘
                       │ complete
                       ▼
              Severity Enforcement
              (CVSS banding + protocol overrides)
                       │
                       ▼
              Excel Report (5 sheets, CVE hyperlinks → NVD)
```

---

## Features

- **Zero CVE hallucination** — the model can only cite identifiers returned by tool calls during the current session; no parametric memory leaks into the final report
- **Multi-source intelligence** — eight APIs queried autonomously: NVD (CPE + keyword), CISA KEV, Exploit-DB, Google OSV, CIRCL, EPSS (FIRST.org)
- **Dual backend** — Groq cloud (Llama 3.3 70B) for full capability; Ollama local (Llama 3.1 8B) for air-gapped or confidential assessments
- **Multi-scanner input** — Nmap XML and Nessus CSV via a format-agnostic parser
- **Version normalisation** — strips distro suffixes (`8.2p1 Ubuntu 4ubuntu0.13` → `8.2p1`) and resolves Nmap range notation (`12.14 - 12.18` → `12.14`) before CPE lookup
- **Disambiguation filter** — removes off-product CVEs (Sambar Server, SecureCRT, wu-ftpd) before observations reach the model
- **OSV ecosystem cascade** — queries Ubuntu:20.04 then Debian:11 for open-source packages, finding CVEs the NVD CPE dictionary misses
- **Structured Excel output** — 5 sheets: Summary Dashboard, Service Inventory, Critical & High Findings, Policy Violations, Remediation Plan

---

## Requirements

- Python 3.10+
- For **local inference**: [Ollama](https://ollama.com) with `llama3.1:8b` pulled
- For **cloud inference**: Groq API key (free Developer tier is sufficient)
- Optional: NVD API key (increases rate limit from 5 to 50 requests/30 s)

---

## Installation

```bash
git clone https://github.com/nabilBoudlal/llm-vulnerability-assessment
cd llm-vulnerability-assessment
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```env
# Required for cloud backend (Groq)
GROQ_API_KEY=gsk_...

# Optional — higher NVD rate limits
NVD_API_KEY=...

# Optional — override the default model
VA_MODEL=llama3.1:8b
VA_GROQ_MODEL=llama-3.3-70b-versatile
```

If you plan to use local inference only, omit `GROQ_API_KEY` and make sure Ollama is running:

```bash
ollama pull llama3.1:8b
ollama serve
```

---

## Usage

```bash
# Default scan (data/network_scan.xml)
python -m src.main_react

# Single scan file
python -m src.main_react data/my_scan.xml

# Multiple scan files — one report per target
python -m src.main_react data/scan_host1.xml data/scan_host2.xml data/scan_host3.xml
```

Reports are written to `reports/<target_ip>_react_assessment_report_<timestamp>.xlsx`.

### Backend selection

| Condition | Backend used |
|-----------|-------------|
| `GROQ_API_KEY` set in `.env` | Groq cloud (70B) |
| `GROQ_API_KEY` absent | Ollama local (8B) |

---

## Project Structure

```
llm-vulnerability-assessment/
├── src/
│   ├── main_react.py          # Entry point — CLI argument handling, multi-scan loop
│   ├── modules/
│   │   ├── va_agent_react.py  # ReAct orchestrator — main agent loop, safety nets
│   │   ├── toolbox.py         # 8 intelligence tools + disambiguation filter
│   │   ├── react_parser.py    # Thought-Action-Input extractor, FINAL_ANSWER parser
│   │   └── reporter.py        # Excel workbook generator (openpyxl)
│   └── utils/
│       ├── parsers.py         # NmapXMLParser + NessusCSVParser (ParserFactory)
│       ├── hybrid_nvd_api.py  # HybridCVEDownloader — CPE Tier 1 + keyword Tier 2
│       └── nvd_api.py         # Raw NVD API client
├── data/
│   ├── network_scan.xml       # Default scan (replace with your own)
│   ├── security_policies.json # Optional local policy rules
│   └── cve_dataset.json       # Optional offline CVE seed data
├── reports/                   # Generated Excel reports (git-ignored)
├── requirements.txt
├── .env.example
└── README.md
```

---

## Intelligence Sources

| Tool | Source | When invoked |
|------|--------|-------------|
| `lookup_cpe` | NVD CPE dictionary + CVE API | First call for any service with known product + version |
| `search_nvd` | NVD keyword search | Fallback when CPE returns nothing; unknown versions |
| `get_cve` | NVD + CIRCL (parallel) | Full details for a specific CVE ID |
| `check_kev` | CISA KEV catalogue (cached at startup) | Every service with at least one CVE |
| `search_exploitdb` | exploit-db.com | Every Critical or High finding |
| `search_osv` | Google OSV — Ubuntu:20.04 → Debian:11 cascade | Open-source packages (Apache, Samba, OpenSSH, PostgreSQL…) |
| `search_circl` | cve.circl.lu (EU NVD mirror) | CWE classification and v2/v3 CVSS enrichment |
| `search_epss` | FIRST.org EPSS v4 | Every Critical or High CVE — exploitation probability |

---

## Severity Classification

CVSS base score banding follows the NVD standard, with two protocol-level overrides:

| Severity | Condition |
|----------|-----------|
| **Critical** | CVSS ≥ 9.0, or: unauthenticated shell, industrial protocols (Modbus, DNP3, Docker API) |
| **High** | CVSS 7.0–8.9, or: cleartext credential protocols (Telnet, FTP, VNC, SNMP v1/v2) |
| **Medium** | CVSS 4.0–6.9 |
| **Low** | CVSS 0.1–3.9 |
| **Informational** | No CVEs found, no protocol risk |

Severity is enforced **deterministically** after LLM output — any misclassification is corrected by the Python enforcement function before the report is written.

---

## Output Report

Each Excel workbook contains five sheets:

1. **Summary Dashboard** — aggregate counts by severity, scan metadata, agent step count
2. **Service Inventory** — all services with port, severity badge, CVSS, CVE hyperlinks, Exploit-DB and KEV flags
3. **Critical & High Findings** — detailed analysis and remediation steps for the most urgent issues
4. **Policy Violations** — services matching rules defined in `data/security_policies.json`
5. **Remediation Plan** — consolidated action list ordered by severity

CVE identifiers throughout the report are rendered as clickable hyperlinks to `https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX`.

---

## Known Limitations

- **NVD CPE indexing gaps** — distribution-packaged software (e.g. `openssh 8.2p1` on Ubuntu, `postgresql 12.14`) may return zero CPE matches even when vulnerabilities exist. The OSV cascade partially compensates for open-source packages.
- **Non-deterministic strategy selection** — services without version strings produce variable severity classifications across runs. High-confidence findings (precise version + well-indexed CVE) are stable across runs.
- **Local 8B memory bound** — the 8B model stalls on scans exceeding ~11 services on 16 GB RAM. Use the Groq backend for larger targets.
- **OSV identifier format** — OSV returns Ubuntu-specific identifiers (`UBUNTU-CVE-*`) alongside canonical CVE aliases. The formatter extracts the canonical alias when present; residual Ubuntu-only IDs are noted in the analysis text.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GROQ_API_KEY` | — | Groq API key; if set, enables cloud 70B backend |
| `NVD_API_KEY` | — | Optional; raises NVD rate limit from 5 to 50 req/30 s |
| `VA_MODEL` | `llama3.1:8b` | Ollama model name for local backend |
| `VA_GROQ_MODEL` | `llama-3.3-70b-versatile` | Groq model name for cloud backend |

---

## Reproducing the Thesis Experiments

The scan files used in the MSc thesis evaluation are provided in `data/`:

```bash
# Baseline (0 open ports)
python -m src.main_react data/test1.xml

# Minimal profile (4 services: telnetd, Apache 2.4.41, Samba ×2)
python -m src.main_react data/test2.xml

# Mail + database (11 services: adds ProFTPD, Postfix, Dovecot ×4, PostgreSQL 12)
python -m src.main_react data/test3.xml

# Full profile (15 services: adds OpenSSH 8.2p1, MySQL, Redis 5.0.7, Java RMI, NFS, mountd ×3)
python -m src.main_react data/test4.xml
```

All experiments were run with `GROQ_API_KEY` set (Llama 3.3 70B) and `NVD_API_KEY` set for authenticated rate limits.


---

## License

This project is released for academic and research purposes. It queries publicly available vulnerability databases (NVD, CISA KEV, Exploit-DB, OSV, CIRCL, EPSS) in accordance with their respective terms of service.

**Use only against systems you own or have explicit written authorisation to assess.** Unauthorised scanning is illegal in most jurisdictions.

---

## Acknowledgements

- [Yao et al. (2022)](https://arxiv.org/abs/2210.03629) — ReAct: Synergizing Reasoning and Acting in Language Models
- [NIST NVD](https://nvd.nist.gov) — National Vulnerability Database
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known Exploited Vulnerabilities Catalogue
- [FIRST.org EPSS](https://www.first.org/epss/) — Exploit Prediction Scoring System
- [Google OSV](https://osv.dev) — Open Source Vulnerability Database
- [CIRCL CVE Search](https://cve.circl.lu) — EU NVD mirror with EPSS enrichment
- [Exploit-DB](https://www.exploit-db.com) — Offensive Security public exploit archive
