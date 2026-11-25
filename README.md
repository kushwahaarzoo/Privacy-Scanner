# 🔒 Privacy Scanner

An evidence-based website privacy auditor built with Python, Playwright and FastAPI.

Most privacy scanners list the cookies and trackers they see. Privacy Scanner goes further: it **tests** how a site behaves (before consent, after rejecting, with GPC/DNT enabled, with a canary email typed into forms) and then **checks the site's privacy policy against what it actually observed**. Every result is stored in a tamper-evident evidence ledger and turned into a scored, law-mapped report.

---

## 📌 Table of Contents

- [Purpose](#-purpose)
- [Key Features](#-key-features)
- [How It Works](#-how-it-works)
- [Project Structure](#-project-structure)
- [Technologies](#-technologies)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Running the Project](#-running-the-project)
- [API Reference](#-api-reference)
- [Report Output](#-report-output)
- [Scoring and Regulation Mapping](#-scoring-and-regulation-mapping)
- [Privacy Interpretation](#-privacy-interpretation)
- [Limitations](#-limitations)
- [Roadmap](#-roadmap)
- [Project Status](#-project-status)

---

## 📌 Purpose

Websites interact with many services while loading: analytics, advertising, content delivery, authentication and more. A visitor usually cannot see these interactions, and a privacy policy may not describe them accurately.

Privacy Scanner investigates:

- Cookies and their security attributes
- First-party and third-party domains
- Known tracking services and the companies behind them
- Browser storage usage
- Consent banners, including measurable dark patterns
- Whether tracking continues after a visitor rejects consent
- Response to Global Privacy Control (GPC) and Do Not Track (DNT)
- Browser fingerprinting indicators
- Whether personal data (an email address) actually reaches third parties
- What the privacy policy claims, and whether the observed behaviour contradicts it

---

## ✨ Key Features

### Core scanning

| Feature | Module | Description |
|---|---|---|
| Browser-based scan | `browser.py` | Loads the page in headless Chromium, records requests, redirects, title, status code and a full-page screenshot |
| Domain analysis | `domains.py` | Splits first-party and third-party domains using the registrable domain (`tldextract`) |
| Cookie analysis | `cookies.py` | Classifies cookies as essential, analytics, advertising or unknown; records Secure, HttpOnly, SameSite and expiry. Values are never stored |
| Tracker detection | `trackers.py` | Matches requests against a local tracker database (name, company, category) |
| Storage analysis | `storage.py` | Inspects localStorage, sessionStorage, IndexedDB, cache storage and service workers |

### Advanced analysis

| Feature | Module | Description |
|---|---|---|
| Consent behaviour test | `consent.py` | Runs three independent sessions (no interaction, reject, accept) and compares trackers and cookies |
| Dark-pattern detector | `dark_patterns.py` | Measures accept/reject button area, font size and colour contrast; detects a missing first-layer reject button and pre-ticked boxes |
| GPC / DNT test | `privacy_signals.py` | Loads the site with and without opt-out signals and compares trackers and third-party domains |
| Fingerprinting detection | `fingerprinting.py` | Instruments canvas, WebGL, audio, font and navigator/screen APIs and records which frames call them |
| Canary PII leak test | `pii_leak.py` | Types a synthetic email into forms and searches outgoing requests for it in plaintext, URL-encoded, base64, MD5, SHA-1 and SHA-256 form |
| LLM policy extraction | `policy_llm.py` | Converts the privacy policy into structured claims with a verbatim quote for each; supports Gemini, Ollama, or a keyword fallback |
| Quote verification | `policy_llm.py` | Every LLM claim is checked against the policy text to catch hallucinated evidence |
| Contradiction engine | `contradiction.py` | Compares policy claims with observed behaviour (for example "we do not sell data" against a hashed email sent to an ad network) |
| Evidence ledger | `ledger.py` | Hash-chained log of every result; any later change breaks the chain |
| Scoring and law mapping | `scoring.py` | 0 to 100 score, A to F grade, and references to GDPR, ePrivacy, DPDP Act 2023 and CCPA |
| SSRF guard | `security.py` | Rejects non-HTTP(S) URLs, embedded credentials and private, loopback or link-local targets |

### Reporting

- **Web dashboard** served at `/ui/` (no build step)
- **PDF report** from the server (`reportlab`) or via the browser's Print / Save as PDF
- **Saved reports** in `backend/reports/` that survive restarts
- **Raw JSON** for every audit

---

## 🔎 How It Works

```text
                 URL submitted (POST /audit)
                            |
                            v
                  SSRF guard + job queued
                            |
                            v
   +--------------------------------------------------+
   | 1. Site scan        cookies, domains, storage    |
   | 2. Consent scan     none / reject / accept       |
   | 3. GPC/DNT scan     baseline vs signals on       |
   | 4. Canary PII test  fake email -> network search |
   | 5. Policy fetch     find and read the policy     |
   | 6. Claim extraction LLM (or keyword fallback)    |
   +--------------------------------------------------+
                            |
                            v
        Contradiction engine: claims vs observations
                            |
                            v
      Findings -> score, grade, regulation mapping
                            |
                            v
          Hash-chained evidence ledger (SHA-256)
                            |
                            v
        JSON  ->  Dashboard  ->  PDF report
```

A full audit takes roughly 1 to 3 minutes per site, because it runs several browser sessions. Audits run as background jobs; the client polls for the result.

---

## 🏗️ Project Structure

```text
privacy-scanner/
│
├── backend/
│   ├── __init__.py
│   ├── main.py                  # FastAPI app, job queue, report endpoints
│   │
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── browser.py           # site scan (cookies, domains, storage, screenshot)
│   │   ├── consent.py           # none / reject / accept scenarios
│   │   ├── dark_patterns.py     # consent banner measurements
│   │   ├── cookies.py           # cookie classification
│   │   ├── domains.py           # first-party vs third-party
│   │   ├── trackers.py          # tracker database matching
│   │   ├── storage.py           # browser storage inspection
│   │   ├── fingerprinting.py    # fingerprinting API instrumentation
│   │   ├── privacy_signals.py   # GPC / DNT comparison
│   │   ├── privacy_policy.py    # policy discovery and keyword topics
│   │   ├── policy_llm.py        # LLM claim extraction + quote verification
│   │   ├── pii_leak.py          # canary email leak test
│   │   ├── contradiction.py     # policy vs behaviour engine
│   │   ├── ledger.py            # tamper-evident evidence ledger
│   │   ├── scoring.py           # score, grade, law mapping
│   │   ├── security.py          # SSRF guard
│   │   ├── audit.py             # orchestrator (full_audit)
│   │   └── report_pdf.py        # PDF report builder
│   │
│   ├── data/
│   │   └── trackers.json        # tracker database
│   │
│   ├── screenshots/             # created automatically
│   └── reports/                 # saved audits (JSON + screenshot), auto-created
│
├── frontend/
│   └── index.html               # dashboard served at /ui/
│
├── evaluation/                  # batch scripts and results (optional)
├── run_audit.py                 # command-line runner
├── check_audit.py               # polls the API and saves audit_report.json
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🛠️ Technologies

| Technology | Used for |
|---|---|
| [Python 3.10+](https://docs.python.org/3/) | Backend and analysis logic |
| [Playwright](https://playwright.dev/python/) | Browser automation, network capture, cookies, instrumentation |
| [FastAPI](https://fastapi.tiangolo.com/) + Uvicorn | HTTP API and static dashboard hosting |
| [tldextract](https://github.com/john-kurkowski/tldextract) | Registrable-domain detection |
| [ReportLab](https://docs.reportlab.com/) | Server-side PDF generation |
| Gemini API or [Ollama](https://ollama.com/) | LLM policy claim extraction |

---

## ⚙️ Requirements

- Python 3.10 or higher
- pip
- Chromium installed through Playwright
- Optional: a free Gemini API key, or Ollama with a local model

```bash
python --version
```

---

## 📦 Installation

### 1. Go to the project folder

```bash
cd privacy-scanner
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv
```

**Windows (PowerShell):**

```powershell
.venv\Scripts\Activate.ps1
```

**Linux / macOS:**

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt`:

```text
fastapi>=0.110
uvicorn>=0.29
pydantic>=2.6
playwright>=1.44
tldextract>=5.1
reportlab>=4.0
requests>=2.31
```

### 4. Install the browser

```bash
python -m playwright install chromium
```

---

## 🔧 Configuration

Configuration uses environment variables. Never put API keys in code or commit them to git.

| Variable | Default | Purpose |
|---|---|---|
| `GEMINI_API_KEY` | none | Enables Gemini for policy claim extraction |
| `LLM_PROVIDER` | `gemini` if a key is set, else `none` | `gemini`, `ollama` or `none` |
| `GEMINI_MODEL` | `gemini-2.0-flash` | Gemini model name; change it if the model is retired |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server address |
| `OLLAMA_MODEL` | `qwen2.5:3b` | Ollama model name |
| `ALLOW_PRIVATE_TARGETS` | unset | Set to `1` only to scan your own local test sites |

**Windows (PowerShell):**

```powershell
$env:GEMINI_API_KEY="your-key-here"
$env:LLM_PROVIDER="gemini"
```

**Linux / macOS:**

```bash
export GEMINI_API_KEY="your-key-here"
export LLM_PROVIDER="gemini"
```

If no LLM is available, the scanner falls back to keyword rules, and the report shows which method was used (`claims._method`). Set the variables in the same terminal that starts Uvicorn.

### Tracker database

`backend/data/trackers.json` maps domains to tracker details. Without entries, no trackers or tracker cookies will be reported.

```json
{
  "google-analytics.com": {
    "name": "Google Analytics",
    "company": "Google",
    "category": "analytics"
  },
  "doubleclick.net": {
    "name": "DoubleClick",
    "company": "Google",
    "category": "advertising"
  }
}
```

---

## ▶️ Running the Project

Run from the project root (the folder containing `backend/` and `frontend/`):

```bash
uvicorn backend.main:app --port 8000
```

| URL | Purpose |
|---|---|
| `http://127.0.0.1:8000/ui/` | Dashboard (keep the trailing slash) |
| `http://127.0.0.1:8000/docs` | Interactive API documentation |

Avoid `--reload` on Windows, as the reloader can interfere with Playwright's browser subprocess.

### Using the dashboard

1. Open `http://127.0.0.1:8000/ui/`.
2. Enter a URL and click **Run audit**.
3. The status line shows the current stage while the audit runs.
4. When it finishes, review the report, then use **Print / Save as PDF**, **Download PDF (server)** or **Raw JSON**.
5. Use the dropdown to reopen earlier reports.

### Using the command line

```bash
python run_audit.py https://example.com
```

or, with the server running:

```bash
python check_audit.py https://example.com
```

Both write `audit_report.json`.

---

## 📋 Report Output

Each completed audit contains:

| Section | Content |
|---|---|
| Summary | Score, grade, target, policy URL, ledger validity, root hash, claim extraction method |
| Findings | Severity, ID, detail, evidence and mapped regulations |
| Contradictions | Policy quote against observed evidence |
| Site overview | Final URL, status, title, request count, domain counts, screenshot |
| Tracker cookies | Analytics and advertising cookies, with whether they appear before choice, after reject and after accept |
| Known trackers | Name, company, category, domain, request count, consent-state presence |
| Third-party domains | Requests, resource types and tracker attribution |
| All cookies | Party, category, Secure, HttpOnly, SameSite, expiry |
| Consent behaviour | Counts per scenario and banner button measurements |
| Dark patterns | Missing reject button, dominant accept button, low contrast, pre-ticked boxes |
| Canary leak test | Destination, encoding, third-party flag, known tracker |
| Fingerprinting | API call counts per category and frames checked |
| GPC / DNT | Browser values and tracker differences |
| Policy claims | Extracted claims with quote and verification status |
| Policy topics | Keyword-based topic coverage |
| Browser storage | Key names and sizes only |
| Timings | Seconds per stage |

Abbreviated JSON:

```json
{
  "url": "https://example.com",
  "score": { "score": 62, "grade": "C", "findings": [] },
  "contradictions": [],
  "tracker_cookies": [],
  "trackers": [],
  "third_parties": [],
  "pii_leaks": { "fields_filled": 1, "leak_count": 0, "leaks": [] },
  "evidence_root_hash": "…",
  "ledger_valid": true
}
```

### Evidence ledger

Each ledger entry stores a SHA-256 hash of its own content plus the previous entry's hash. Changing any stored result invalidates every later hash, and `ledger_valid` reports whether the chain is intact. The root hash identifies the exact evidence behind a report.

---

## 📊 Scoring and Regulation Mapping

The score starts at 100 and loses points per finding:

| Severity | Points |
|---|---|
| high | 15 |
| medium | 7 |
| review | 4 |
| low | 2 |
| info | 0 |

| Score | Grade |
|---|---|
| 90 to 100 | A |
| 75 to 89 | B |
| 55 to 74 | C |
| 35 to 54 | D |
| below 35 | F |

Findings reference relevant provisions of **GDPR**, the **ePrivacy Directive**, India's **DPDP Act 2023**, **CCPA**. These are pointers for investigation, not conclusions that a law was broken.

---

## 🔐 Privacy Interpretation

- **Third-party domains** may provide analytics, content delivery or other legitimate services.
- **Cookies** may be needed for authentication, security or preferences.
- **Known trackers** are matches against the tracker database, not proof of data collection.
- **A tracker request** shows a connection. The canary test checks whether personal data was actually sent.
- **Fingerprinting API calls** have legitimate uses and do not prove a user was identified.
- **Consent banners** being present does not mean consent is valid.
- **Differences between scenarios** can come from timing or randomness and are reported as observations.
- **Contradictions** depend on the quality of the extracted policy claims. Check the quote verification flag.

---

## ⚠️ Limitations

- Only behaviour observable during the scan is analysed.
- Banner detection uses English text matching and may miss iframes, shadow DOM or other languages.
- Tracker and cookie classification depend on `trackers.json` and a small name-pattern list.
- Small local LLMs are less accurate than large models; the keyword fallback is coarse.
- The canary test fills email-type fields only, never submits forms, and covers only listed encodings.
- Fingerprinting instrumentation covers selected APIs and can miss workers or unlisted techniques.
- The SSRF guard is a pre-check. Redirects and DNS rebinding are not fully blocked yet.
- Jobs are held in memory (finished reports are saved to disk). Audits run one at a time.
- Sites behind login, CAPTCHAs or bot protection may not be scanned fully.
- A scan cannot guarantee that every privacy risk has been found.
---

## 🗺️ Roadmap

- [ ] Batch evaluation script and CSV export for many sites
- [ ] Open Cookie Database lookup to replace name-pattern matching
- [ ] Third-party server geolocation for cross-border transfer analysis
- [ ] Vision-LLM check of the consent banner screenshot
- [ ] Scan-over-time comparison
- [ ] SQLite job storage and a request-level SSRF filter (`page.route`)
- [ ] Multi-language consent banner support
- [ ] Automated tests

---

## 👨‍💻 Project Status

**Current progress:** The scanner combines site scanning, consent-behaviour testing, dark-pattern measurement, GPC/DNT and fingerprinting checks, a canary PII leak test, LLM-based policy claim extraction with quote verification, a policy-versus-behaviour contradiction engine, a hash-chained evidence ledger, scoring with regulation mapping, and a dashboard with PDF export.
