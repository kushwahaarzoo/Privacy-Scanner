# 🔒 Privacy Scanner

A browser-based website privacy analysis tool built with Python.

Privacy Scanner analyzes websites to identify privacy-related information, including cookies, third-party domains, known trackers, browser storage, consent mechanisms, fingerprinting indicators, privacy policies, and other privacy signals.

The project uses browser automation and modular scanning components to examine observable website behavior and help identify potential privacy concerns.

---

# 📌 Purpose

Modern websites interact with multiple services and technologies while loading. These interactions may support analytics, advertising, authentication, content delivery, personalization, or user tracking.

The purpose of Privacy Scanner is to analyze these interactions and provide structured information about a website's privacy-related behavior.

The scanner helps investigate:

- Cookies and their security attributes
- First-party and third-party domains
- Known tracking services
- Browser network requests
- Browser storage usage
- Website redirects and metadata
- Consent mechanisms
- Browser fingerprinting indicators
- Privacy policy information
- Privacy-related signals

---

# ✨ Features

## 🌐 Browser-Based Website Scanning

The scanner opens a target website using browser automation and collects information about its observable behavior.

The analysis may include:

- Original URL
- Final URL after redirects
- Website title
- Network requests
- Cookies
- Domain information
- Tracker matches
- Browser storage
- Privacy-related indicators

Browser-based scanning helps identify behavior that may not be visible through static HTML analysis alone.

---

## 🔄 Redirect Detection

The scanner can record the final URL reached after navigating to a website.

Example:

```text
http://example.com
        ↓
https://www.example.com
```

Redirect analysis helps identify changes in the website destination during navigation.

---

## 🍪 Cookie Analysis

The scanner collects and analyzes cookie information available during the browser session.

Relevant cookie attributes may include:

- Cookie name
- Domain
- Path
- Expiration
- Secure flag
- HTTP-only flag
- SameSite policy

Cookies can support authentication, session management, user preferences, analytics, and tracking.

Their presence alone does not establish that a website is violating privacy.

---

## 🌍 Domain Analysis

The scanner analyzes domains involved in website activity.

### First-Party Domains

Domains associated with the website being scanned.

Example:

```text
example.com
```

### Third-Party Domains

External domains contacted while the website loads.

Example:

```text
analytics.example-service.com
```

Third-party domains may provide analytics, advertising, content delivery, embedded services, or tracking functionality.

The presence of a third-party domain does not automatically indicate a privacy risk.

---

## 🕵️ Tracker Detection

The tracker detection module identifies domains or requests that match known tracking services.

The relevant components are:

```text
backend/scanner/trackers.py
backend/data/trackers.json
```

The local tracker database provides information used to recognize known trackers.

Potential tracker categories include analytics, advertising, marketing, and social media services, depending on the available database.

Detection accuracy depends on the coverage and quality of the tracker data.

---

## 💾 Browser Storage Analysis

The storage analysis module examines browser storage mechanisms used by websites.

Module:

```text
backend/scanner/storage.py
```

Storage mechanisms may include:

- Local Storage
- Session Storage
- Other supported browser storage mechanisms

Browser storage can support normal website functionality but may also retain information that contributes to user identification.

---

## 🛡️ Consent Analysis

The consent analysis module examines website consent-related elements and indicators.

Module:

```text
backend/scanner/consent.py
```

Consent analysis can help investigate how websites present consent options and privacy-related choices.

The findings depend on the consent detection logic implemented in the scanner. Detecting a consent banner does not establish that the website obtains valid consent or complies with applicable privacy regulations.

---

## 🧬 Fingerprinting Analysis

The fingerprinting analysis module examines indicators associated with browser fingerprinting.

Module:

```text
backend/scanner/fingerprinting.py
```

Browser fingerprinting involves collecting characteristics of a browser or device that may help distinguish it from other users.

Depending on the implemented detection logic, analysis may examine observable fingerprinting-related scripts or browser behavior.

Detection of indicators does not necessarily prove that a website successfully fingerprints users.

---

## 📄 Privacy Policy Analysis

The privacy policy module supports analysis of available website privacy policy information.

Module:

```text
backend/scanner/privacy_policy.py
```

Privacy policies describe how websites may collect, use, share, and retain information.

This module provides a foundation for examining privacy policy information as part of the overall website analysis.

Automated analysis should not be treated as a legal determination of compliance.

---

## 📊 Privacy Signals

The privacy signals module collects or evaluates privacy-related indicators.

Module:

```text
backend/scanner/privacy_signals.py
```

These signals can help organize findings from the website scanning process and support a broader privacy assessment.

The significance of each signal depends on the detection rules and analysis logic implemented in the project.

---

## 📸 Website Screenshots

The project includes a directory for storing screenshots captured during website scanning.

Directory:

```text
backend/screenshots/
```

Screenshots can help document the website's appearance during a scan and support debugging, research, and visual review.

---

# 🏗️ Project Structure

```text
privacy-scanner/
│
├── backend/
│   │
│   ├── main.py
│   │
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── browser.py
│   │   ├── consent.py
│   │   ├── cookies.py
│   │   ├── domains.py
│   │   ├── fingerprinting.py
│   │   ├── privacy_policy.py
│   │   ├── privacy_signals.py
│   │   ├── storage.py
│   │   └── trackers.py
│   │
│   ├── data/
│   │   └── trackers.json
│   │
│   └── screenshots/
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

# 📂 Project Components

## `backend/main.py`

The main backend entry point.

It connects the application interface or API routes to the scanner functionality, depending on the application's implementation.

## `backend/scanner/browser.py`

Handles browser-based website scanning.

Its responsibilities may include:

- Launching the browser
- Opening the target website
- Observing network requests
- Collecting website metadata
- Recording the final URL
- Coordinating scanning operations

## `backend/scanner/domains.py`

Handles domain extraction and classification, including identifying first-party and third-party domains.

## `backend/scanner/cookies.py`

Processes cookie information collected during the browser session.

## `backend/scanner/trackers.py`

Identifies known tracking services using the tracker information available to the scanner.

## `backend/scanner/storage.py`

Examines supported browser storage mechanisms and related privacy indicators.

## `backend/scanner/consent.py`

Analyzes consent-related website elements and indicators.

## `backend/scanner/fingerprinting.py`

Examines observable indicators associated with browser fingerprinting.

## `backend/scanner/privacy_policy.py`

Supports analysis of available privacy policy information.

## `backend/scanner/privacy_signals.py`

Collects or evaluates privacy-related indicators for the overall analysis.

## `backend/scanner/__init__.py`

Marks the scanner directory as a Python package.

---

# 🗂️ Data Files

## `backend/data/trackers.json`

Stores the local tracker information used by the tracker detection module.

Keeping tracker data separate from the scanning logic makes the database easier to maintain and extend.

---

# 🛠️ Technologies Used

## Python

Used for backend development, browser scanning, data processing, and privacy analysis.

Documentation: https://docs.python.org/3/

## Playwright

Used for browser automation, website navigation, network observation, cookie collection, and other supported browser operations.

Documentation: https://playwright.dev/python/

## FastAPI

Used if configured in the project for providing HTTP API endpoints and connecting requests to the scanning functionality.

Documentation: https://fastapi.tiangolo.com/

---

# ⚙️ Requirements

Before running the project, install:

- Python 3.10 or higher
- pip
- Dependencies listed in `requirements.txt`
- Playwright browser binaries

Check your Python installation:

```bash
python --version
```

---

# 📦 Installation

## 1. Navigate to the Project Directory

```bash
cd privacy-scanner
```

## 2. Create a Virtual Environment

```bash
python -m venv venv
```

## 3. Activate the Virtual Environment

**Windows:**

```bash
venv\Scripts\activate
```

**Linux / macOS:**

```bash
source venv/bin/activate
```

## 4. Install Dependencies

```bash
pip install -r requirements.txt
```

## 5. Install Playwright Browsers

```bash
python -m playwright install chromium
```

---

# ▶️ Running the Project

Run commands from the project root directory with the virtual environment activated.

If `backend/main.py` defines a FastAPI application named `app`, run:

```bash
uvicorn backend.main:app --reload
```

The development server will typically be available at:

```text
http://127.0.0.1:8000
```

If API documentation is enabled, access it at:

```text
http://127.0.0.1:8000/docs
```

The exact startup command and available endpoints depend on the implementation in `backend/main.py`.

---

# 🔎 How the Scanner Works

The scanner follows a modular website analysis workflow.

```text
User Provides Website URL
          |
          v
    Backend Application
          |
          v
     Browser Scanner
          |
          v
  Website Loaded in Browser
          |
          +----> Network Analysis
          |
          +----> Domain Analysis
          |
          +----> Cookie Analysis
          |
          +----> Tracker Detection
          |
          +----> Storage Analysis
          |
          +----> Consent Analysis
          |
          +----> Fingerprinting Analysis
          |
          +----> Privacy Policy Analysis
          |
          v
    Privacy Signals
          |
          v
      Scan Results
```

The precise execution order depends on how the scanner modules are integrated.

---

# 📋 Example Privacy Information

A scan may return structured information about a website.

The following is an illustrative example, not a guarantee of the application's exact response format.

```json
{
  "url": "https://example.com",
  "final_url": "https://example.com",
  "title": "Example Domain",
  "cookies": [],
  "third_party_domains": [],
  "trackers": [],
  "storage": {},
  "privacy_signals": []
}
```

The actual fields and output structure depend on the backend implementation.

---

# 🔐 Privacy Interpretation

Privacy Scanner identifies technical indicators that can help users investigate website behavior.

These indicators require context.

- **Third-party domains:** May provide analytics, content delivery, or other legitimate services.
- **Cookies:** May be necessary for authentication, security, or user preferences.
- **Known trackers:** Indicate a match against the available tracker database.
- **Fingerprinting indicators:** Do not necessarily prove successful identification of a user.
- **Consent elements:** Do not establish that consent is legally valid.
- **Privacy policies:** Automated analysis cannot guarantee legal compliance.

The scanner's findings should be interpreted as technical observations rather than definitive legal conclusions.

---

# ⚠️ Limitations

- The scanner can only analyze behavior observable during the scan.
- Some website behavior requires user interaction or additional time to appear.
- Tracker detection depends on the available tracker database.
- Fingerprinting detection may not identify every technique.
- Privacy policy analysis may not fully understand complex legal language.
- Consent interfaces may vary across websites and regions.
- A scan cannot guarantee that all privacy risks have been identified.

---


# 👨‍💻 Project Status

**Current Progress:**

Privacy Scanner includes modular components for browser-based website scanning, domain analysis, cookie analysis, tracker detection, browser storage analysis, consent analysis, fingerprinting indicators, privacy policy analysis, and privacy signals.

The project is designed to help users understand observable website behavior and investigate potential privacy concerns.
