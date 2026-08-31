# 🔒 Privacy Scanner

A browser-based website privacy analysis tool built with Python.

Privacy Scanner analyzes publicly accessible websites and identifies privacy-related elements such as cookies, third-party domains, known trackers, browser storage, network activity, and screenshots.

The project uses browser automation to observe how a website behaves when loaded in a real browser environment.

---

# 📌 Purpose

Modern websites often communicate with multiple external services while loading. These services may be used for legitimate purposes such as content delivery, analytics, authentication, embedded content, or advertising. Some may also be associated with user tracking.

The purpose of Privacy Scanner is to provide a structured way to analyze these privacy-related behaviors.

The scanner can help identify:

* Cookies created or available during a browsing session
* First-party and third-party domains
* Known trackers
* Network requests
* Browser storage usage
* Redirected URLs
* Website metadata
* Visual screenshots of scanned websites
  
---

# ✨ Features

## 🌐 Browser-Based Website Scanning

The scanner opens the target website using a browser automation engine and analyzes the website after it has loaded.

This allows the scanner to observe behavior that may not be visible through static HTML analysis alone.

The scanner can collect information such as:

* Original URL
* Final URL after redirects
* Page title
* Network activity
* Cookies
* Third-party domains
* Known trackers
* Browser storage data

---

## 🔄 Redirect Detection

Websites may redirect visitors to another URL.

For example:

```text
http://example.com
        ↓
https://www.example.com
```

The scanner records the final URL reached by the browser.

This helps identify:

* HTTP to HTTPS redirects
* Domain redirects
* Subdomain redirects
* Website destination changes

---

## 🍪 Cookie Analysis

The scanner collects cookies available during the browser session.

Cookie information may include:

* Cookie name
* Domain
* Path
* Expiration
* Secure flag
* HTTP-only flag
* SameSite policy

Cookies can be used for different purposes, including:

* Authentication
* Session management
* User preferences
* Analytics
* Advertising
* Tracking

Privacy Scanner collects this information so it can be analyzed as part of the overall privacy behavior of a website.

---

## 🌍 Domain Analysis

The scanner analyzes domains involved in website activity.

It helps distinguish between:

### First-Party Domains

Domains directly associated with the website being scanned.

Example:

```text
example.com
```

### Third-Party Domains

External domains contacted while the website is loading.

Example:

```text
analytics-service.com
```

Third-party domains may be associated with:

* Analytics
* Advertising
* Content delivery
* Social media
* Embedded services
* Tracking technologies

The presence of a third-party domain alone does not necessarily indicate a privacy risk.

---

## 🕵️ Tracker Detection

Privacy Scanner includes tracker detection capabilities.

Known tracker information is maintained in:

```text
backend/data/trackers.json
```

The scanner compares detected domains and requests against known tracker data.

Potential tracker categories may include:

* Analytics
* Advertising
* Social media
* Marketing
* User tracking
* Other third-party tracking services

The tracker detection logic is handled by:

```text
backend/scanner/trackers.py
```

---

## 💾 Browser Storage Analysis

Modern websites can store information in the browser using mechanisms other than cookies.

The scanner includes storage analysis through:

```text
backend/scanner/storage.py
```

Browser storage analysis can help identify privacy-relevant data stored by websites.

This may include:

* Local Storage
* Session Storage
* Other browser-accessible storage information supported by the scanner

Browser storage can be used for legitimate website functionality, but it may also contribute to persistent user identification.

---

## 📸 Website Screenshots

The project includes a dedicated screenshots directory:

```text
backend/screenshots/
```

Screenshots can be used to preserve a visual record of the website during scanning.

This can be useful for:

* Documentation
* Privacy research
* Scan reports
* Website comparison
* Debugging
* Visual verification

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
│   │   ├── domains.py
│   │   ├── cookies.py
│   │   ├── trackers.py
│   │   └── storage.py
│   │
│   ├── data/
│   │   └── trackers.json
│   │
│   └── screenshots/
│
├── requirements.txt
└── .gitignore
```

---

# 📂 Project Components

## `backend/main.py`

This is the main backend entry point of the application.

It is responsible for connecting the application interface or API layer with the privacy scanning modules.

---

# 🔍 Scanner Modules

The scanner functionality is divided into separate modules to keep the project modular and easier to extend.

---

## `backend/scanner/browser.py`

This module handles browser-based website scanning.

Its responsibilities include:

* Launching the browser
* Opening the target website
* Monitoring browser activity
* Collecting website metadata
* Recording the final URL
* Observing network requests
* Coordinating privacy analysis modules

Browser automation is useful because modern websites often load privacy-related resources dynamically through JavaScript.

---

## `backend/scanner/domains.py`

This module handles domain analysis.

Its responsibilities include:

* Extracting domains from URLs
* Identifying the main website domain
* Comparing request domains
* Identifying first-party domains
* Identifying third-party domains

Example:

```text
Target Website:
example.com
```

Requests:

```text
example.com/script.js
cdn.example.com/style.css
analytics.example-service.com/tracker.js
```

The domain analysis module can help classify external domains relative to the scanned website.

---

## `backend/scanner/cookies.py`

This module handles cookie analysis.

Its responsibilities include processing cookie information collected during the browser session.

Possible information analyzed includes:

* Cookie names
* Cookie domains
* Cookie security attributes
* HTTP-only status
* SameSite configuration
* Expiration information

---

## `backend/scanner/trackers.py`

This module is responsible for identifying known tracking services.

It compares detected domains or requests with tracker information stored in:

```text
backend/data/trackers.json
```

This separation allows the tracker database to be updated without requiring major changes to the browser scanning logic.

---

## `backend/scanner/storage.py`

This module handles browser storage analysis.

It is responsible for collecting and processing information related to browser storage mechanisms used by scanned websites.

This helps expand privacy analysis beyond traditional cookies.

---

## `backend/scanner/__init__.py`

This file identifies the scanner directory as a Python package and supports organized imports between scanner modules.

---

# 🗂️ Data Files

## `backend/data/trackers.json`

This file contains information used for tracker detection.

Keeping tracker information separate from the scanning code provides several benefits:

* Easier tracker database updates
* Cleaner scanner logic
* Expandable tracker categories
* Better maintainability
* Easier addition of new tracking services

The scanner can compare detected domains against the tracker data during analysis.

---

# 📸 Screenshots

## `backend/screenshots/`

This directory is used to store screenshots captured during website scans.

Screenshots can provide visual context for a scan and can later be used for:

* Privacy reports
* Website documentation
* Historical comparisons
* Debugging
* User interfaces

Depending on the implementation, generated screenshots may be excluded from version control through `.gitignore`.

---

# 🛠️ Technologies Used

## Python

Python is used for:

* Scanner logic
* Data processing
* Backend development
* Privacy analysis

---

## Playwright

Playwright is used for browser automation.

It enables the scanner to:

* Launch a browser
* Load websites
* Execute JavaScript
* Observe network requests
* Access cookies
* Access browser storage
* Capture screenshots

---

# ⚙️ Requirements

Before running the project, make sure the following are installed.

## Python

Recommended:

```text
Python 3.10 or higher
```

Check your Python version:

```bash
python --version
```

or:

```bash
python3 --version
```

---

# 📦 Installation

## 1. Clone or Download the Project

Navigate to the project directory:

```bash
cd privacy-scanner
```

---

## 2. Create a Virtual Environment

Create a virtual environment:

```bash
python -m venv venv
```

---

## 3. Activate the Virtual Environment

### Windows

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
source venv/bin/activate
```

---

## 4. Install Dependencies

Install all required Python packages:

```bash
pip install -r requirements.txt
```

---

## 5. Install Playwright Browsers

After installing the Python dependencies, install the browser binaries required by Playwright:

```bash
playwright install
```

If the command is not recognized, use:

```bash
python -m playwright install
```

---

# ▶️ Running the Project

From the project root directory, make sure the virtual environment is activated.

Then run the backend according to the application configuration.

For a FastAPI application, the expected command is:

```bash
uvicorn backend.main:app --reload
```

The development server will typically be available at:

```text
http://127.0.0.1:8000
```

If API documentation is enabled, FastAPI documentation is typically available at:

```text
http://127.0.0.1:8000/docs
```

The exact available routes depend on the implementation in:

```text
backend/main.py
```

---

# 🔎 How the Scanner Works

The Privacy Scanner follows a browser-based analysis workflow.

```text
User Provides Website URL
            │
            ▼
      Backend Application
            │
            ▼
      Browser Scanner
            │
            ▼
    Website Loaded in Browser
            │
            ├──────────────► Network Analysis
            │
            ├──────────────► Domain Analysis
            │
            ├──────────────► Cookie Analysis
            │
            ├──────────────► Tracker Detection
            │
            ├──────────────► Storage Analysis
            │
            └──────────────► Screenshot Capture
                            │
                            ▼
                      Scan Results
```

---

# 📊 Privacy Analysis Workflow

When a website is scanned, the following process takes place:

1. A target URL is provided.
2. The browser scanner launches a browser.
3. The target website is opened.
4. Redirect behavior is observed.
5. The final URL is recorded.
6. Network requests are collected.
7. Domains are extracted from those requests.
8. First-party and third-party domains are analyzed.
9. Cookies are collected and processed.
10. Detected domains are compared against known tracker data.
11. Browser storage information is analyzed.
12. A screenshot may be captured.
13. Results are returned in a structured format.

---

# 📋 Example Privacy Information

A scan may collect information similar to:

```json
{
  "url": "https://example.com",
  "final_url": "https://www.example.com",
  "title": "Example Website",
  "cookies": [],
  "third_party_domains": [],
  "trackers": [],
  "storage": {},
  "screenshot": null
}
```

> The exact structure of the scan result depends on the implementation in the current scanner modules.

---

# 🧠 Why Browser-Based Analysis?

Many modern websites rely heavily on JavaScript.

A simple HTML request may not reveal all privacy-related behavior.

For example:

```text
Website HTML
     │
     ▼
JavaScript Executes
     │
     ▼
Additional Resources Load
     │
     ├── Analytics Scripts
     ├── Advertising Resources
     ├── Social Media Widgets
     └── Third-Party Services
```

Browser automation allows the Privacy Scanner to observe these resources while the website is running.

This provides more realistic information about website behavior than static HTML analysis alone.

---

# 🔐 Privacy Interpretation

Privacy Scanner detects technical indicators.

These indicators should be interpreted carefully.

For example:

### Third-Party Domain

A third-party domain may provide:

* Fonts
* Images
* Content delivery
* Security services
* Analytics
* Advertising

Therefore, a third-party request is not automatically a privacy violation.

---

### Cookie

A cookie may be necessary for:

* Login sessions
* Security
* User preferences
* Shopping carts

Therefore, the presence of cookies does not automatically indicate tracking.

---

### Known Tracker

A detected known tracker indicates that a domain or service matched the scanner's tracker information.

The actual privacy impact can depend on:

* Website configuration
* Tracker functionality
* Data collected
* User consent
* Regional privacy regulations

---

# ⚠️ Current Scope and Limitations

The scanner analyzes observable website behavior in a browser environment.

It may not detect every privacy technology used by a website.

Examples of advanced techniques that may require future improvements include:

* Advanced browser fingerprinting
* Canvas fingerprinting
* WebGL fingerprinting
* Audio fingerprinting
* Server-side tracking
* Encrypted tracking requests
* Authenticated user tracking
* Cross-device tracking
* Tracking performed after user interaction

The results should therefore be considered an analysis of observable browser behavior rather than a complete privacy audit.

---

# 🔮 Future Improvements

Possible future additions include:

* Privacy risk scoring
* Tracker severity classification
* Advanced fingerprinting detection
* Consent banner analysis
* Privacy policy analysis
* Historical scan comparison
* Scan database
* User authentication
* Web dashboard
* PDF reports
* HTML reports
* Exportable JSON reports
* Scheduled website scans
* Tracker database updates
* Advanced visualization

---

# 🔐 Ethical and Responsible Use

Privacy Scanner should be used responsibly.

Use the project for:

* Websites you own
* Websites you are authorized to analyze
* Publicly accessible websites for legitimate research
* Educational purposes
* Privacy and security research

Do not use the project to:

* Attack websites
* Overload servers
* Bypass security mechanisms
* Circumvent access controls
* Collect unauthorized personal information

Always respect applicable laws, website policies, and responsible scanning practices.

---

# 📄 `.gitignore`

The `.gitignore` file should be used to prevent unnecessary or sensitive files from being uploaded to version control.

Typical files and directories that may be ignored include:

```text
venv/
__pycache__/
*.pyc
.env
backend/screenshots/*
```

Depending on the project requirements, screenshots may be included or excluded from Git.

---

# 🤝 Contributing

Future contributions can focus on improving:

* Tracker databases
* Domain classification
* Cookie analysis
* Browser storage analysis
* Scan performance
* Privacy scoring
* Reporting
* User interface development

The modular structure allows new scanner components to be added without significantly changing the existing codebase.

---


# 👨‍💻 Project Status

**Current Status: Active Development**

Privacy Scanner currently provides a modular browser-based foundation for analyzing website privacy behavior, including domain analysis, cookie analysis, tracker detection, storage analysis, and browser-based scanning.

The project can be expanded further with advanced privacy analysis, reporting, scoring, and visualization features.
