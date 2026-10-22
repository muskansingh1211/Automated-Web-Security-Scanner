# 🔐 Automated Web Security Scanner

A passive, read-only web security scanner built with Python and Streamlit. It analyses HTTP response headers to identify common security misconfigurations and provides severity-rated findings with remediation advice.

> ⚠️ **Ethical Use Notice:** Only scan websites you own or have explicit written permission to assess. This tool performs passive checks only — it reads response headers and never sends attack payloads or exploits vulnerabilities.

---

## Features

- **HTTPS Check** — Detects whether the target uses encrypted HTTPS or plain HTTP
- **Security Header Analysis** — Checks for four critical HTTP security headers:
  - `Content-Security-Policy` (CSP)
  - `Strict-Transport-Security` (HSTS)
  - `X-Content-Type-Options`
  - `X-Frame-Options`
- **CORS Configuration Check** — Passively reads `Access-Control-Allow-Origin` and flags wildcard (`*`) usage
- **Severity Levels** — Each finding is rated **High (FAIL)**, **Medium (WARN)**, or **Pass**
- **Remediation Advice** — Every finding includes a concrete, actionable fix
- **Input Validation** — Validates URL format and scheme before making any network request
- **Error Handling** — Gracefully handles timeouts, SSL errors, and connection failures

---

## Project Structure

```
Automated-Web-Security-Scanner/
├── app.py              # All application code (scanner engine + Streamlit dashboard)
└── requirements.txt    # Python dependencies
```

> All application code is contained in a single file (`app.py`) as required.

---

## Requirements

- Python 3.10 or newer
- pip

---

## Installation (Windows)

### 1. Clone or download the project

```powershell
cd e:\Automated-Web-Security-Scanner
```

### 2. Create and activate a virtual environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

> If you get an execution policy error, run this first:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
> ```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

---

## Running the App

```powershell
streamlit run app.py
```

Streamlit will start a local server and open the app in your browser automatically.
The default address is: **http://localhost:8501**

Press `Ctrl+C` in the terminal to stop the server.

---

## How to Use

1. Enter the full URL of a website you own into the **Target URL** field in the sidebar (e.g. `https://example.com`)
2. Click **▶ Run Scan**
3. Review the findings — failures and warnings are expanded automatically
4. Use the remediation advice in each card to fix the identified issues

---

## Severity Levels

| Severity | Meaning |
|---|---|
| 🔴 **FAIL — High** | Missing or misconfigured control with direct security impact |
| ⚠️ **WARN — Medium** | Configuration that increases risk but may be intentional |
| ✅ **PASS** | Control is present and correctly configured |

---

## Checks Reference

| Check | Severity if Missing | Description |
|---|---|---|
| HTTPS Usage | 🔴 High | Ensures traffic is encrypted in transit |
| Content-Security-Policy | 🔴 High | Prevents XSS and data-injection attacks |
| Strict-Transport-Security | 🔴 High | Forces HTTPS-only connections (SSL-stripping defence) |
| X-Content-Type-Options | ⚠️ Medium | Prevents MIME-type sniffing attacks |
| X-Frame-Options | ⚠️ Medium | Defends against clickjacking via iframes |
| CORS (Access-Control-Allow-Origin) | ⚠️ Medium | Flags wildcard cross-origin access |

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `streamlit` | ≥ 1.35.0 | Web dashboard framework |
| `requests` | ≥ 2.32.0 | HTTP requests to the target URL |

Standard library modules used: `urllib.parse` (URL validation).

---

## Technical Notes

- All HTTP requests use a **10-second timeout**
- Requests identify themselves with a descriptive `User-Agent` header
- Header lookups are **case-insensitive** (HTTP/1.1 headers are case-insensitive by spec)
- Findings are sorted by severity: failures first, then warnings, then passes
- No data is stored, logged, or transmitted beyond the single GET request to the target

---

## License

This project is for educational purposes. Use responsibly and legally.
