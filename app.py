"""
Automated Web Security Scanner
A passive, read-only security header analyser built with Streamlit.
Only use against websites you own or have explicit permission to assess.
"""

import streamlit as st
import requests
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Section 1 — Constants & Finding Templates
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT = 10  # seconds

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "label": "Content-Security-Policy (CSP)",
        "explanation_fail": (
            "The Content-Security-Policy header is missing. CSP tells the browser "
            "which sources of content (scripts, styles, images, etc.) are trusted. "
            "Without it, the site is more vulnerable to Cross-Site Scripting (XSS) "
            "and data-injection attacks."
        ),
        "remediation": (
            "Add a Content-Security-Policy header to your web server or application. "
            "Example (strict starting point): "
            "`Content-Security-Policy: default-src 'self'`. "
            "Refine the policy to allow only the specific origins your site needs."
        ),
        "severity": "FAIL",
    },
    "Strict-Transport-Security": {
        "label": "Strict-Transport-Security (HSTS)",
        "explanation_fail": (
            "The Strict-Transport-Security header is missing. HSTS instructs browsers "
            "to only communicate with the site over HTTPS, preventing SSL-stripping "
            "attacks and accidental HTTP connections."
        ),
        "remediation": (
            "Add the HSTS header with a suitable max-age. "
            "Example: `Strict-Transport-Security: max-age=31536000; includeSubDomains`. "
            "Ensure your HTTPS configuration is stable before enabling this header, "
            "as it cannot be easily undone during the max-age window."
        ),
        "severity": "FAIL",
    },
    "X-Content-Type-Options": {
        "label": "X-Content-Type-Options",
        "explanation_fail": (
            "The X-Content-Type-Options header is missing. Without it, some browsers "
            "may try to 'sniff' the MIME type of a response, which can allow an "
            "attacker to trick the browser into executing files as a different type "
            "(e.g., running a text file as JavaScript)."
        ),
        "remediation": (
            "Add `X-Content-Type-Options: nosniff` to all HTTP responses. "
            "This is a simple, one-line change in your web server configuration "
            "(Apache, Nginx, IIS, or application middleware)."
        ),
        "severity": "WARN",
    },
    "X-Frame-Options": {
        "label": "X-Frame-Options",
        "explanation_fail": (
            "The X-Frame-Options header is missing. This header prevents your page "
            "from being embedded in an <iframe> on another domain, defending against "
            "clickjacking attacks where an attacker overlays an invisible frame over "
            "a legitimate-looking page to hijack user clicks."
        ),
        "remediation": (
            "Add `X-Frame-Options: DENY` (or `SAMEORIGIN` if you need same-domain "
            "framing). Alternatively, set `frame-ancestors` in your CSP policy, "
            "which is the modern equivalent."
        ),
        "severity": "WARN",
    },
}

# ---------------------------------------------------------------------------
# Section 2 — Scanner Engine
# ---------------------------------------------------------------------------

def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate that the URL is well-formed and uses http or https.
    Returns (is_valid: bool, error_message: str).
    """
    url = url.strip()
    if not url:
        return False, "Please enter a URL."
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, (
            f"Invalid scheme '{parsed.scheme}'. "
            "URL must start with http:// or https://"
        )
    if not parsed.netloc:
        return False, "URL does not contain a valid hostname."
    return True, ""


def check_https(url: str) -> dict:
    """Check whether the URL uses HTTPS."""
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return {
            "check": "HTTPS Usage",
            "status": "PASS",
            "explanation": "The URL uses HTTPS, meaning traffic is encrypted in transit.",
            "remediation": "No action required.",
        }
    return {
        "check": "HTTPS Usage",
        "status": "FAIL",
        "explanation": (
            "The URL uses plain HTTP. Data transmitted over HTTP is unencrypted "
            "and can be intercepted or modified by an attacker on the same network "
            "(man-in-the-middle attack)."
        ),
        "remediation": (
            "Obtain a TLS/SSL certificate (free options include Let's Encrypt) and "
            "configure your web server to serve all traffic over HTTPS (port 443). "
            "Set up a permanent HTTP → HTTPS redirect (HTTP 301) so users and "
            "search engines always reach the secure version."
        ),
    }


def fetch_response(url: str) -> tuple[requests.Response | None, str]:
    """
    Perform the HTTP GET request.
    Returns (response, error_message). On success, error_message is empty.
    """
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; AutomatedWebSecurityScanner/1.0; "
            "+passive-check)"
        )
    }
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers=headers,
            allow_redirects=True,
        )
        return response, ""
    except requests.exceptions.Timeout:
        return None, (
            f"Request timed out after {REQUEST_TIMEOUT} seconds. "
            "The server may be slow or unreachable."
        )
    except requests.exceptions.SSLError as exc:
        return None, f"SSL/TLS error: {exc}. The site's certificate may be invalid."
    except requests.exceptions.ConnectionError as exc:
        return None, f"Connection error: {exc}. Check the URL and your network."
    except requests.exceptions.RequestException as exc:
        return None, f"Request failed: {exc}"


def check_security_headers(response_headers: dict) -> list[dict]:
    """Inspect response headers for missing security headers."""
    findings = []
    # Normalise header names to lowercase for case-insensitive lookup
    lowered = {k.lower(): v for k, v in response_headers.items()}

    for header_name, meta in SECURITY_HEADERS.items():
        if header_name.lower() in lowered:
            value = lowered[header_name.lower()]
            findings.append({
                "check": meta["label"],
                "status": "PASS",
                "explanation": (
                    f"Header present with value: `{value}`"
                ),
                "remediation": "No action required.",
            })
        else:
            findings.append({
                "check": meta["label"],
                "status": meta["severity"],
                "explanation": meta["explanation_fail"],
                "remediation": meta["remediation"],
            })
    return findings


def check_cors(response_headers: dict) -> dict:
    """
    Passively check the Access-Control-Allow-Origin header.
    Only reads the header value — makes no additional requests.
    """
    lowered = {k.lower(): v for k, v in response_headers.items()}
    acao = lowered.get("access-control-allow-origin", None)

    if acao is None:
        return {
            "check": "CORS (Access-Control-Allow-Origin)",
            "status": "PASS",
            "explanation": (
                "No Access-Control-Allow-Origin header was returned. "
                "CORS is not broadly opened on this endpoint."
            ),
            "remediation": "No action required.",
        }
    if acao.strip() == "*":
        return {
            "check": "CORS (Access-Control-Allow-Origin)",
            "status": "WARN",
            "explanation": (
                "The Access-Control-Allow-Origin header is set to `*` (wildcard). "
                "This means any website can make cross-origin requests to this "
                "endpoint and read the response. For public APIs this may be "
                "intentional, but it is a risk for endpoints that return "
                "user-specific or sensitive data."
            ),
            "remediation": (
                "Restrict Access-Control-Allow-Origin to specific trusted origins "
                "rather than `*`. Example: "
                "`Access-Control-Allow-Origin: https://your-trusted-site.com`. "
                "If the wildcard is intentional for a fully public API, ensure the "
                "endpoint never returns authenticated or sensitive user data."
            ),
        }
    return {
        "check": "CORS (Access-Control-Allow-Origin)",
        "status": "PASS",
        "explanation": (
            f"Access-Control-Allow-Origin is set to a specific origin: `{acao}`. "
            "This is a more restrictive and generally safer configuration than a wildcard."
        ),
        "remediation": (
            "Verify that the listed origin(s) are intentional and that no sensitive "
            "endpoints unintentionally allow cross-origin access from untrusted domains."
        ),
    }


def run_scan(url: str) -> list[dict]:
    """
    Orchestrate all passive security checks against the given URL.
    Returns a list of finding dicts.
    """
    findings = []

    # HTTPS check (no network request needed)
    findings.append(check_https(url))

    # Fetch headers
    response, error = fetch_response(url)

    if error:
        findings.append({
            "check": "HTTP Request",
            "status": "FAIL",
            "explanation": f"Could not retrieve the page: {error}",
            "remediation": (
                "Ensure the URL is reachable, the server is online, and that no "
                "firewall or network policy is blocking the request."
            ),
        })
        return findings

    # Security headers
    findings.extend(check_security_headers(dict(response.headers)))

    # CORS
    findings.append(check_cors(dict(response.headers)))

    return findings


# ---------------------------------------------------------------------------
# Section 3 — Streamlit Dashboard
# ---------------------------------------------------------------------------

STATUS_CONFIG = {
    "PASS": {"icon": "✅", "label": "PASS", "color": "green"},
    "WARN": {"icon": "⚠️", "label": "WARN — Medium", "color": "orange"},
    "FAIL": {"icon": "🔴", "label": "FAIL — High", "color": "red"},
}

def render_finding_card(finding: dict) -> None:
    """Render a single finding as a styled expander card."""
    status = finding["status"]
    cfg = STATUS_CONFIG.get(status, STATUS_CONFIG["FAIL"])
    title = f"{cfg['icon']} {finding['check']}  —  **{cfg['label']}**"

    with st.expander(title, expanded=(status != "PASS")):
        st.markdown("**Finding**")
        st.info(finding["explanation"])
        if status != "PASS":
            st.markdown("**Remediation**")
            st.success(finding["remediation"])


def main() -> None:
    st.set_page_config(
        page_title="Web Security Scanner",
        page_icon="🔐",
        layout="wide",
    )

    # ── Header ──────────────────────────────────────────────────────────────
    st.title("🔐 Automated Web Security Scanner")
    st.caption(
        "Passive, read-only security header analysis. "
        "Only scan websites you own or have explicit permission to assess."
    )
    st.divider()

    # ── Sidebar ─────────────────────────────────────────────────────────────
    with st.sidebar:
        st.header("🔍 Scan Target")
        url_input = st.text_input(
            "Target URL",
            placeholder="https://example.com",
            help="Enter the full URL including http:// or https://",
        )
        scan_button = st.button("▶ Run Scan", type="primary", use_container_width=True)

        st.divider()
        st.markdown("### Checks Performed")
        st.markdown(
            "- 🔒 HTTPS Usage\n"
            "- 📋 Content-Security-Policy\n"
            "- 🚀 Strict-Transport-Security\n"
            "- 🛡️ X-Content-Type-Options\n"
            "- 🖼️ X-Frame-Options\n"
            "- 🌐 CORS Configuration\n"
        )

        st.divider()
        st.markdown("### ⚖️ Ethical Use")
        st.warning(
            "This tool performs **passive checks only** — it reads HTTP "
            "response headers and makes no attempts to exploit vulnerabilities. "
            "\n\n**Only scan websites you own or have written permission to test.**",
            icon="⚠️",
        )

    # ── Main area — pre-scan info ────────────────────────────────────────────
    if not scan_button:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("About this tool")
            st.markdown(
                "This scanner performs **passive, non-intrusive** security checks by "
                "analysing the HTTP response headers returned by a web server. "
                "No payloads are sent, no vulnerabilities are exploited, and no "
                "data is stored.\n\n"
                "**Severity levels:**\n"
                "- 🔴 **FAIL (High)** — Missing or misconfigured control with direct security impact\n"
                "- ⚠️ **WARN (Medium)** — Configuration that increases risk but may be intentional\n"
                "- ✅ **PASS** — Control is present and configured\n"
            )
        with col2:
            st.subheader("How to use")
            st.markdown(
                "1. Enter the full URL of a site you own in the sidebar\n"
                "2. Click **▶ Run Scan**\n"
                "3. Review the findings, explanations, and remediation advice\n\n"
                "**Tips:**\n"
                "- Always include the scheme: `https://` or `http://`\n"
                "- Scan the exact URL you want to check (subdomains may differ)\n"
                "- HTTP header checks reflect the server's current configuration\n"
            )
        st.stop()

    # ── Input validation ─────────────────────────────────────────────────────
    is_valid, error_msg = validate_url(url_input)
    if not is_valid:
        st.error(f"**Invalid URL:** {error_msg}")
        st.stop()

    # ── Run scan ─────────────────────────────────────────────────────────────
    with st.spinner(f"Scanning `{url_input}` …"):
        findings = run_scan(url_input)

    # ── Summary metrics ───────────────────────────────────────────────────────
    st.subheader(f"Results for `{url_input}`")

    passes = sum(1 for f in findings if f["status"] == "PASS")
    warns  = sum(1 for f in findings if f["status"] == "WARN")
    fails  = sum(1 for f in findings if f["status"] == "FAIL")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Checks", len(findings))
    m2.metric("✅ Pass", passes)
    m3.metric("⚠️ Warnings", warns)
    m4.metric("🔴 Failures", fails)

    st.divider()

    # ── Finding cards — ordered: FAIL → WARN → PASS ───────────────────────────
    ordered = (
        [f for f in findings if f["status"] == "FAIL"]
        + [f for f in findings if f["status"] == "WARN"]
        + [f for f in findings if f["status"] == "PASS"]
    )
    for finding in ordered:
        render_finding_card(finding)

    # ── Footer ────────────────────────────────────────────────────────────────
    st.divider()
    st.caption(
        "🔐 Automated Web Security Scanner · Passive checks only · "
        "Always obtain permission before scanning any website."
    )


if __name__ == "__main__":
    main()
