"""
OWASP Sentinel AI - Security Header & Information Disclosure Scanner
Checks for missing or misconfigured security headers and information leakage headers.
OWASP Category: A05:2021 - Security Misconfiguration
"""

import logging
from typing import List, Dict, Any
import requests

logger = logging.getLogger(__name__)


class SecurityHeaderScanner:
    """Evaluates HTTP response headers for missing defense-in-depth protections."""

    REQUIRED_HEADERS = {
        "Content-Security-Policy": {
            "severity": "Medium",
            "cwe_id": "CWE-693",
            "desc": "Content-Security-Policy (CSP) is missing. CSP helps mitigate Cross-Site Scripting (XSS) and data injection attacks by restricting resources that can be loaded.",
            "remediation": "Configure a strong Content-Security-Policy header specifying trusted sources for scripts, styles, images, and other resources (e.g., default-src 'self')."
        },
        "Strict-Transport-Security": {
            "severity": "High",
            "cwe_id": "CWE-319",
            "desc": "HTTP Strict Transport Security (HSTS) is missing. Without HSTS, clients may communicate over unencrypted HTTP, leaving them vulnerable to Man-in-the-Middle (MitM) downgrade attacks.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses."
        },
        "X-Content-Type-Options": {
            "severity": "Low",
            "cwe_id": "CWE-693",
            "desc": "X-Content-Type-Options header is missing or not set to 'nosniff'. Browsers may perform MIME-sniffing and execute non-executable files as scripts.",
            "remediation": "Set 'X-Content-Type-Options: nosniff' on all responses."
        },
        "X-Frame-Options": {
            "severity": "Medium",
            "cwe_id": "CWE-1021",
            "desc": "X-Frame-Options (or CSP frame-ancestors) is missing. The application may be vulnerable to Clickjacking attacks allowing attackers to frame the site and deceive users.",
            "remediation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors' directive."
        },
        "Referrer-Policy": {
            "severity": "Low",
            "cwe_id": "CWE-200",
            "desc": "Referrer-Policy header is missing. Sensitive URL parameters may leak to external domains via the Referer HTTP header.",
            "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
        },
        "Permissions-Policy": {
            "severity": "Low",
            "cwe_id": "CWE-693",
            "desc": "Permissions-Policy (formerly Feature-Policy) is missing. Modern browser capabilities (geolocation, camera, microphone) are not explicitly restricted.",
            "remediation": "Configure 'Permissions-Policy: camera=(), microphone=(), geolocation=()' to restrict unnecessary browser APIs."
        }
    }

    DISCLOSURE_HEADERS = [
        ("Server", "Web server software and version disclosure", "Low", "CWE-200"),
        ("X-Powered-By", "Backend technology or framework disclosure", "Low", "CWE-200"),
        ("X-AspNet-Version", "ASP.NET version disclosure", "Low", "CWE-200"),
        ("X-Runtime", "Server runtime indicator", "Info", "CWE-200"),
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def _is_intermediary_challenge(self, resp: requests.Response) -> bool:
        """
        Detects if the response is a Vercel challenge checkpoint, Cloudflare challenge,
        WAF interstitial, or anti-bot challenge rather than the real application response.
        """
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body_lower = resp.text[:5000].lower()

        # 1. Vercel Security Checkpoint / Challenge indicators
        if (
            "x-vercel-challenge" in headers_lower or
            "x-vercel-challenge-token" in headers_lower or
            headers_lower.get("x-vercel-mitigated") == "challenge" or
            "vercel security checkpoint" in body_lower or
            "vercel challenge" in body_lower or
            "<title>vercel security checkpoint</title>" in body_lower
        ):
            return True

        # 2. Cloudflare Turnstile / Challenge indicators
        if (
            "cf-mitigated" in headers_lower or
            "cf-chl-bypass" in headers_lower or
            ("just a moment..." in body_lower and "cloudflare" in body_lower) or
            ("turnstile" in body_lower and "challenge" in body_lower) or
            "attention required! | cloudflare" in body_lower
        ):
            return True

        # 3. Generic WAF / Intermediary challenge indicators
        if (
            "x-datadome" in headers_lower or
            "x-sucuri-id" in headers_lower or
            ("x-amz-cf-id" in headers_lower and resp.status_code in (403, 429) and ("blocked" in body_lower or "waf" in body_lower))
        ):
            return True

        return False

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        findings = []
        if not urls:
            return findings

        # Check primary URL first
        target = urls[0]
        try:
            resp = requests.get(target, timeout=self.timeout, verify=False, allow_redirects=True)
            status_code = resp.status_code
            status_reason = resp.reason or ("OK" if status_code == 200 else "")
            headers = resp.headers

            # -------------------------------------------------------------
            # CONDITION 1: Intermediary Challenge (e.g. Vercel Security Checkpoint)
            # -------------------------------------------------------------
            if self._is_intermediary_challenge(resp):
                findings.append({
                    "vuln_type": "Security Header Verification Inconclusive",
                    "severity": "Info",
                    "confidence": "Low",
                    "url": target,
                    "parameter": "HTTP Response",
                    "evidence": f"HTTP status: {status_code} {status_reason} | Intermediary security challenge detected.",
                    "description": "Security header verification inconclusive – intermediary security challenge detected. The application response was intercepted by an automated security challenge or blocking page (such as Vercel Security Checkpoint or WAF), preventing authoritative analysis of origin security headers.",
                    "remediation": "Temporarily disable Vercel Attack Challenge Mode or configure a bypass secret/cookie to enable direct scanner inspection of production application headers.",
                    "cwe_id": "CWE-693",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "verification_status": "Needs verification",
                    "http_status": f"{status_code} {status_reason}",
                    "response_type": "Intermediary Challenge",
                    "actual_content_detected": "Vercel Security Checkpoint",
                    "recommended_classification": "Informational / Inconclusive Scan",
                    "verification_guidance": "Security header verification inconclusive – intermediary security challenge detected."
                })
                # Do NOT evaluate missing application headers against a challenge page!
                return findings

            # -------------------------------------------------------------
            # CONDITION 2: HTTP 403 (Request Forbidden)
            # -------------------------------------------------------------
            if status_code == 403:
                findings.append({
                    "vuln_type": "Access Forbidden (HTTP 403)",
                    "severity": "Info",
                    "confidence": "Low",
                    "url": target,
                    "parameter": "HTTP Status 403",
                    "evidence": "HTTP status: 403 Forbidden | Request was forbidden by access control policy.",
                    "description": "HTTP 403: Request forbidden. Direct evaluation of application security headers is restricted by server access controls.",
                    "remediation": "Verify authorization credentials, IP allow-listing, or URL routing permissions.",
                    "cwe_id": "CWE-284",
                    "owasp_category": "A01:2021-Broken Access Control",
                    "verification_status": "Needs verification",
                    "http_status": "403 Forbidden",
                    "response_type": "HTML (Forbidden)",
                    "actual_content_detected": "Not established",
                    "recommended_classification": "Informational / Restricted Access",
                    "verification_guidance": "Request forbidden: Verify access permissions before evaluating security posture."
                })
                return findings

            # -------------------------------------------------------------
            # CONDITION 3: HTTP 429 (Rate Limited)
            # -------------------------------------------------------------
            if status_code == 429:
                findings.append({
                    "vuln_type": "Scanner Rate Limited (HTTP 429)",
                    "severity": "Info",
                    "confidence": "Low",
                    "url": target,
                    "parameter": "HTTP Status 429",
                    "evidence": "HTTP status: 429 Too Many Requests | Rate limiting threshold triggered.",
                    "description": "HTTP 429: Rate limited. The target server throttled scanner requests. Header verification is incomplete.",
                    "remediation": "Reduce scan rate or whitelist scanner IP addresses in the reverse proxy rate limiter.",
                    "cwe_id": "CWE-799",
                    "owasp_category": "A04:2021-Insecure Design",
                    "verification_status": "Needs verification",
                    "http_status": "429 Too Many Requests",
                    "response_type": "HTML (Rate Limited)",
                    "actual_content_detected": "Not established",
                    "recommended_classification": "Informational / Rate Limited",
                    "verification_guidance": "Rate limit triggered: Reduce scan rate or whitelist scanner IP."
                })
                return findings

            # -------------------------------------------------------------
            # CONDITION 4: HTTP 5xx (Server-Side Error)
            # -------------------------------------------------------------
            if 500 <= status_code <= 599:
                findings.append({
                    "vuln_type": f"Server-Side Error (HTTP {status_code})",
                    "severity": "Medium",
                    "confidence": "Low",
                    "url": target,
                    "parameter": f"HTTP Status {status_code}",
                    "evidence": f"HTTP status: {status_code} {status_reason} | Server encountered an internal error during inspection.",
                    "description": f"HTTP {status_code}: Server-side error. Security header verification on an internal server error response is inconclusive.",
                    "remediation": f"Check server-side logs and application diagnostics for HTTP {status_code} errors.",
                    "cwe_id": "CWE-209",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "verification_status": "Needs verification",
                    "http_status": f"{status_code} {status_reason}",
                    "response_type": "HTML (Server Error)",
                    "actual_content_detected": "Not established",
                    "recommended_classification": "Informational / Server Error",
                    "verification_guidance": f"Server error: Security header verification inconclusive due to HTTP {status_code} response."
                })
                return findings

            # -------------------------------------------------------------
            # CONDITION 5: HTTP 200 (Application Response Successfully Received)
            # -------------------------------------------------------------
            for header_name, meta in self.REQUIRED_HEADERS.items():
                if header_name.lower() not in [h.lower() for h in headers.keys()]:
                    if header_name == "Strict-Transport-Security" and not target.startswith("https://"):
                        continue

                    findings.append({
                        "vuln_type": f"Missing Security Header: {header_name}",
                        "severity": meta["severity"],
                        "confidence": "High",
                        "url": target,
                        "parameter": header_name,
                        "evidence": f"HTTP status: 200 OK | Header '{header_name}' was not present in HTTP response.",
                        "description": meta["desc"],
                        "remediation": meta["remediation"],
                        "cwe_id": meta["cwe_id"],
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "verification_status": "Verified Exposure",
                        "http_status": "200 OK",
                        "response_type": "Application Response",
                        "actual_content_detected": "Established",
                        "recommended_classification": f"{meta['severity']} Severity Finding",
                        "verification_guidance": "Verified missing defensive header on HTTP 200 application response."
                    })

            for d_header, desc, sev, cwe in self.DISCLOSURE_HEADERS:
                for h_key, h_val in headers.items():
                    if h_key.lower() == d_header.lower():
                        findings.append({
                            "vuln_type": f"Information Disclosure in Header: {d_header}",
                            "severity": sev,
                            "confidence": "High",
                            "url": target,
                            "parameter": d_header,
                            "evidence": f"HTTP status: 200 OK | {d_header}: {h_val}",
                            "description": f"{desc}. Disclosing server software, versions, or frameworks assists attackers in identifying version-specific vulnerabilities.",
                            "remediation": f"Disable or suppress the '{d_header}' header in the web server or reverse proxy configuration.",
                            "cwe_id": cwe,
                            "owasp_category": "A05:2021-Security Misconfiguration",
                            "verification_status": "Verified Exposure",
                            "http_status": "200 OK",
                            "response_type": "Application Response",
                            "actual_content_detected": "Established",
                            "recommended_classification": f"{sev} Severity Finding",
                            "verification_guidance": "Verified server technology disclosure in HTTP response header."
                        })

        except Exception as e:
            logger.debug("Header scanner error on %s: %s", target, e)

        return findings
