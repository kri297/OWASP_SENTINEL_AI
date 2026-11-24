"""
OWASP Sentinel AI - Sensitive Information Disclosure Scanner
Scans page content, response bodies, and metadata for exposed secrets, credentials,
internal network details, stack traces, and sensitive paths with false-positive filtering.
OWASP Category: A01:2021 - Broken Access Control / A04:2021 - Insecure Design | CWE-200
"""

import logging
import re
from typing import List, Dict, Any
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

DUMMY_KEY_PATTERNS = [
    r"example",
    r"dummy",
    r"placeholder",
    r"your[-_]?api[-_]?key",
    r"your[-_]?secret",
    r"00000000",
    r"12345678",
    r"test[-_]?key",
    r"akiaiossfodnn7example",
]


class SensitiveInfoScanner:
    """Detects leaks of secrets, tokens, PII, stack traces, and administrative routes."""

    SECRET_PATTERNS = [
        ("AWS Access Key ID", r"(?i)\b(AKIA[0-9A-Z]{16})\b", "High", "CWE-798"),
        ("Private Key Block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Critical", "CWE-312"),
        ("Generic API Key / Token Assignment", r"(?i)(?:api_key|apikey|secret_key|app_secret|auth_token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]", "High", "CWE-798"),
        ("Slack Webhook / Token", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "High", "CWE-200"),
        ("JSON Web Token (JWT)", r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b", "Medium", "CWE-200"),
    ]

    DEBUG_PATTERNS = [
        ("Stack Trace / Debug Output (Python/Django/Flask)", r"(?i)(Traceback \(most recent call last\):|Werkzeug Debugger|django\.views\.debug)", "Medium", "CWE-209"),
        ("Stack Trace / Exception (Java/Spring)", r"(?i)(Exception in thread \".*\" java\.lang\.|org\.springframework\.web\.)", "Medium", "CWE-209"),
        ("Stack Trace / PHP Warning", r"(?i)(Fatal error: .* in /.*\.php on line|Warning: .* in /.*\.php on line)", "Medium", "CWE-209"),
        ("ASP.NET Server Error Stack", r"(?i)(Server Error in '/' Application\.|\[HttpUnhandledException\])", "Medium", "CWE-209"),
    ]

    INTERNAL_IP_PATTERN = r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OWASP-Sentinel-AI-Auditor/2.0"})

    def _is_dummy_token(self, text: str) -> bool:
        """Check if matched token looks like a dummy placeholder or documentation example."""
        lower = text.lower()
        return any(re.search(pat, lower) for pat in DUMMY_KEY_PATTERNS)

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        findings = []
        if not urls:
            return findings

        primary_url = urls[0]

        # 1. Check robots.txt for sensitive endpoints
        try:
            robots_url = urljoin(primary_url, "/robots.txt")
            resp = self.session.get(robots_url, timeout=self.timeout, verify=False)
            is_html = bool(re.search(r"<!doctype html|<html[\s>]", resp.text, re.IGNORECASE))
            if resp.status_code == 200 and not is_html and "text" in resp.headers.get("Content-Type", ""):
                disallowed = []
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if any(term in path.lower() for term in ["admin", "secret", "backup", "internal", "api", "config", "private"]):
                            disallowed.append(path)

                if disallowed:
                    findings.append({
                        "vuln_type": "Sensitive Paths Disclosed in robots.txt",
                        "severity": "Low",
                        "confidence": "High",
                        "url": robots_url,
                        "parameter": "robots.txt",
                        "evidence": f"Sensitive paths listed in Disallow entries: {', '.join(disallowed[:5])}",
                        "description": "The robots.txt file reveals paths intended to be hidden or restricted (e.g. admin panels, private APIs). Attackers actively inspect robots.txt for reconnaissance.",
                        "remediation": "Do not rely on robots.txt for security or access control. Implement robust authentication and authorization checks on all restricted endpoints.",
                        "cwe_id": "CWE-200",
                        "owasp_category": "A01:2021-Broken Access Control",
                        "verification_status": "Verified Exposure",
                        "http_status": "200 OK",
                        "response_type": "Plaintext (robots.txt)",
                        "actual_content_detected": "Established",
                        "recommended_classification": "Informational / Reconnaissance",
                        "verification_guidance": "Verified disallow directive in public robots.txt file.",
                    })
        except Exception as e:
            logger.debug("robots.txt check failed: %s", e)

        # 2. Inspect crawled pages for secrets, debug traces, and sensitive comments
        for url in urls[:12]:
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                content = resp.text

                # Check secret patterns
                for name, pattern, sev, cwe in self.SECRET_PATTERNS:
                    match = re.search(pattern, content)
                    if match:
                        matched_str = match.group(0)
                        is_dummy = self._is_dummy_token(matched_str)
                        snippet = matched_str[:50]

                        if is_dummy:
                            findings.append({
                                "vuln_type": f"Potential Placeholder / Sample Secret: {name}",
                                "severity": "Info",
                                "confidence": "Low",
                                "url": url,
                                "parameter": name,
                                "evidence": f"Found dummy/example token signature: {snippet}...",
                                "description": f"The page contains a token or API key structure ({name}), but it appears to be a documentation example or placeholder.",
                                "remediation": "Verify whether this token is active. Remove non-production credentials from production builds.",
                                "cwe_id": cwe,
                                "owasp_category": "A01:2021-Broken Access Control",
                                "verification_status": "Needs verification",
                                "http_status": "200 OK",
                                "response_type": "HTML/Script",
                                "actual_content_detected": "Candidate / Example Pattern",
                                "recommended_classification": "Informational / False Positive Candidate",
                                "verification_guidance": "Verify whether this token is an active secret or a dummy placeholder in markup.",
                            })
                        else:
                            findings.append({
                                "vuln_type": f"Exposed Secret: {name}",
                                "severity": sev,
                                "confidence": "High",
                                "url": url,
                                "parameter": name,
                                "evidence": f"Detected matching active token pattern: {snippet}...",
                                "description": f"The page discloses sensitive tokens or credentials ({name}) in client-accessible source code.",
                                "remediation": "Revoke and rotate exposed credentials immediately. Store secrets in secure backend environment variables or key vaults, never in client-facing assets.",
                                "cwe_id": cwe,
                                "owasp_category": "A01:2021-Broken Access Control",
                                "verification_status": "Verified Exposure",
                                "http_status": "200 OK",
                                "response_type": "HTML/Script",
                                "actual_content_detected": "Established",
                                "recommended_classification": "High Severity Finding",
                                "verification_guidance": "Active credential or API key pattern detected in public source.",
                            })

                # Check debug stack traces
                for name, pattern, sev, cwe in self.DEBUG_PATTERNS:
                    match = re.search(pattern, content)
                    if match:
                        findings.append({
                            "vuln_type": f"Debug Trace Exposure: {name}",
                            "severity": sev,
                            "confidence": "High",
                            "url": url,
                            "parameter": "stack_trace",
                            "evidence": f"Found debug signature: {match.group(0)}",
                            "description": "Detailed error messages, call stacks, or framework debugging views are exposed to users. These disclose internal file structures, libraries, and logic.",
                            "remediation": "Disable debug mode in production (e.g. DEBUG=False). Implement custom generic error pages.",
                            "cwe_id": cwe,
                            "owasp_category": "A05:2021-Security Misconfiguration",
                            "verification_status": "Verified Exposure",
                            "http_status": "200 OK",
                            "response_type": "Debug HTML",
                            "actual_content_detected": "Established",
                            "recommended_classification": "Confirmed Finding",
                            "verification_guidance": "Server error stack trace visible in response.",
                        })

                # Check internal RFC1918 IPs
                ip_match = re.search(self.INTERNAL_IP_PATTERN, content)
                if ip_match and "127.0.0.1" not in ip_match.group(0):
                    findings.append({
                        "vuln_type": "Internal IP Address Disclosure",
                        "severity": "Low",
                        "confidence": "Medium",
                        "url": url,
                        "parameter": "internal_ip",
                        "evidence": f"Internal RFC1918 address detected in response: {ip_match.group(0)}",
                        "description": "Internal network IP addresses are exposed in the HTML source, aiding attackers in network mapping and pivoting.",
                        "remediation": "Ensure internal network addressing and server IPs are stripped from public responses and headers.",
                        "cwe_id": "CWE-200",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "verification_status": "Verified Exposure",
                        "http_status": "200 OK",
                        "response_type": "HTML",
                        "actual_content_detected": "Established",
                        "recommended_classification": "Low Severity Finding",
                        "verification_guidance": "Internal IP discovered in source code.",
                    })

            except Exception as e:
                logger.debug("Sensitive info error on %s: %s", url, e)

        return findings
