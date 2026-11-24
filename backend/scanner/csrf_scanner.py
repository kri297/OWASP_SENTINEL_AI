"""
OWASP Sentinel AI - Cross-Site Request Forgery (CSRF) Scanner
Inspects discovered HTML forms to verify the presence of anti-CSRF tokens and protection mechanisms.
OWASP Category: A01:2021 - Broken Access Control | CWE-352
"""

import logging
from typing import List, Dict, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class CSRFScanner:
    """Detects state-changing forms lacking anti-CSRF token parameters or headers."""

    # Common anti-CSRF token parameter names
    KNOWN_CSRF_NAMES = {
        "csrf", "xsrf", "_csrf", "_xsrf", "csrf_token", "csrfmiddlewaretoken",
        "authenticity_token", "antiforgery", "__requestverificationtoken",
        "nonce", "token", "form_token", "csrf-token"
    }

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def scan(self, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []

        for form in forms:
            method = form.get("method", "GET").upper()
            action = form.get("action", "")
            page_url = form.get("page_url", action)
            inputs = form.get("inputs", [])

            # CSRF is primary risk for state-changing methods (POST, PUT, DELETE)
            if method not in ("POST", "PUT", "DELETE"):
                continue

            # Skip trivial search forms
            input_names = [inp.get("name", "").lower() for inp in inputs if inp.get("name")]
            if len(inputs) <= 1 and any("search" in name or "query" in name for name in input_names):
                continue

            has_csrf_token = False
            for name in input_names:
                if any(token_id in name for token_id in self.KNOWN_CSRF_NAMES):
                    has_csrf_token = True
                    break

            if not has_csrf_token:
                findings.append({
                    "vuln_type": "Missing Anti-CSRF Protection in Form",
                    "severity": "Medium",
                    "confidence": "Medium",
                    "url": page_url,
                    "parameter": action,
                    "evidence": f"Form submitting to '{action}' via {method} does not contain an anti-CSRF token field. Inputs: {', '.join(input_names[:6])}",
                    "description": f"The form submitting to '{action}' lacks an identifiable anti-CSRF token. If the application relies on ambient credentials (cookies), an attacker can forge unauthorized state-changing actions on behalf of authenticated users.",
                    "remediation": "Include a cryptographically random, unique, per-session anti-CSRF token in all state-changing forms, or enforce SameSite=Strict cookies and verify Origin/Referer headers.",
                    "cwe_id": "CWE-352",
                    "owasp_category": "A01:2021-Broken Access Control"
                })

        return findings
