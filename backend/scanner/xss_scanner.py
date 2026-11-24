"""
OWASP Sentinel AI - Cross-Site Scripting (XSS) Scanner
Checks for reflected user input and unescaped HTML/JavaScript contexts in URL parameters and forms.
Also inspects client-side JavaScript for DOM-based XSS sink indicators.
OWASP Category: A03:2021 - Injection | CWE-79
"""

import html
import logging
import re
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests

logger = logging.getLogger(__name__)


class XSSScanner:
    """Non-destructive diagnostic scanner checking for unescaped reflections and dangerous DOM patterns."""

    # Benign canary payloads with unique identifiers
    CANARY_TOKEN = "sentinel_xss_test"
    PROBES = [
        f"<{CANARY_TOKEN}>",
        f"\"<b id={CANARY_TOKEN}>test</b>",
        f"'><script class='{CANARY_TOKEN}'>/*test*/</script>",
        f"javascript:alert('{CANARY_TOKEN}')"
    ]

    DOM_SINKS = [
        (r"document\.write\s*\(", "document.write()"),
        (r"element\.innerHTML\s*=", "innerHTML"),
        (r"\.outerHTML\s*=", "outerHTML"),
        (r"eval\s*\(.*location\.", "eval() with location source"),
        (r"setTimeout\s*\(.*location\.", "setTimeout() with location source"),
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OWASP-Sentinel-AI-Auditor/1.0"})

    def scan(self, urls: List[str], forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        tested_params = set()

        # 1. Test Reflected Parameters
        for url in urls[:15]:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            # Check DOM sinks in the page itself
            try:
                page_resp = self.session.get(url, timeout=self.timeout, verify=False)
                for pattern, sink_name in self.DOM_SINKS:
                    if re.search(pattern, page_resp.text):
                        findings.append({
                            "vuln_type": "Potential DOM-Based XSS Sink",
                            "severity": "Medium",
                            "confidence": "Medium",
                            "url": url,
                            "parameter": sink_name,
                            "evidence": f"Dangerous sink '{sink_name}' identified in client script.",
                            "description": f"The page uses dangerous DOM manipulation ({sink_name}). If untrusted user input (e.g. from window.location, document.referrer) flows into this sink, it can lead to DOM XSS.",
                            "remediation": "Replace dangerous sinks like innerHTML or document.write with safe DOM methods like textContent or element.setAttribute, and sanitize dynamic HTML.",
                            "cwe_id": "CWE-79",
                            "owasp_category": "A03:2021-Injection"
                        })
            except Exception:
                pass

            if not query_params:
                continue

            for param_name in query_params:
                param_key = f"{parsed.path}?{param_name}"
                if param_key in tested_params:
                    continue
                tested_params.add(param_key)

                for probe in self.PROBES:
                    test_params = {k: v[:] for k, v in query_params.items()}
                    test_params[param_name] = [probe]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                    try:
                        resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                        # Check if raw unescaped probe is reflected in the response
                        if probe in resp.text:
                            findings.append({
                                "vuln_type": "Reflected Cross-Site Scripting (XSS)",
                                "severity": "High",
                                "confidence": "High",
                                "url": url,
                                "parameter": param_name,
                                "evidence": f"Payload '{probe}' was reflected verbatim in response without HTML entity encoding.",
                                "description": f"Parameter '{param_name}' reflects user-supplied data directly into the HTML document without adequate contextual encoding or sanitization.",
                                "remediation": "Apply contextual output encoding (e.g. HTML entity encoding, JavaScript encoding) before rendering untrusted input, and implement a strict Content-Security-Policy.",
                                "cwe_id": "CWE-79",
                                "owasp_category": "A03:2021-Injection"
                            })
                            break
                    except Exception as e:
                        logger.debug("XSS test error on %s: %s", test_url, e)

        # 2. Test Form Inputs for Reflection
        for form in forms[:8]:
            action_url = form.get("action")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            for inp in inputs:
                param_name = inp.get("name")
                if not param_name or inp.get("type") in ("submit", "hidden", "button", "reset"):
                    continue

                probe = f"<b id={self.CANARY_TOKEN}>reflected_test</b>"
                form_data = {item.get("name"): item.get("value", "test") for item in inputs if item.get("name")}
                form_data[param_name] = probe

                try:
                    if method == "POST":
                        resp = self.session.post(action_url, data=form_data, timeout=self.timeout, verify=False)
                    else:
                        resp = self.session.get(action_url, params=form_data, timeout=self.timeout, verify=False)

                    if probe in resp.text:
                        findings.append({
                            "vuln_type": "Reflected XSS in Form Submission",
                            "severity": "High",
                            "confidence": "High",
                            "url": action_url,
                            "parameter": param_name,
                            "evidence": f"Form field '{param_name}' payload was returned unescaped in response.",
                            "description": f"The form field '{param_name}' reflects input directly into the rendered response without adequate output encoding.",
                            "remediation": "Sanitize and contextually encode all form submission values before rendering them in response templates.",
                            "cwe_id": "CWE-79",
                            "owasp_category": "A03:2021-Injection"
                        })
                        break
                except Exception as e:
                    logger.debug("Form XSS test error on %s: %s", action_url, e)

        return findings
