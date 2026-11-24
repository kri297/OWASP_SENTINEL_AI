"""
OWASP Sentinel AI - AI Vulnerability Analyzer & Knowledge Base
Provides deep vulnerability explanations, context-specific remediations,
and executive risk summaries using Google Gemini (REST API) with robust rule-based fallback.
"""

import logging
import os
import requests
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Comprehensive Security Knowledge Base for Rule-Based Fallback
KNOWLEDGE_BASE = {
    "sql injection": {
        "description": "SQL Injection occurs when untrusted user input is directly concatenated into dynamic database queries rather than being handled via parameterized statements or prepared queries. An attacker can manipulate query syntax to read, alter, or delete database contents.",
        "remediation": "1. Replace all dynamic string concatenation with parameterized queries or prepared statements.\n2. Utilize an Object-Relational Mapper (ORM) with automated parameter binding.\n3. Implement least-privilege database user accounts to restrict potential database damage.\n4. Apply input validation and allow-listing for expected formats.",
        "attack_scenario": "An attacker supplies crafted SQL syntax such as ' OR 1=1-- into a vulnerable parameter, bypassing authentication or dumping entire database tables through error or union-based responses.",
        "severity": "Critical",
        "cwe": "CWE-89",
        "owasp": "A03:2021-Injection"
    },
    "cross-site scripting": {
        "description": "Cross-Site Scripting (XSS) arises when an application includes unvalidated or unescaped user input within web page output. When rendered by a victim's browser, malicious JavaScript executes in the victim's session context.",
        "remediation": "1. Apply contextual output encoding (e.g. HTML entity encoding, JavaScript hex encoding) before reflecting user input in browser templates.\n2. Enforce a strong Content-Security-Policy (CSP) restricting script execution (avoid 'unsafe-inline').\n3. Mark all sensitive session cookies with the HttpOnly flag to prevent JavaScript cookie theft.\n4. Use modern web frameworks that automatically sanitize outputs.",
        "attack_scenario": "An attacker tricks an authenticated user into clicking a crafted URL containing an unescaped script probe, capturing the victim's session cookie or forging transactions within the application.",
        "severity": "High",
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection"
    },
    "security header": {
        "description": "Missing HTTP security headers represent a defense-in-depth failure. Headers like Content-Security-Policy, HSTS, X-Frame-Options, and X-Content-Type-Options instruct modern web browsers to enforce strict safety boundaries against clickjacking, MIME-sniffing, and code injection.",
        "remediation": "1. Deploy Content-Security-Policy (CSP) defining approved sources for script and media assets.\n2. Enable HTTP Strict Transport Security (HSTS) with a long max-age (e.g. 31536000 seconds).\n3. Set X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors) to defeat clickjacking attacks.\n4. Set X-Content-Type-Options: nosniff to stop MIME type sniffing.",
        "attack_scenario": "Without X-Frame-Options or CSP, an attacker embeds the target website inside a transparent iframe on a malicious webpage, enticing a logged-in user to click concealed buttons (Clickjacking).",
        "severity": "Medium",
        "cwe": "CWE-693",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    "cookie": {
        "description": "Cookies stored without essential protective attributes (HttpOnly, Secure, SameSite) are vulnerable to interception, client-side script theft, or cross-site request forgery attacks.",
        "remediation": "1. Ensure all session and authentication cookies include the 'HttpOnly' flag so client-side JavaScript cannot read them.\n2. Include the 'Secure' flag to ensure cookies are only transmitted over TLS/HTTPS encrypted connections.\n3. Set 'SameSite=Lax' or 'SameSite=Strict' to mitigate Cross-Site Request Forgery (CSRF).",
        "attack_scenario": "If an XSS weakness exists and session cookies lack HttpOnly, an attacker executes document.cookie and immediately exfiltrates active authentication tokens to an external server.",
        "severity": "Medium",
        "cwe": "CWE-1004",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    "csrf": {
        "description": "Cross-Site Request Forgery (CSRF) allows malicious sites to transmit unauthorized commands on behalf of an authenticated user because the browser automatically attaches ambient session cookies to cross-origin requests.",
        "remediation": "1. Implement synchronized anti-CSRF tokens for all state-altering POST/PUT/DELETE forms and API requests.\n2. Configure SameSite=Lax or SameSite=Strict on all authentication cookies.\n3. Validate the Origin and Referer request headers on incoming state-changing operations.",
        "attack_scenario": "A victim visits a malicious site while logged into the vulnerable application. The malicious site automatically submits an invisible form modifying the victim's email address or password.",
        "severity": "Medium",
        "cwe": "CWE-352",
        "owasp": "A01:2021-Broken Access Control"
    },
    "cors": {
        "description": "Overly permissive Cross-Origin Resource Sharing (CORS) configurations, such as reflecting arbitrary Origin headers or wildcard '*' origins with credentials, allow malicious websites to make authenticated cross-domain requests and read private user responses.",
        "remediation": "1. Validate incoming Origin headers against a strict server-side domain allow-list.\n2. Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.\n3. Restrict exposed headers and methods to only those strictly required.",
        "attack_scenario": "An attacker creates a website that triggers authenticated XHR requests to the target API, leveraging permissive CORS reflection to read sensitive account data returned in responses.",
        "severity": "High",
        "cwe": "CWE-942",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    "secret": {
        "description": "Exposure of hardcoded API keys, private keys, or tokens in source code or client-side files grants unauthorized parties direct access to backend systems, third-party APIs, or cloud resources.",
        "remediation": "1. Immediately revoke, invalidate, and rotate any exposed tokens or credentials.\n2. Store secrets in environment variables or dedicated secret management services (e.g. HashiCorp Vault, AWS Secrets Manager).\n3. Use automated secret scanners in pre-commit git hooks and CI/CD pipelines.",
        "attack_scenario": "An attacker identifies an exposed cloud provider API key in a public script, using it to query private infrastructure, exfiltrate stored records, or spin up unauthorized resources.",
        "severity": "High",
        "cwe": "CWE-798",
        "owasp": "A01:2021-Broken Access Control"
    },
    "debug": {
        "description": "Exposing detailed stack traces, debugging consoles, or framework exception screens provides attackers with internal file paths, framework versions, database structures, and environment parameters.",
        "remediation": "1. Turn off framework debugging modes in production environments (e.g., set DEBUG = False).\n2. Implement a global exception handler that logs detailed stack traces internally while returning sanitized, generic error pages to users.\n3. Restrict access to diagnostic endpoints via network firewalls and authentication.",
        "attack_scenario": "An attacker provokes an application exception by passing invalid input, extracting backend directory structures and library versions from the stack trace to tailor targeted exploits.",
        "severity": "Medium",
        "cwe": "CWE-209",
        "owasp": "A05:2021-Security Misconfiguration"
    }
}


class AIAnalyzer:
    """Provides AI-powered or rule-based intelligence for vulnerability analysis and remediation."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.cache: Dict[str, Dict[str, str]] = {}
        self.models_to_try = ["gemini-flash-lite-latest", "gemini-3.8-flash", "gemini-2.5-flash-lite"]
        self.use_ai = bool(self.api_key)
        if self.use_ai:
            logger.info("AIAnalyzer: Initialized with Gemini API credentials.")

    def _call_gemini_api(self, prompt: str) -> Optional[str]:
        """Make direct REST call to Google Gemini with model fallback and fast timeout."""
        if not self.api_key:
            return None

        for model_name in self.models_to_try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={self.api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 350}
            }
            try:
                resp = requests.post(url, json=payload, timeout=8)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates and "content" in candidates[0]:
                        parts = candidates[0]["content"].get("parts", [])
                        if parts:
                            return parts[0].get("text", "").strip()
            except Exception as e:
                logger.debug("Gemini model %s query skipped: %s", model_name, e)

        return None

    def _get_rule_fallback(self, vuln_type: str) -> Dict[str, Any]:
        """Return standardized baseline knowledge for any finding."""
        lower_type = vuln_type.lower()
        for key, data in KNOWLEDGE_BASE.items():
            if key in lower_type:
                return data
        return {
            "description": f"Potential security vulnerability discovered: {vuln_type}. May violate least-privilege or defensive boundary controls.",
            "remediation": "Audit the affected endpoint, sanitize untrusted parameters, and enforce defensive security configuration controls.",
            "attack_scenario": "An attacker targets this parameter or configuration to probe or compromise application boundaries.",
            "severity": "Medium",
            "cwe": "CWE-16",
            "owasp": "A05:2021-Security Misconfiguration"
        }

    def enrich(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich vulnerability with context-specific AI description and fix instructions."""
        vuln_type = vuln.get("vuln_type", "Unknown")
        cache_key = f"{vuln_type}::{vuln.get('parameter', '')}"

        if cache_key in self.cache:
            return self.cache[cache_key]

        rule_data = self._get_rule_fallback(vuln_type)

        if self.use_ai:
            prompt = (
                f"You are an expert OWASP application security engineer.\n"
                f"Vulnerability: {vuln_type}\n"
                f"URL: {vuln.get('url', 'N/A')}\n"
                f"Parameter/Component: {vuln.get('parameter', 'N/A')}\n"
                f"Evidence: {vuln.get('evidence', 'N/A')}\n\n"
                f"Provide concise, high-impact security analysis:\n"
                f"1. A 2-sentence explanation of what went wrong and the security impact.\n"
                f"2. Practical code or configuration remediation instructions in 2-3 bullet points."
            )
            ai_text = self._call_gemini_api(prompt)
            if ai_text:
                result = {
                    "description": ai_text.split("2.")[0].replace("1.", "").strip() if "2." in ai_text else ai_text,
                    "remediation": ("2. " + ai_text.split("2.", 1)[1]).strip() if "2." in ai_text else rule_data["remediation"],
                }
                self.cache[cache_key] = result
                return result

        result = {
            "description": vuln.get("description") or rule_data["description"],
            "remediation": vuln.get("remediation") or rule_data["remediation"],
        }
        self.cache[cache_key] = result
        return result
