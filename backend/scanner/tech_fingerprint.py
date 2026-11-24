"""
OWASP Sentinel AI - Technology Fingerprinting Scanner
Identifies web servers, backend frameworks, CMS platforms, frontend libraries,
and CDN / WAF layers from HTTP response headers, cookies, and HTML structures.
"""

import logging
import re
from typing import List, Dict, Any
from urllib.parse import urlparse
import requests

logger = logging.getLogger(__name__)

# Known signatures
SERVER_SIGNATURES = [
    ("nginx", "Nginx", "Web Server"),
    ("apache", "Apache HTTP Server", "Web Server"),
    ("cloudflare", "Cloudflare", "CDN / Reverse Proxy"),
    ("litespeed", "LiteSpeed Web Server", "Web Server"),
    ("microsoft-iis", "Microsoft IIS", "Web Server"),
    ("caddy", "Caddy Server", "Web Server"),
    ("gunicorn", "Gunicorn (Python)", "WSGI Application Server"),
    ("uvicorn", "Uvicorn (FastAPI / ASGI)", "ASGI Application Server"),
    ("express", "Express (Node.js)", "Web Framework"),
]

FRAMEWORK_SIGNATURES = [
    (r"laravel", "Laravel (PHP)", "Backend Framework"),
    (r"django", "Django (Python)", "Backend Framework"),
    (r"rails|rack", "Ruby on Rails", "Backend Framework"),
    (r"express", "Express.js", "Backend Framework"),
    (r"flask", "Flask (Python)", "Backend Framework"),
    (r"spring", "Spring Boot (Java)", "Backend Framework"),
    (r"asp\.net|dotnet", "ASP.NET (Microsoft)", "Backend Framework"),
    (r"next\.js|_next", "Next.js", "Frontend / Fullstack Framework"),
    (r"nuxt", "Nuxt.js (Vue)", "Frontend / Fullstack Framework"),
    (r"vue", "Vue.js", "Frontend Framework"),
    (r"react", "React.js", "Frontend Framework"),
    (r"angular", "Angular", "Frontend Framework"),
]

CMS_SIGNATURES = [
    (r"wp-content|wp-includes|wordpress", "WordPress", "Content Management System"),
    (r"drupal", "Drupal", "Content Management System"),
    (r"joomla", "Joomla", "Content Management System"),
    (r"shopify", "Shopify", "E-Commerce Platform"),
    (r"magento", "Magento", "E-Commerce Platform"),
    (r"ghost", "Ghost", "Publishing Platform"),
]

CDN_WAF_SIGNATURES = [
    ("cf-ray", "Cloudflare", "CDN / DDoS Protection"),
    ("x-amz-cf-id", "Amazon CloudFront", "CDN"),
    ("x-akamai", "Akamai", "CDN / WAF"),
    ("x-sucuri", "Sucuri CloudProxy", "WAF"),
    ("x-fastly", "Fastly", "CDN"),
    ("x-github-request-id", "GitHub Pages", "Hosting"),
    ("x-vercel-id", "Vercel", "Cloud Edge Platform"),
    ("x-powered-by", None, "Custom Header"),
]


class TechFingerprinter:
    """Discovers underlying technologies powering the target web application."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "OWASP-Sentinel-AI-Auditor/2.0 (Security Scanner; +https://owaspsentinel.local)"
        })

    def fingerprint(self, urls: List[str]) -> Dict[str, Any]:
        """Inspect targets and aggregate technological fingerprints."""
        findings = {
            "server": None,
            "frameworks": [],
            "cms": [],
            "js_libraries": [],
            "cdn_waf": [],
            "technologies": [],
        }

        detected_names = set()

        def add_tech(name: str, category: str, version: str = None, confidence: str = "High", evidence: str = ""):
            if name and name not in detected_names:
                detected_names.add(name)
                entry = {
                    "name": name,
                    "category": category,
                    "version": version or "Detected",
                    "confidence": confidence,
                    "evidence": evidence,
                }
                findings["technologies"].append(entry)
                if category == "Web Server":
                    findings["server"] = entry
                elif "Framework" in category:
                    findings["frameworks"].append(entry)
                elif "CMS" in category or "Management" in category:
                    findings["cms"].append(entry)
                elif "CDN" in category or "WAF" in category or "Platform" in category:
                    findings["cdn_waf"].append(entry)
                else:
                    findings["js_libraries"].append(entry)

        sample_urls = urls[:5] if urls else []
        for url in sample_urls:
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.text[:100000]

                # Check Server Header
                server_hdr = headers_lower.get("server", "")
                if server_hdr:
                    for sig, display, cat in SERVER_SIGNATURES:
                        if sig in server_hdr.lower():
                            add_tech(display, cat, version=server_hdr, confidence="High", evidence=f"Server: {server_hdr}")
                            break
                    if not findings["server"]:
                        add_tech(server_hdr, "Web Server", version=server_hdr, confidence="Medium", evidence=f"Server: {server_hdr}")

                # Check X-Powered-By
                x_powered = headers_lower.get("x-powered-by", "")
                if x_powered:
                    add_tech(x_powered, "Backend Framework", version=x_powered, confidence="High", evidence=f"X-Powered-By: {x_powered}")

                # Check CDN / WAF headers
                for hdr_key, display, cat in CDN_WAF_SIGNATURES:
                    if hdr_key in headers_lower and display:
                        add_tech(display, cat, confidence="High", evidence=f"Header: {hdr_key}")

                # Check Cookies
                cookies_str = " ".join(resp.cookies.keys()).lower()
                if "phpsessid" in cookies_str:
                    add_tech("PHP", "Programming Language", confidence="High", evidence="PHPSESSID cookie")
                if "jsessionid" in cookies_str:
                    add_tech("Java / JVM", "Application Runtime", confidence="High", evidence="JSESSIONID cookie")
                if "csrftoken" in cookies_str or "django" in cookies_str:
                    add_tech("Django", "Backend Framework", confidence="Medium", evidence="csrftoken cookie")
                if "laravel_session" in cookies_str or "XSRF-TOKEN" in resp.cookies:
                    add_tech("Laravel", "Backend Framework", confidence="Medium", evidence="Laravel session cookies")
                if "connect.sid" in cookies_str:
                    add_tech("Express / Node.js", "Backend Framework", confidence="High", evidence="connect.sid cookie")

                # Body Inspection for Frameworks & CMS
                for pattern, name, cat in FRAMEWORK_SIGNATURES:
                    if re.search(pattern, body, re.IGNORECASE) or re.search(pattern, str(resp.headers), re.IGNORECASE):
                        add_tech(name, cat, confidence="Medium", evidence=f"Pattern '{pattern}' detected in markup")

                for pattern, name, cat in CMS_SIGNATURES:
                    if re.search(pattern, body, re.IGNORECASE):
                        add_tech(name, cat, confidence="High", evidence=f"CMS marker '{pattern}' discovered in HTML")

                # Frontend JS Libraries in script tags
                if "jquery" in body.lower():
                    add_tech("jQuery", "JavaScript Library", confidence="High", evidence="jquery script signature in HTML")
                if "bootstrap" in body.lower():
                    add_tech("Bootstrap UI", "CSS Framework", confidence="High", evidence="bootstrap css/js classes in HTML")
                if "tailwind" in body.lower() or "tw-" in body.lower():
                    add_tech("Tailwind CSS", "CSS Framework", confidence="Medium", evidence="tailwind classes in HTML")
                if "fontawesome" in body.lower() or "fa-" in body.lower():
                    add_tech("FontAwesome", "Icon Font", confidence="Medium", evidence="font-awesome markers")

            except Exception as e:
                logger.debug("Tech fingerprint error on %s: %s", url, e)

        # Default fallback if nothing found
        if not findings["technologies"]:
            parsed = urlparse(urls[0] if urls else "http://target.local")
            add_tech(f"Web Host ({parsed.netloc})", "Generic Web Server", confidence="Low", evidence="HTTP response available")

        return findings
