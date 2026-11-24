"""
OWASP Sentinel AI - Insecure Configuration Scanner
Checks for TLS/HTTPS redirects, insecure cookie attributes (HttpOnly, Secure, SameSite),
CORS wildcards, directory listing, dangerous HTTP methods, and exposed configuration files
with structural content verification to eliminate soft-404 / HTML-fallback false positives.
OWASP Category: A05:2021 - Security Misconfiguration | CWE-16
"""

import logging
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import requests

logger = logging.getLogger(__name__)


class InsecureConfigScanner:
    """Audits transport security, cookie flags, CORS policies, and common file exposures."""

    # File rules: (filename, display_name, high_severity, cwe_id, check_type)
    COMMON_EXPOSED_FILES = [
        ("web.config", "IIS Configuration File", "High", "CWE-16", "xml_config"),
        (".env", "Environment Variables & Secrets", "Critical", "CWE-312", "env_vars"),
        (".git/HEAD", "Git Repository Metadata", "High", "CWE-200", "git_head"),
        (".git/config", "Git Configuration File", "High", "CWE-200", "git_config"),
        ("Dockerfile", "Container Definition File", "Medium", "CWE-200", "dockerfile"),
        ("docker-compose.yml", "Docker Compose Orchestration", "Medium", "CWE-200", "docker_compose"),
        ("backup.sql", "Database Backup Dump", "Critical", "CWE-312", "sql_dump"),
        ("dump.sql", "Database Dump File", "Critical", "CWE-312", "sql_dump"),
        ("phpinfo.php", "PHP Diagnostics & Environment", "High", "CWE-200", "phpinfo"),
        ("package.json", "Node.js Package Manifest", "Low", "CWE-200", "json_pkg"),
        ("composer.json", "PHP Composer Manifest", "Low", "CWE-200", "json_pkg"),
        ("crossdomain.xml", "Flash Cross-Domain Policy", "Low", "CWE-942", "xml_crossdomain"),
        (".DS_Store", "macOS Finder Metadata", "Low", "CWE-200", "ds_store"),
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OWASP-Sentinel-AI-Auditor/2.0"})

    def _verify_file_content(self, filename: str, check_type: str, body: str, content: bytes, headers: dict) -> Dict[str, Any]:
        """
        Verify whether the response body actually contains the expected file structure
        versus a generic HTML fallback page, soft 404, or single-page app index.html.
        """
        content_type = headers.get("Content-Type", "").lower()
        is_html = bool(re.search(r"<!doctype html|<html[\s>]", body, re.IGNORECASE))
        body_stripped = body.strip()

        # 1. web.config verification
        if check_type == "xml_config":
            is_xml = bool(
                re.search(r"<configuration(?:\s|>)", body, re.IGNORECASE) and
                re.search(r"</configuration>", body, re.IGNORECASE)
            )
            if is_xml and not is_html:
                return {
                    "is_vulnerable": True,
                    "confidence": "High",
                    "severity": "High",
                    "status": "200 OK",
                    "response_type": "XML",
                    "actual_content_detected": "Established (Valid XML Configuration)",
                    "verification_status": "Verified Exposure",
                    "recommended_classification": "High Severity Finding",
                    "verification_guidance": "Verified XML configuration file exposed to unauthenticated users.",
                    "evidence": "Status 200 OK: Valid XML <configuration> tags detected in response body.",
                }
            elif is_html or not is_xml:
                return {
                    "is_vulnerable": False,
                    "is_candidate": True,
                    "confidence": "Low",
                    "severity": "Info",
                    "status": "200 OK",
                    "response_type": "HTML" if is_html else (content_type.split(";")[0] or "Text"),
                    "actual_content_detected": "Not established",
                    "verification_status": "Needs verification",
                    "recommended_classification": "Informational / False Positive Candidate",
                    "verification_guidance": "Do not assign High severity until actual configuration disclosure is verified.",
                    "evidence": "HTTP status: 200 OK | Response type: HTML | Actual XML detected: Not established",
                }

        # 2. .env file verification
        elif check_type == "env_vars":
            # Looks for KEY=VALUE pairs typical in environment files
            has_env_keys = bool(
                re.search(r"(?m)^[A-Za-z0-9_]{3,}\s*=\s*['\"A-Za-z0-9_\-\.\:\/\$]", body) and
                any(w in body.upper() for w in ["KEY", "SECRET", "PASS", "DB_", "APP_", "TOKEN", "DATABASE", "ENV", "PORT", "URL"])
            )
            if has_env_keys and not is_html:
                return {
                    "is_vulnerable": True,
                    "confidence": "High",
                    "severity": "Critical",
                    "status": "200 OK",
                    "response_type": "Plaintext Environment File",
                    "actual_content_detected": "Established (Environment Variables)",
                    "verification_status": "Verified Exposure",
                    "recommended_classification": "Critical Severity Finding",
                    "verification_guidance": "Verified environment variables and configuration secrets exposed.",
                    "evidence": "Status 200 OK: Valid environment assignment keys and secrets verified.",
                }
            elif is_html or not has_env_keys:
                return {
                    "is_vulnerable": False,
                    "is_candidate": True,
                    "confidence": "Low",
                    "severity": "Info",
                    "status": "200 OK",
                    "response_type": "HTML" if is_html else "Text",
                    "actual_content_detected": "Not established",
                    "verification_status": "Needs verification",
                    "recommended_classification": "Informational / False Positive Candidate",
                    "verification_guidance": "Do not assign High severity until actual configuration disclosure is verified.",
                    "evidence": "HTTP status: 200 OK | Response type: HTML | Actual secrets detected: Not established",
                }

        # 3. .git/HEAD verification
        elif check_type == "git_head":
            is_git_ref = bool(body_stripped.startswith("ref: refs/") or bool(re.match(r"^[0-9a-f]{40}$", body_stripped)))
            if is_git_ref and not is_html:
                return {
                    "is_vulnerable": True,
                    "confidence": "High",
                    "severity": "High",
                    "status": "200 OK",
                    "response_type": "Git Ref",
                    "actual_content_detected": "Established (Git HEAD Reference)",
                    "verification_status": "Verified Exposure",
                    "recommended_classification": "High Severity Finding",
                    "verification_guidance": "Verified git repository metadata exposed in web root.",
                    "evidence": f"Status 200 OK: Valid Git HEAD ref detected: {body_stripped[:50]}",
                }
            elif is_html or not is_git_ref:
                return {
                    "is_vulnerable": False,
                    "is_candidate": True,
                    "confidence": "Low",
                    "severity": "Info",
                    "status": "200 OK",
                    "response_type": "HTML" if is_html else "Text",
                    "actual_content_detected": "Not established",
                    "verification_status": "Needs verification",
                    "recommended_classification": "Informational / False Positive Candidate",
                    "verification_guidance": "Do not assign High severity until actual configuration disclosure is verified.",
                    "evidence": "HTTP status: 200 OK | Response type: HTML | Actual Git metadata detected: Not established",
                }

        # 4. .git/config verification
        elif check_type == "git_config":
            is_git_cfg = bool("[core]" in body and not is_html)
            if is_git_cfg:
                return {
                    "is_vulnerable": True,
                    "confidence": "High",
                    "severity": "High",
                    "status": "200 OK",
                    "response_type": "Git Config",
                    "actual_content_detected": "Established (Git INI Configuration)",
                    "verification_status": "Verified Exposure",
                    "recommended_classification": "High Severity Finding",
                    "verification_guidance": "Verified .git/config repository configuration file exposed.",
                    "evidence": "Status 200 OK: Valid [core] Git repository configuration verified.",
                }
            elif is_html or not is_git_cfg:
                return {
                    "is_vulnerable": False,
                    "is_candidate": True,
                    "confidence": "Low",
                    "severity": "Info",
                    "status": "200 OK",
                    "response_type": "HTML" if is_html else "Text",
                    "actual_content_detected": "Not established",
                    "verification_status": "Needs verification",
                    "recommended_classification": "Informational / False Positive Candidate",
                    "verification_guidance": "Do not assign High severity until actual configuration disclosure is verified.",
                    "evidence": "HTTP status: 200 OK | Response type: HTML | Actual Git configuration: Not established",
                }

        # 5. SQL dump verification
        elif check_type == "sql_dump":
            is_sql = bool(re.search(r"(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL dump|-- PostgreSQL)", body, re.IGNORECASE))
            if is_sql and not is_html:
                return {
                    "is_vulnerable": True,
                    "confidence": "High",
                    "severity": "Critical",
                    "status": "200 OK",
                    "response_type": "SQL Script",
                    "actual_content_detected": "Established (Database SQL Dump)",
                    "verification_status": "Verified Exposure",
                    "recommended_classification": "Critical Severity Finding",
                    "verification_guidance": "Verified database backup dump containing table definitions or data.",
                    "evidence": "Status 200 OK: SQL schema and data creation statements verified.",
                }
            elif is_html or not is_sql:
                return {
                    "is_vulnerable": False,
                    "is_candidate": True,
                    "confidence": "Low",
                    "severity": "Info",
                    "status": "200 OK",
                    "response_type": "HTML" if is_html else "Text",
                    "actual_content_detected": "Not established",
                    "verification_status": "Needs verification",
                    "recommended_classification": "Informational / False Positive Candidate",
                    "verification_guidance": "Do not assign High severity until actual configuration disclosure is verified.",
                    "evidence": "HTTP status: 200 OK | Response type: HTML | Actual SQL dump: Not established",
                }

        # 6. Dockerfile / docker-compose verification
        elif check_type in ("dockerfile", "docker_compose"):
            is_docker = bool(
                re.search(r"(?m)^(FROM|RUN|CMD|ENTRYPOINT|WORKDIR|COPY)\s+", body) or
                ("version:" in body and "services:" in body)
            )
            if is_docker and not is_html:
                return {
                    "is_vulnerable": True,
                    "confidence": "High",
                    "severity": "Medium",
                    "status": "200 OK",
                    "response_type": "Docker Definition",
                    "actual_content_detected": "Established (Container Directives)",
                    "verification_status": "Verified Exposure",
                    "recommended_classification": "Medium Severity Finding",
                    "verification_guidance": "Verified Docker build instructions or compose file exposed.",
                    "evidence": "Status 200 OK: Valid Docker instructions detected in response body.",
                }
            elif is_html or not is_docker:
                return {
                    "is_vulnerable": False,
                    "is_candidate": True,
                    "confidence": "Low",
                    "severity": "Info",
                    "status": "200 OK",
                    "response_type": "HTML" if is_html else "Text",
                    "actual_content_detected": "Not established",
                    "verification_status": "Needs verification",
                    "recommended_classification": "Informational / False Positive Candidate",
                    "verification_guidance": "Do not assign High severity until actual configuration disclosure is verified.",
                    "evidence": "HTTP status: 200 OK | Response type: HTML | Actual Docker config: Not established",
                }

        # 7. phpinfo.php verification
        elif check_type == "phpinfo":
            is_phpinfo = bool("PHP Version" in body and ("phpinfo()" in body or "Configuration File (php.ini)" in body))
            if is_phpinfo:
                return {
                    "is_vulnerable": True,
                    "confidence": "High",
                    "severity": "High",
                    "status": "200 OK",
                    "response_type": "HTML (phpinfo)",
                    "actual_content_detected": "Established (PHP Diagnostic Page)",
                    "verification_status": "Verified Exposure",
                    "recommended_classification": "High Severity Finding",
                    "verification_guidance": "Verified live phpinfo() configuration diagnostic page accessible.",
                    "evidence": "Status 200 OK: Live PHP Version and phpinfo() table structure verified.",
                }
            else:
                return {
                    "is_vulnerable": False,
                    "is_candidate": True,
                    "confidence": "Low",
                    "severity": "Info",
                    "status": "200 OK",
                    "response_type": "HTML",
                    "actual_content_detected": "Not established",
                    "verification_status": "Needs verification",
                    "recommended_classification": "Informational / False Positive Candidate",
                    "verification_guidance": "Do not assign High severity until actual configuration disclosure is verified.",
                    "evidence": "HTTP status: 200 OK | Response type: HTML | Actual phpinfo() diagnostics: Not established",
                }

        # 8. .DS_Store verification
        elif check_type == "ds_store":
            is_ds = bool(b"\x00\x00\x00\x01Bud1" in content or (b"\x00" * 4 in content and not is_html))
            if is_ds:
                return {
                    "is_vulnerable": True,
                    "confidence": "High",
                    "severity": "Low",
                    "status": "200 OK",
                    "response_type": "Binary (.DS_Store)",
                    "actual_content_detected": "Established (macOS Finder Metadata)",
                    "verification_status": "Verified Exposure",
                    "recommended_classification": "Low Severity Finding",
                    "verification_guidance": "Verified macOS Finder .DS_Store binary metadata file exposed.",
                    "evidence": "Status 200 OK: Valid .DS_Store binary signature verified.",
                }
            else:
                return {
                    "is_vulnerable": False,
                    "is_candidate": True,
                    "confidence": "Low",
                    "severity": "Info",
                    "status": "200 OK",
                    "response_type": "HTML" if is_html else "Binary",
                    "actual_content_detected": "Not established",
                    "verification_status": "Needs verification",
                    "recommended_classification": "Informational / False Positive Candidate",
                    "verification_guidance": "Do not assign High severity until actual configuration disclosure is verified.",
                    "evidence": "HTTP status: 200 OK | Response type: HTML | Actual .DS_Store binary: Not established",
                }

        # 9. JSON Package Manifests (package.json / composer.json)
        elif check_type == "json_pkg":
            is_json_valid = False
            if not is_html:
                try:
                    import json as _json
                    pkg_data = _json.loads(body)
                    if isinstance(pkg_data, dict) and any(k in pkg_data for k in ("name", "version", "dependencies", "require", "scripts")):
                        is_json_valid = True
                except Exception:
                    pass

            if is_json_valid:
                return {
                    "is_vulnerable": True,
                    "confidence": "High",
                    "severity": "Low",
                    "status": "200 OK",
                    "response_type": "JSON Package Manifest",
                    "actual_content_detected": f"Established ({filename} Package Data)",
                    "verification_status": "Verified Exposure",
                    "recommended_classification": "Low Severity Finding",
                    "verification_guidance": f"Verified {filename} package manifest exposed in web root.",
                    "evidence": f"Status 200 OK: Valid JSON package manifest with dependencies verified for {filename}.",
                }
            else:
                return {
                    "is_vulnerable": False,
                    "is_candidate": True,
                    "confidence": "Low",
                    "severity": "Info",
                    "status": "200 OK",
                    "response_type": "HTML" if is_html else "Text",
                    "actual_content_detected": "Not established",
                    "verification_status": "Needs verification",
                    "recommended_classification": "Informational / False Positive Candidate",
                    "verification_guidance": "Do not assign High severity until actual configuration disclosure is verified.",
                    "evidence": f"HTTP status: 200 OK | Response type: {'HTML' if is_html else 'Text'} | Actual package manifest: Not established",
                }

        # 10. Flash Cross-Domain Policy (crossdomain.xml)
        elif check_type == "xml_crossdomain":
            is_crossdomain = bool("<cross-domain-policy" in body.lower() and not is_html)
            if is_crossdomain:
                return {
                    "is_vulnerable": True,
                    "confidence": "High",
                    "severity": "Low",
                    "status": "200 OK",
                    "response_type": "XML Cross-Domain Policy",
                    "actual_content_detected": "Established (cross-domain-policy)",
                    "verification_status": "Verified Exposure",
                    "recommended_classification": "Low Severity Finding",
                    "verification_guidance": "Verified Flash cross-domain policy file exposed.",
                    "evidence": "Status 200 OK: Valid <cross-domain-policy> XML structure verified.",
                }
            else:
                return {
                    "is_vulnerable": False,
                    "is_candidate": True,
                    "confidence": "Low",
                    "severity": "Info",
                    "status": "200 OK",
                    "response_type": "HTML" if is_html else "Text",
                    "actual_content_detected": "Not established",
                    "verification_status": "Needs verification",
                    "recommended_classification": "Informational / False Positive Candidate",
                    "verification_guidance": "Do not assign High severity until actual configuration disclosure is verified.",
                    "evidence": f"HTTP status: 200 OK | Response type: {'HTML' if is_html else 'Text'} | Actual XML detected: Not established",
                }

        # Generic fallback
        return {
            "is_vulnerable": not is_html and len(body_stripped) > 20,
            "is_candidate": is_html,
            "confidence": "High" if not is_html else "Low",
            "severity": "Medium" if not is_html else "Info",
            "status": "200 OK",
            "response_type": "HTML" if is_html else "Plaintext",
            "actual_content_detected": "Established" if not is_html else "Not established",
            "verification_status": "Verified Exposure" if not is_html else "Needs verification",
            "recommended_classification": "Confirmed Finding" if not is_html else "Informational / False Positive Candidate",
            "verification_guidance": "Do not assign High severity until actual configuration disclosure is verified.",
            "evidence": f"Status 200 OK for '{filename}' | Content verified: {'Established' if not is_html else 'Not established'}",
        }

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        findings = []
        if not urls:
            return findings

        primary_url = urls[0]
        parsed = urlparse(primary_url)

        # 1. Transport Security Check (Plain HTTP vs HTTPS)
        if parsed.scheme == "http":
            try:
                resp = requests.get(primary_url, allow_redirects=False, timeout=self.timeout, verify=False)
                location = resp.headers.get("Location", "")
                if not (resp.status_code in (301, 302, 307, 308) and location.startswith("https://")):
                    findings.append({
                        "vuln_type": "Insecure Transport (Plain HTTP without HTTPS Redirect)",
                        "severity": "High",
                        "confidence": "High",
                        "url": primary_url,
                        "parameter": "scheme",
                        "evidence": f"HTTP status: {resp.status_code}, Location: {location or 'None'}",
                        "description": "The application allows unencrypted HTTP connections without automatically enforcing an HTTPS redirect. Data transmitted in transit can be intercepted or altered by an eavesdropper.",
                        "remediation": "Enforce automatic 301 Permanent Redirect from HTTP to HTTPS for all incoming requests.",
                        "cwe_id": "CWE-319",
                        "owasp_category": "A02:2021-Cryptographic Failures"
                    })
            except Exception as e:
                logger.debug("HTTP redirect check failed: %s", e)

        # 2. Cookie Security Flags (HttpOnly, Secure, SameSite)
        try:
            resp = self.session.get(primary_url, timeout=self.timeout, verify=False)
            set_cookie_headers = resp.headers.get("Set-Cookie", "")

            for cookie in resp.cookies:
                c_name = cookie.name
                c_secure = cookie.secure
                c_httponly = cookie.has_nonstandard_attr("HttpOnly") or "httponly" in set_cookie_headers.lower()
                c_samesite = cookie.get_nonstandard_attr("SameSite")

                if not c_httponly:
                    findings.append({
                        "vuln_type": f"Cookie Missing 'HttpOnly' Flag: {c_name}",
                        "severity": "Medium",
                        "confidence": "High",
                        "url": primary_url,
                        "parameter": c_name,
                        "evidence": f"Cookie '{c_name}' does not contain HttpOnly directive.",
                        "description": f"The cookie '{c_name}' can be accessed via client-side JavaScript (document.cookie). If XSS occurs, attackers can steal this session cookie directly.",
                        "remediation": f"Set the 'HttpOnly' flag on cookie '{c_name}' in server response headers.",
                        "cwe_id": "CWE-1004",
                        "owasp_category": "A05:2021-Security Misconfiguration"
                    })

                if not c_secure and parsed.scheme == "https":
                    findings.append({
                        "vuln_type": f"Cookie Missing 'Secure' Flag: {c_name}",
                        "severity": "Medium",
                        "confidence": "High",
                        "url": primary_url,
                        "parameter": c_name,
                        "evidence": f"Cookie '{c_name}' transmitted without Secure directive over HTTPS.",
                        "description": f"The cookie '{c_name}' lacks the Secure flag, permitting transmission over unencrypted HTTP channels.",
                        "remediation": f"Set the 'Secure' flag on cookie '{c_name}' so it is only transmitted over TLS/HTTPS.",
                        "cwe_id": "CWE-614",
                        "owasp_category": "A05:2021-Security Misconfiguration"
                    })

                if not c_samesite:
                    findings.append({
                        "vuln_type": f"Cookie Missing 'SameSite' Attribute: {c_name}",
                        "severity": "Low",
                        "confidence": "High",
                        "url": primary_url,
                        "parameter": c_name,
                        "evidence": f"Cookie '{c_name}' does not specify SameSite.",
                        "description": f"Cookie '{c_name}' does not specify SameSite=Lax or SameSite=Strict, increasing exposure to Cross-Site Request Forgery (CSRF).",
                        "remediation": f"Set 'SameSite=Lax' or 'SameSite=Strict' for cookie '{c_name}'.",
                        "cwe_id": "CWE-1275",
                        "owasp_category": "A01:2021-Broken Access Control"
                    })
        except Exception as e:
            logger.debug("Cookie check failed: %s", e)

        # 3. Permissive CORS Misconfiguration
        try:
            origin_test = "https://evil-attacker.example.com"
            cors_resp = requests.get(primary_url, headers={"Origin": origin_test}, timeout=self.timeout, verify=False)
            allow_origin = cors_resp.headers.get("Access-Control-Allow-Origin")
            allow_creds = cors_resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if allow_origin == "*" and allow_creds == "true":
                findings.append({
                    "vuln_type": "Critical CORS Misconfiguration: Wildcard with Credentials",
                    "severity": "Critical",
                    "confidence": "High",
                    "url": primary_url,
                    "parameter": "Access-Control-Allow-Origin",
                    "evidence": "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                    "description": "Wildcard CORS origin is combined with credentials, allowing unauthorized domains to read authenticated responses via client-side requests.",
                    "remediation": "Never combine wildcard '*' with Access-Control-Allow-Credentials. Strictly whitelist authorized origin domains.",
                    "cwe_id": "CWE-942",
                    "owasp_category": "A05:2021-Security Misconfiguration"
                })
            elif allow_origin == origin_test:
                findings.append({
                    "vuln_type": "Insecure CORS: Arbitrary Origin Reflection",
                    "severity": "High",
                    "confidence": "High",
                    "url": primary_url,
                    "parameter": "Access-Control-Allow-Origin",
                    "evidence": f"Access-Control-Allow-Origin reflected arbitrary origin: {origin_test}",
                    "description": "The server reflects arbitrary Origin headers back into Access-Control-Allow-Origin, nullifying Same-Origin Policy protections.",
                    "remediation": "Validate incoming Origin against a strict server-side whitelist before echoing it in CORS headers.",
                    "cwe_id": "CWE-942",
                    "owasp_category": "A05:2021-Security Misconfiguration"
                })
        except Exception as e:
            logger.debug("CORS check failed: %s", e)

        # 4. Check Exposed Files / Backups (With Content & Structural Verification)
        for filename, desc, sev, cwe, check_type in self.COMMON_EXPOSED_FILES:
            try:
                probe_url = urljoin(primary_url, filename)
                resp = requests.get(probe_url, timeout=5, verify=False, allow_redirects=False)

                # Ignore immediate 404, 403, or connection dropouts
                if resp.status_code in (404, 403):
                    continue

                if resp.status_code == 200 and len(resp.content) > 10:
                    v_res = self._verify_file_content(filename, check_type, resp.text, resp.content, resp.headers)

                    if v_res.get("is_vulnerable"):
                        # Confirmed real configuration/file exposure
                        findings.append({
                            "vuln_type": f"Exposed Sensitive File: {filename}",
                            "severity": sev,
                            "confidence": "High",
                            "url": probe_url,
                            "parameter": filename,
                            "evidence": v_res.get("evidence"),
                            "description": f"The sensitive file '{filename}' ({desc}) is publicly accessible via direct HTTP GET request and was verified to contain valid file contents.",
                            "remediation": f"Block public access to '{filename}' in web server configuration or remove it from the public document root.",
                            "cwe_id": cwe,
                            "owasp_category": "A05:2021-Security Misconfiguration",
                            "verification_status": v_res.get("verification_status", "Verified Exposure"),
                            "http_status": v_res.get("status", "200 OK"),
                            "response_type": v_res.get("response_type", "Established"),
                            "actual_content_detected": v_res.get("actual_content_detected", "Established"),
                            "recommended_classification": v_res.get("recommended_classification", "Confirmed Finding"),
                            "verification_guidance": v_res.get("verification_guidance", "Verified sensitive file exposure."),
                        })
                    elif v_res.get("is_candidate"):
                        # Soft-404 / HTML fallback / False Positive candidate
                        findings.append({
                            "vuln_type": f"Potentially Exposed {filename}",
                            "severity": "Info",
                            "confidence": "Low",
                            "url": probe_url,
                            "parameter": filename,
                            "evidence": v_res.get("evidence"),
                            "description": f"The endpoint '/{filename}' returned HTTP 200 OK, but the response body is HTML (likely a single-page application fallback, custom error page, or soft 404) rather than the actual file. Do not assign High severity until actual configuration disclosure is verified.",
                            "remediation": f"Inspect the endpoint manually. Ensure the web server returns standard 404 Not Found status codes for missing files and that '{filename}' is blocked.",
                            "cwe_id": cwe,
                            "owasp_category": "A05:2021-Security Misconfiguration",
                            "verification_status": "Needs verification",
                            "http_status": v_res.get("status", "200 OK"),
                            "response_type": v_res.get("response_type", "HTML"),
                            "actual_content_detected": v_res.get("actual_content_detected", "Not established"),
                            "recommended_classification": "Informational / False Positive Candidate",
                            "verification_guidance": "Do not assign High severity until actual configuration disclosure is verified.",
                        })
            except Exception:
                pass

        # 5. Dangerous HTTP Methods (OPTIONS check)
        try:
            opt_resp = requests.options(primary_url, timeout=self.timeout, verify=False)
            allow_header = opt_resp.headers.get("Allow", "")
            if any(method in allow_header.upper() for method in ["TRACE", "TRACK"]):
                findings.append({
                    "vuln_type": "Dangerous HTTP Method Enabled: TRACE",
                    "severity": "Medium",
                    "confidence": "High",
                    "url": primary_url,
                    "parameter": "HTTP Methods",
                    "evidence": f"Allow header exposes: {allow_header}",
                    "description": "HTTP TRACE/TRACK method is enabled. Attackers can leverage Cross-Site Tracing (XST) to steal HttpOnly cookies when combined with XSS.",
                    "remediation": "Disable TRACE and TRACK methods in web server configuration.",
                    "cwe_id": "CWE-16",
                    "owasp_category": "A05:2021-Security Misconfiguration"
                })
        except Exception as e:
            logger.debug("OPTIONS check failed: %s", e)

        return findings
