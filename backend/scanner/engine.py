"""
OWASP Sentinel AI - Unified Scan Engine
Coordinates discovery crawling and runs active/passive vulnerability modules
based on selected scan profiles and configuration options.
"""

import logging
from typing import List, Dict, Any, Optional, Callable

from scanner.crawler import SimpleCrawler
from scanner.header_scanner import SecurityHeaderScanner
from scanner.sql_injection import SQLInjectionScanner
from scanner.xss_scanner import XSSScanner
from scanner.sensitive_info import SensitiveInfoScanner
from scanner.config_scanner import InsecureConfigScanner
from scanner.csrf_scanner import CSRFScanner
from scanner.tech_fingerprint import TechFingerprinter
from scanner.ssl_analyzer import SSLAnalyzer
from scanner.dns_recon import DNSRecon

logger = logging.getLogger(__name__)


class ScanEngine:
    """Orchestrates crawling, security scanning, and reconnaissance against a target."""

    def __init__(
        self,
        target_url: str,
        scan_type: str = "full",
        timeout: int = 30,
        max_urls: int = 50,
        checks: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, int, str], None]] = None,
    ):
        self.target_url = target_url.strip()
        self.scan_type = scan_type.lower()
        self.timeout = timeout
        self.max_urls = max_urls if self.scan_type == "full" else min(max_urls, 10)
        self.max_depth = 2 if self.scan_type == "full" else 1
        self.progress_callback = progress_callback

        # Enabled check modules (if not specified, default to all)
        all_checks = {
            "sql_injection",
            "xss",
            "security_headers",
            "sensitive_info",
            "insecure_config",
            "csrf",
            "tech_fingerprint",
            "ssl_analysis",
            "dns_recon",
        }
        self.enabled_checks = set(checks) if checks else all_checks

        # Reconnaissance results storage
        self.tech_data: Dict[str, Any] = {}
        self.ssl_data: Dict[str, Any] = {}
        self.dns_data: Dict[str, Any] = {}

    def _notify(self, stage: str, pct: int, msg: str):
        """Emit step progress if callback is provided."""
        if self.progress_callback:
            try:
                self.progress_callback(stage, pct, msg)
            except Exception as e:
                logger.debug("Progress callback error: %s", e)

    def run(self) -> List[Dict[str, Any]]:
        """
        Execute the scanning workflow and return list of discovered vulnerabilities.
        """
        logger.info(
            "Initializing scan on '%s' (type: %s, enabled checks: %s)",
            self.target_url,
            self.scan_type,
            len(self.enabled_checks),
        )

        all_findings: List[Dict[str, Any]] = []

        # Step 1: Web Crawling & Discovery
        self._notify("crawling", 10, f"Crawling endpoint: {self.target_url}")
        try:
            logger.info("Starting crawler on target: %s", self.target_url)
            crawler = SimpleCrawler(
                target_url=self.target_url,
                max_pages=self.max_urls,
                max_depth=self.max_depth,
                timeout=min(self.timeout, 15),
            )
            crawl_data = crawler.crawl()
            discovered_urls = crawl_data.get("urls", [self.target_url])
            discovered_forms = crawl_data.get("forms", [])
            logger.info("Crawl finished: Discovered %d URLs and %d forms", len(discovered_urls), len(discovered_forms))
        except Exception as exc:
            logger.error("Crawl error on %s: %s", self.target_url, exc)
            discovered_urls = [self.target_url]
            discovered_forms = []

        # Step 2: HTTP Security Headers
        if "security_headers" in self.enabled_checks:
            self._notify("headers", 25, "Auditing security headers & policy configurations...")
            try:
                logger.info("Running Security Headers check...")
                header_scanner = SecurityHeaderScanner(timeout=min(self.timeout, 10))
                header_findings = header_scanner.scan(discovered_urls)
                all_findings.extend(header_findings)
                logger.info("Security Headers check completed (%d findings)", len(header_findings))
            except Exception as exc:
                logger.error("Header check failed: %s", exc)

        # Step 3: Insecure Configurations & Transports
        if "insecure_config" in self.enabled_checks:
            self._notify("config", 35, "Checking HTTPS, cookie flags & transport encryption...")
            try:
                logger.info("Running Insecure Configuration check...")
                config_scanner = InsecureConfigScanner(timeout=min(self.timeout, 10))
                config_findings = config_scanner.scan(discovered_urls)
                all_findings.extend(config_findings)
                logger.info("Insecure Configuration check completed (%d findings)", len(config_findings))
            except Exception as exc:
                logger.error("Config check failed: %s", exc)

        # Step 4: Sensitive Information Exposure
        if "sensitive_info" in self.enabled_checks:
            self._notify("sensitive_info", 45, "Inspecting exposed tokens, debug traces & robots.txt...")
            try:
                logger.info("Running Sensitive Info Disclosure check...")
                info_scanner = SensitiveInfoScanner(timeout=min(self.timeout, 10))
                info_findings = info_scanner.scan(discovered_urls)
                all_findings.extend(info_findings)
                logger.info("Sensitive Info check completed (%d findings)", len(info_findings))
            except Exception as exc:
                logger.error("Sensitive info check failed: %s", exc)

        # Step 5: SQL Injection Indicators
        if "sql_injection" in self.enabled_checks:
            self._notify("sql_injection", 55, "Testing parameters for SQL injection vulnerabilities...")
            try:
                logger.info("Running SQL Injection indicator check...")
                sqli_scanner = SQLInjectionScanner(timeout=min(self.timeout, 15))
                sqli_findings = sqli_scanner.scan(discovered_urls, discovered_forms)
                all_findings.extend(sqli_findings)
                logger.info("SQL Injection check completed (%d findings)", len(sqli_findings))
            except Exception as exc:
                logger.error("SQLi check failed: %s", exc)

        # Step 6: Cross-Site Scripting (XSS) Indicators
        if "xss" in self.enabled_checks:
            self._notify("xss", 65, "Validating reflected inputs & script injection vectors...")
            try:
                logger.info("Running XSS reflection check...")
                xss_scanner = XSSScanner(timeout=min(self.timeout, 15))
                xss_findings = xss_scanner.scan(discovered_urls, discovered_forms)
                all_findings.extend(xss_findings)
                logger.info("XSS check completed (%d findings)", len(xss_findings))
            except Exception as exc:
                logger.error("XSS check failed: %s", exc)

        # Step 7: CSRF Form Protection Checks
        if "csrf" in self.enabled_checks:
            self._notify("csrf", 75, "Analyzing form anti-CSRF protections...")
            try:
                logger.info("Running CSRF form check...")
                csrf_scanner = CSRFScanner(timeout=min(self.timeout, 10))
                csrf_findings = csrf_scanner.scan(discovered_forms)
                all_findings.extend(csrf_findings)
                logger.info("CSRF check completed (%d findings)", len(csrf_findings))
            except Exception as exc:
                logger.error("CSRF check failed: %s", exc)

        # Step 8: Technology Fingerprinting
        if "tech_fingerprint" in self.enabled_checks:
            self._notify("fingerprint", 82, "Fingerprinting web server, frameworks & libraries...")
            try:
                logger.info("Running Technology Fingerprinting...")
                fingerprinter = TechFingerprinter(timeout=min(self.timeout, 10))
                self.tech_data = fingerprinter.fingerprint(discovered_urls)
            except Exception as exc:
                logger.error("Tech fingerprinting failed: %s", exc)

        # Step 9: SSL/TLS Certificate Analysis
        if "ssl_analysis" in self.enabled_checks:
            self._notify("ssl", 88, "Evaluating SSL/TLS certificate & cipher suites...")
            try:
                logger.info("Running SSL Analyzer...")
                ssl_analyzer = SSLAnalyzer(timeout=min(self.timeout, 8))
                self.ssl_data = ssl_analyzer.analyze(self.target_url)
            except Exception as exc:
                logger.error("SSL analysis failed: %s", exc)

        # Step 10: DNS Reconnaissance
        if "dns_recon" in self.enabled_checks:
            self._notify("dns", 94, "Performing DNS mapping & subdomain checks...")
            try:
                logger.info("Running DNS Recon...")
                dns_recon = DNSRecon(timeout=min(self.timeout, 5))
                self.dns_data = dns_recon.recon(self.target_url)
            except Exception as exc:
                logger.error("DNS recon failed: %s", exc)

        # De-duplicate findings based on (vuln_type, url, parameter)
        unique_findings = []
        seen_keys = set()
        for f in all_findings:
            key = (f.get("vuln_type"), f.get("url"), f.get("parameter"))
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)

        # Sort deterministically by severity tier, vuln_type, URL, and parameter
        severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        unique_findings.sort(
            key=lambda x: (
                severity_rank.get(x.get("severity", "Info"), 5),
                str(x.get("vuln_type", "")),
                str(x.get("url", "")),
                str(x.get("parameter", "")),
            )
        )

        self._notify("completed", 100, f"Scan finished: {len(unique_findings)} unique findings.")
        logger.info("ScanEngine completed with %d unique findings.", len(unique_findings))
        return unique_findings

    def scan(self) -> Dict[str, Any]:
        """Convenience method returning findings and scan summary dict."""
        findings = self.run()
        summary = {
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "total_vulnerabilities": len(findings),
            "critical_count": sum(1 for f in findings if f.get("severity") == "Critical"),
            "high_count": sum(1 for f in findings if f.get("severity") == "High"),
            "medium_count": sum(1 for f in findings if f.get("severity") == "Medium"),
            "low_count": sum(1 for f in findings if f.get("severity") == "Low"),
            "info_count": sum(1 for f in findings if f.get("severity") == "Info"),
        }
        return {
            "vulnerabilities": findings,
            "scan_summary": summary,
            "tech_data": self.tech_data,
            "ssl_data": self.ssl_data,
            "dns_data": self.dns_data,
        }
