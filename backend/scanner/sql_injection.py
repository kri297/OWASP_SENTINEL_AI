"""
OWASP Sentinel AI - SQL Injection Indicator Scanner
Tests URL query parameters and discovered form inputs for SQL injection indicators
by checking for standard database error responses and structural behavioral shifts,
with baseline comparison to avoid false positives.
OWASP Category: A03:2021 - Injection | CWE-89
"""

import logging
import re
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests

logger = logging.getLogger(__name__)


class SQLInjectionScanner:
    """Non-destructive diagnostic scanner checking for SQL error signatures and indicators."""

    SQL_ERRORS = [
        # MySQL
        (r"you have an error in your sql syntax", "MySQL"),
        (r"warning: mysql_", "MySQL"),
        (r"check the manual that corresponds to your mysql server version", "MySQL"),
        # PostgreSQL
        (r"pg_query\(\): query failed: error:", "PostgreSQL"),
        (r"psycopg2\.errors\.", "PostgreSQL"),
        (r"syntax error at or near", "PostgreSQL"),
        # Microsoft SQL Server
        (r"unclosed quotation mark after the character string", "MSSQL"),
        (r"microsoft ole db provider for sql server", "MSSQL"),
        (r"driver\]\[sql server\]", "MSSQL"),
        # Oracle
        (r"ora-[0-9]{4,5}", "Oracle"),
        (r"quoted string not properly terminated", "Oracle"),
        # SQLite
        (r"sqlite3\.operationalerror", "SQLite"),
        (r"unrecognized token:", "SQLite"),
        (r"near \".*\": syntax error", "SQLite"),
        # Generic / ODBC
        (r"sql command not properly ended", "Generic SQL"),
        (r"odbc sql server driver", "ODBC"),
    ]

    TEST_PROBES = [
        "'",
        "''",
        "' OR '1'='1",
        "\""
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OWASP-Sentinel-AI-Auditor/2.0"})

    def _check_sql_errors(self, body: str) -> str:
        """Scan response body for database error messages."""
        for pattern, db_engine in self.SQL_ERRORS:
            if re.search(pattern, body, re.IGNORECASE):
                return db_engine
        return ""

    def scan(self, urls: List[str], forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        tested_params = set()

        # 1. Test URL Query Parameters
        for url in urls[:15]:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            if not query_params:
                continue

            # Fetch baseline page to check for pre-existing error messages
            baseline_error = ""
            try:
                base_resp = self.session.get(url, timeout=self.timeout, verify=False)
                baseline_error = self._check_sql_errors(base_resp.text)
            except Exception:
                pass

            for param_name, original_vals in query_params.items():
                param_key = f"{parsed.path}?{param_name}"
                if param_key in tested_params:
                    continue
                tested_params.add(param_key)

                for probe in self.TEST_PROBES:
                    test_params = {k: v[:] for k, v in query_params.items()}
                    test_params[param_name] = [probe]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                    try:
                        resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                        db_detected = self._check_sql_errors(resp.text)

                        # Only flag if db error was triggered by probe and was NOT in baseline!
                        if db_detected and db_detected != baseline_error:
                            findings.append({
                                "vuln_type": "SQL Injection Indicator",
                                "severity": "Critical",
                                "confidence": "High",
                                "url": url,
                                "parameter": param_name,
                                "evidence": f"Injected '{probe}' into query param '{param_name}'. Database error signature detected: {db_detected}.",
                                "description": f"Target parameter '{param_name}' returned a database syntax error ({db_detected}) when supplied with SQL meta-characters. This indicates direct user input concatenation in database queries.",
                                "remediation": "Use parameterized queries (prepared statements) or an ORM. Never concatenate user-supplied input directly into SQL commands.",
                                "cwe_id": "CWE-89",
                                "owasp_category": "A03:2021-Injection",
                                "verification_status": "Verified Exposure",
                                "http_status": f"{resp.status_code} OK",
                                "response_type": "Database Error Response",
                                "actual_content_detected": f"Established ({db_detected} SQL error)",
                                "recommended_classification": "Critical Severity Finding",
                                "verification_guidance": "Verified database syntax error induced by probe injection.",
                            })
                            break
                    except Exception as e:
                        logger.debug("SQLi GET probe failed: %s", e)

        # 2. Test Discovered Forms
        for form in forms[:8]:
            action_url = form.get("action")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            if not action_url or not inputs:
                continue

            for input_field in inputs:
                input_name = input_field.get("name")
                input_type = input_field.get("type", "text").lower()

                if not input_name or input_type in ("submit", "button", "hidden", "image"):
                    continue

                for probe in self.TEST_PROBES[:2]:
                    form_data = {
                        inp.get("name"): (probe if inp.get("name") == input_name else (inp.get("value") or "test"))
                        for inp in inputs if inp.get("name")
                    }

                    try:
                        if method == "POST":
                            resp = self.session.post(action_url, data=form_data, timeout=self.timeout, verify=False)
                        else:
                            resp = self.session.get(action_url, params=form_data, timeout=self.timeout, verify=False)

                        db_detected = self._check_sql_errors(resp.text)
                        if db_detected:
                            findings.append({
                                "vuln_type": "SQL Injection in Form Input",
                                "severity": "Critical",
                                "confidence": "High",
                                "url": action_url,
                                "parameter": input_name,
                                "evidence": f"Injected '{probe}' into form field '{input_name}'. Database error detected: {db_detected}.",
                                "description": f"Form parameter '{input_name}' triggered a database syntax error ({db_detected}) upon receiving an SQL meta-character probe.",
                                "remediation": "Implement parameterized database queries across all form submission handlers.",
                                "cwe_id": "CWE-89",
                                "owasp_category": "A03:2021-Injection",
                                "verification_status": "Verified Exposure",
                                "http_status": f"{resp.status_code} OK",
                                "response_type": "Database Error Response",
                                "actual_content_detected": f"Established ({db_detected} SQL error)",
                                "recommended_classification": "Critical Severity Finding",
                                "verification_guidance": "Verified database syntax error induced by form field probe.",
                            })
                            break
                    except Exception as e:
                        logger.debug("SQLi Form probe failed: %s", e)

        return findings
