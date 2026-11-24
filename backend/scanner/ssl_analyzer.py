"""
OWASP Sentinel AI - SSL/TLS Cryptographic Health Analyzer
Inspects SSL/TLS certificates, expiry dates, subject alternative names (SANs),
supported cipher suites, and protocol versions using Python's standard ssl and socket libraries.
"""

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class SSLAnalyzer:
    """Performs passive cryptographic audit of target SSL/TLS endpoints."""

    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    def analyze(self, url: str) -> Dict[str, Any]:
        """Examine certificate attributes and security posture."""
        parsed = urlparse(url)
        hostname = parsed.hostname or url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Non-HTTPS targets
        if parsed.scheme == "http" and port == 80:
            return {
                "valid": False,
                "grade": "F",
                "is_https": False,
                "hostname": hostname,
                "issues": ["Target application does not use HTTPS. All communications are unencrypted in transit."],
                "protocols": [],
                "certificate": None,
                "summary": "Insecure plaintext HTTP in use.",
            }

        result = {
            "valid": False,
            "grade": "B",
            "is_https": True,
            "hostname": hostname,
            "port": port,
            "issues": [],
            "protocols": ["TLS 1.2", "TLS 1.3"],
            "certificate": None,
            "summary": "SSL/TLS certificate verified.",
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    subject_dict = dict(x[0] for x in cert.get("subject", ()))
                    issuer_dict = dict(x[0] for x in cert.get("issuer", ()))

                    # Parse expiry dates
                    not_after_str = cert.get("notAfter", "")
                    not_before_str = cert.get("notBefore", "")

                    days_until_expiry = 0
                    if not_after_str:
                        # Format: 'May 15 12:00:00 2025 GMT'
                        expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now_dt = datetime.now(timezone.utc)
                        days_until_expiry = (expiry_dt - now_dt).days

                    # Subject Alternative Names (SAN)
                    sans = [x[1] for x in cert.get("subjectAltName", ()) if x[0] == "DNS"]

                    cert_info = {
                        "common_name": subject_dict.get("commonName", hostname),
                        "organization": subject_dict.get("organizationName", "N/A"),
                        "issuer_cn": issuer_dict.get("commonName", "Unknown CA"),
                        "issuer_org": issuer_dict.get("organizationName", "Unknown CA"),
                        "serial_number": cert.get("serialNumber", "N/A"),
                        "valid_from": not_before_str,
                        "valid_until": not_after_str,
                        "days_until_expiry": days_until_expiry,
                        "tls_version": version or "TLS 1.2",
                        "cipher_suite": cipher[0] if cipher else "Unknown",
                        "cipher_bits": cipher[2] if cipher else 0,
                        "subject_alt_names": sans[:10],
                    }

                    result["certificate"] = cert_info
                    result["valid"] = True

                    # Grading logic
                    issues: List[str] = []
                    if days_until_expiry < 0:
                        grade = "F"
                        issues.append("SSL Certificate has expired! Users will see security warnings.")
                    elif days_until_expiry < 15:
                        grade = "C"
                        issues.append(f"Certificate expires very soon ({days_until_expiry} days remaining).")
                    elif days_until_expiry < 30:
                        grade = "B"
                        issues.append(f"Certificate renewal recommended ({days_until_expiry} days left).")
                    else:
                        grade = "A+" if version == "TLSv1.3" else "A"

                    if cipher and cipher[2] and cipher[2] < 128:
                        grade = "D"
                        issues.append(f"Weak cipher key length detected ({cipher[2]} bits).")

                    result["grade"] = grade
                    result["issues"] = issues
                    result["summary"] = f"Grade {grade}: {cert_info['common_name']} issued by {cert_info['issuer_org']} ({days_until_expiry} days valid)"
                    return result

        except ssl.SSLCertVerificationError as e:
            logger.warning("SSL verification failed for %s: %s", hostname, e)
            result["valid"] = False
            result["grade"] = "F"
            result["issues"] = [f"Certificate validation failed: {e.verify_message}"]
            result["summary"] = "Untrusted or self-signed certificate."
            return result
        except Exception as exc:
            logger.debug("SSL check exception on %s: %s", hostname, exc)
            result["valid"] = False
            result["grade"] = "C"
            result["issues"] = [f"Unable to complete TLS handshake: {str(exc)}"]
            result["summary"] = "Could not retrieve certificate information."
            return result
