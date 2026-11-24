"""
OWASP Sentinel AI - DNS Reconnaissance & Asset Discovery Module
Resolves IP mappings, canonical names, and checks common host configurations
using Python standard socket libraries for fast, non-intrusive discovery.
"""

import logging
import socket
from typing import Dict, Any, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

COMMON_SUBDOMAINS = [
    "www", "api", "admin", "dev", "test", "staging",
    "mail", "portal", "cdn", "app", "auth", "login"
]


class DNSRecon:
    """Discovers DNS assets, IP endpoints, and surface information for target hosts."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def recon(self, url: str) -> Dict[str, Any]:
        """Perform non-intrusive DNS discovery."""
        parsed = urlparse(url)
        hostname = parsed.hostname or url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        result = {
            "hostname": hostname,
            "ip_addresses": [],
            "cname": None,
            "subdomains": [],
            "summary": "",
            "issues": [],
        }

        if not hostname or hostname in ("localhost", "127.0.0.1"):
            result["ip_addresses"] = ["127.0.0.1"]
            result["summary"] = "Local loopback address (development environment)."
            return result

        # 1. Resolve Primary Host IP addresses
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = sorted(list(set(info[4][0] for info in addr_info)))
            result["ip_addresses"] = ips
        except Exception as exc:
            logger.debug("DNS resolution error for %s: %s", hostname, exc)
            result["issues"].append(f"Primary hostname resolution failed: {exc}")

        # 2. Check for Canonical Name (CNAME)
        try:
            fqdn = socket.getfqdn(hostname)
            if fqdn and fqdn != hostname:
                result["cname"] = fqdn
        except Exception:
            pass

        # 3. Check lightweight common subdomains if target is a root or 2nd-level domain
        domain_parts = hostname.split(".")
        if len(domain_parts) >= 2:
            base_domain = ".".join(domain_parts[-2:])
            discovered_subs: List[Dict[str, str]] = []

            for sub in COMMON_SUBDOMAINS:
                test_host = f"{sub}.{base_domain}"
                if test_host == hostname:
                    continue
                try:
                    ip = socket.gethostbyname(test_host)
                    discovered_subs.append({
                        "subdomain": test_host,
                        "ip": ip,
                        "status": "Active"
                    })
                    if len(discovered_subs) >= 6:
                        break
                except (socket.gaierror, socket.timeout):
                    pass

            result["subdomains"] = discovered_subs

        # Summary creation
        ip_count = len(result["ip_addresses"])
        sub_count = len(result["subdomains"])
        result["summary"] = f"Resolved {ip_count} IP(s) with {sub_count} active subdomain endpoint(s) discovered."

        return result
