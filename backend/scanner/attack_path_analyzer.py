"""
OWASP Sentinel AI - Attack-Path Analyzer
Correlates individual vulnerabilities using predefined heuristic risk rules
to model multi-stage exploitation scenarios and visualize attack chains.
"""

import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class AttackPathAnalyzer:
    """Discovers and constructs realistic exploitation chains from discovered vulnerabilities."""

    def __init__(self):
        pass

    def _matches_any(self, vulns: List[Dict[str, Any]], keywords: List[str]) -> List[Dict[str, Any]]:
        """Filter vulnerabilities matching any of the given keywords."""
        matched = []
        for v in vulns:
            v_type = v.get("vuln_type", "").lower()
            if any(k.lower() in v_type for k in keywords):
                matched.append(v)
        return matched

    def analyze(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze vulnerabilities and synthesize correlated attack paths.
        Returns:
            List of attack path dictionaries.
        """
        if not vulnerabilities:
            return []

        paths = []
        vuln_names = [v.get("vuln_type", "") for v in vulnerabilities]

        # Extract subsets
        xss_vulns = self._matches_any(vulnerabilities, ["xss", "cross-site scripting"])
        cookie_vulns = self._matches_any(vulnerabilities, ["httponly", "cookie", "samesite"])
        sqli_vulns = self._matches_any(vulnerabilities, ["sql injection", "sqli"])
        info_vulns = self._matches_any(vulnerabilities, ["secret", "debug", "robots.txt", "disclosure", "information disclosure", "internal ip"])
        header_vulns = self._matches_any(vulnerabilities, ["security header", "content-security-policy", "x-frame-options", "hsts"])
        csrf_vulns = self._matches_any(vulnerabilities, ["csrf", "cross-site request forgery"])
        cors_vulns = self._matches_any(vulnerabilities, ["cors"])
        http_vulns = self._matches_any(vulnerabilities, ["insecure transport", "plain http", "https"])

        # -------------------------------------------------------------
        # Path 1: Session Hijacking via XSS and Insecure Cookies
        # -------------------------------------------------------------
        if xss_vulns and any("httponly" in v.get("vuln_type", "").lower() for v in cookie_vulns):
            paths.append({
                "name": "Session Hijacking via Script Injection and Missing HttpOnly Flag",
                "description": "An attacker exploits reflected or stored Cross-Site Scripting (XSS). Because sensitive session cookies lack the 'HttpOnly' flag, client-side scripts can access document.cookie to exfiltrate the victim's session tokens, achieving total account takeover.",
                "risk_level": "Critical",
                "impact": "Full session takeover without needing user credentials.",
                "likelihood": "High",
                "vulnerabilities": ["Reflected Cross-Site Scripting (XSS)", "Cookie Missing 'HttpOnly' Flag"],
                "related_vulnerabilities": ["XSS", "Cookie Security"],
                "attack_steps": [
                    {
                        "step_number": 1,
                        "description": "Attacker delivers crafted XSS payload targeting the vulnerable input parameter.",
                        "vulnerability_type": "Reflected Cross-Site Scripting (XSS)",
                        "impact": "Malicious JavaScript executes in the victim's browser session."
                    },
                    {
                        "step_number": 2,
                        "description": "Executed script accesses document.cookie to read active session tokens.",
                        "vulnerability_type": "Cookie Missing 'HttpOnly' Flag",
                        "impact": "Bypasses browser cookie access barriers due to missing HttpOnly attribute."
                    },
                    {
                        "step_number": 3,
                        "description": "Session token is transmitted to attacker-controlled listener.",
                        "vulnerability_type": "Data Exfiltration",
                        "impact": "Attacker imports stolen session cookie and impersonates victim."
                    }
                ],
                "steps": [
                    {
                        "step_number": 1,
                        "description": "Attacker delivers crafted XSS payload targeting the vulnerable parameter.",
                        "vulnerability_type": "Reflected Cross-Site Scripting (XSS)",
                    },
                    {
                        "step_number": 2,
                        "description": "Script queries document.cookie because HttpOnly is absent.",
                        "vulnerability_type": "Cookie Missing 'HttpOnly' Flag",
                    },
                    {
                        "step_number": 3,
                        "description": "Session token is exfiltrated to attacker server, enabling account takeover.",
                        "vulnerability_type": "Account Takeover",
                    }
                ]
            })

        # -------------------------------------------------------------
        # Path 2: Targeted Database Breach via Info Disclosure + SQLi
        # -------------------------------------------------------------
        if sqli_vulns:
            has_debug = any("debug" in v.get("vuln_type", "").lower() or "stack" in v.get("vuln_type", "").lower() for v in info_vulns)
            paths.append({
                "name": "Database Exfiltration & Backend Compromise via SQL Injection",
                "description": "SQL injection indicators allow direct manipulation of backend queries. If debug traces or database error messages are also exposed, attackers can accurately reconstruct table schemas and exfiltrate entire databases.",
                "risk_level": "Critical",
                "impact": "Unauthorized reading, modification, or deletion of all backend database records.",
                "likelihood": "High" if has_debug else "Medium",
                "vulnerabilities": ["SQL Injection Indicator"] + (["Debug Trace Exposure"] if has_debug else []),
                "related_vulnerabilities": ["SQL Injection", "Information Disclosure"],
                "attack_steps": [
                    {
                        "step_number": 1,
                        "description": "Attacker probes inputs with SQL syntax characters, observing syntax errors.",
                        "vulnerability_type": "SQL Injection Indicator",
                        "impact": "Confirms presence of unescaped dynamic SQL concatenation."
                    },
                    {
                        "step_number": 2,
                        "description": "Verbose error responses or debug traces reveal database engine and schema details.",
                        "vulnerability_type": "Debug Trace Exposure" if has_debug else "SQL Error Reflection",
                        "impact": "Facilitates rapid mapping of database tables and columns."
                    },
                    {
                        "step_number": 3,
                        "description": "Attacker formulates union queries or data exfiltration requests to dump stored tables.",
                        "vulnerability_type": "Data Exfiltration",
                        "impact": "Breach of customer records, credentials, or confidential business data."
                    }
                ],
                "steps": [
                    {
                        "step_number": 1,
                        "description": "Attacker identifies vulnerable SQL parameter.",
                        "vulnerability_type": "SQL Injection Indicator",
                    },
                    {
                        "step_number": 2,
                        "description": "Database error details guide query construction.",
                        "vulnerability_type": "Schema Discovery",
                    },
                    {
                        "step_number": 3,
                        "description": "Backend database contents are exfiltrated.",
                        "vulnerability_type": "Data Compromise",
                    }
                ]
            })

        # -------------------------------------------------------------
        # Path 3: Client Manipulation via CSRF + Missing Headers
        # -------------------------------------------------------------
        if csrf_vulns:
            paths.append({
                "name": "Unauthorized Action Execution via Cross-Site Request Forgery",
                "description": "State-changing forms lack anti-CSRF protection tokens. When an authenticated user visits a malicious external site, hidden background requests submit forms on the target application in the user's authenticated context.",
                "risk_level": "High",
                "impact": "Unauthorized state changes such as password changes, email modifications, or financial transactions.",
                "likelihood": "Medium",
                "vulnerabilities": ["Missing Anti-CSRF Protection in Form"],
                "related_vulnerabilities": ["CSRF", "Access Control"],
                "attack_steps": [
                    {
                        "step_number": 1,
                        "description": "Attacker hosts an exploit page with an auto-submitting hidden form.",
                        "vulnerability_type": "Malicious Webpage",
                        "impact": "Prepares forged request targeting victim's active session."
                    },
                    {
                        "step_number": 2,
                        "description": "Victim visits exploit page while currently authenticated to target app.",
                        "vulnerability_type": "Social Engineering / Phishing",
                        "impact": "Browser automatically attaches valid session cookies."
                    },
                    {
                        "step_number": 3,
                        "description": "Target server processes request due to absence of anti-CSRF validation tokens.",
                        "vulnerability_type": "Missing Anti-CSRF Protection in Form",
                        "impact": "Unauthorized modification of victim account settings."
                    }
                ],
                "steps": [
                    {
                        "step_number": 1,
                        "description": "Attacker sets up an auto-submitting form targeting state-changing URL.",
                        "vulnerability_type": "Forged Request Preparation",
                    },
                    {
                        "step_number": 2,
                        "description": "Authenticated user is lured into loading malicious page.",
                        "vulnerability_type": "Ambient Authentication",
                    },
                    {
                        "step_number": 3,
                        "description": "Action succeeds because no anti-CSRF token was required.",
                        "vulnerability_type": "Missing Anti-CSRF Protection",
                    }
                ]
            })

        # -------------------------------------------------------------
        # Path 4: Eavesdropping & MitM via Insecure Transport
        # -------------------------------------------------------------
        if http_vulns or any("hsts" in v.get("vuln_type", "").lower() for v in header_vulns):
            paths.append({
                "name": "Traffic Eavesdropping & Credential Downgrade via Missing Transport Security",
                "description": "The application either allows unencrypted HTTP connections or fails to enforce HSTS. An attacker on the local network (e.g. public Wi-Fi) can intercept credentials or inject malicious content into insecure traffic.",
                "risk_level": "High",
                "impact": "Plaintext interception of sensitive credentials and session cookies.",
                "likelihood": "Medium",
                "vulnerabilities": ["Insecure Transport (Plain HTTP without HTTPS Redirect)", "Missing Security Header: Strict-Transport-Security"],
                "related_vulnerabilities": ["Transport Security", "HSTS"],
                "attack_steps": [
                    {
                        "step_number": 1,
                        "description": "Victim connects over an untrusted or public network.",
                        "vulnerability_type": "Network Positioning",
                        "impact": "Attacker performs ARP spoofing or DNS spoofing."
                    },
                    {
                        "step_number": 2,
                        "description": "Traffic is stripped of TLS protection due to missing HSTS or lack of HTTPS redirect.",
                        "vulnerability_type": "Insecure Transport / Missing HSTS",
                        "impact": "Browser initiates requests over plaintext HTTP."
                    },
                    {
                        "step_number": 3,
                        "description": "Attacker captures credentials, session headers, and response bodies in transit.",
                        "vulnerability_type": "Eavesdropping / Packet Sniffing",
                        "impact": "Full disclosure of user data and session hijacking."
                    }
                ],
                "steps": [
                    {
                        "step_number": 1,
                        "description": "Attacker monitors network traffic on shared network.",
                        "vulnerability_type": "Network Surveillance",
                    },
                    {
                        "step_number": 2,
                        "description": "Insecure HTTP connection is intercepted without HSTS enforcement.",
                        "vulnerability_type": "Missing HSTS / Plain HTTP",
                    },
                    {
                        "step_number": 3,
                        "description": "Sensitive credentials and session cookies are read in plaintext.",
                        "vulnerability_type": "Credential Interception",
                    }
                ]
            })

        # -------------------------------------------------------------
        # Path 5: Clickjacking & UI Redressing via Missing Frame Controls
        # -------------------------------------------------------------
        if any("x-frame-options" in v.get("vuln_type", "").lower() for v in header_vulns):
            paths.append({
                "name": "Clickjacking & UI Redressing Attack Chain",
                "description": "Missing X-Frame-Options or CSP frame-ancestors permits framing of the website in external iframes. Attackers overlay deceptive buttons over legitimate application controls to trick users into performing unintentional actions.",
                "risk_level": "Medium",
                "impact": "Unintentional clicks leading to account changes or social interactions.",
                "likelihood": "Medium",
                "vulnerabilities": ["Missing Security Header: X-Frame-Options"],
                "related_vulnerabilities": ["Clickjacking", "Security Headers"],
                "attack_steps": [
                    {
                        "step_number": 1,
                        "description": "Attacker creates a deceptive game or lure website.",
                        "vulnerability_type": "Phishing / Social Engineering",
                        "impact": "Entices user to click specific screen coordinates."
                    },
                    {
                        "step_number": 2,
                        "description": "Target application is loaded into an invisible, transparent iframe beneath cursor.",
                        "vulnerability_type": "Missing Security Header: X-Frame-Options",
                        "impact": "Browser permits cross-origin framing because X-Frame-Options is omitted."
                    },
                    {
                        "step_number": 3,
                        "description": "User clicks the visible decoy, triggering actions on the hidden target application.",
                        "vulnerability_type": "UI Redressing",
                        "impact": "Unintended deletion, subscription, or account setting modification."
                    }
                ],
                "steps": [
                    {
                        "step_number": 1,
                        "description": "Attacker embeds application inside transparent iframe on decoy website.",
                        "vulnerability_type": "Missing X-Frame-Options",
                    },
                    {
                        "step_number": 2,
                        "description": "Victim clicks decoy elements positioned over real application buttons.",
                        "vulnerability_type": "Click Redirection",
                    },
                    {
                        "step_number": 3,
                        "description": "Target application executes state change on behalf of authenticated user.",
                        "vulnerability_type": "Unintended Action Execution",
                    }
                ]
            })

        # Default fallback path if specific chains aren't triggered
        if not paths and vulnerabilities:
            paths.append({
                "name": "Defense-in-Depth Degradation & Reconnaissance Pathway",
                "description": "Multiple low-to-medium configuration weaknesses and missing HTTP defense headers reduce defense-in-depth protections. Attackers combine these findings during reconnaissance to map software versions and plan targeted attacks.",
                "risk_level": "Low",
                "impact": "Facilitates subsequent reconnaissance and exploitation attempts.",
                "likelihood": "Low",
                "vulnerabilities": [v.get("vuln_type") for v in vulnerabilities[:3]],
                "related_vulnerabilities": ["Defense-in-Depth", "Security Headers"],
                "attack_steps": [
                    {
                        "step_number": 1,
                        "description": "Attacker conducts automated passive reconnaissance against public endpoints.",
                        "vulnerability_type": "Information Gathering",
                        "impact": "Discovers software banners and missing protective headers."
                    },
                    {
                        "step_number": 2,
                        "description": "Identifies lack of browser-enforced security policies and safeguards.",
                        "vulnerability_type": "Missing Security Headers",
                        "impact": "Weakens client-side defense barriers."
                    }
                ],
                "steps": [
                    {
                        "step_number": 1,
                        "description": "Attacker gathers metadata from missing headers and exposed banners.",
                        "vulnerability_type": "Reconnaissance",
                    },
                    {
                        "step_number": 2,
                        "description": "Leverages reduced client protections for secondary attack phases.",
                        "vulnerability_type": "Defense Weakening",
                    }
                ]
            })

        return paths
