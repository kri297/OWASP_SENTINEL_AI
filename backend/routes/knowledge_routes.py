"""
OWASP Sentinel AI - OWASP Top 10 Security Knowledge Base API
Provides comprehensive definitions, risk classification, CWE references,
common exploitation scenarios, and developer remediation guidelines.
"""

from flask import Blueprint, jsonify, request

knowledge_bp = Blueprint("knowledge", __name__, url_prefix="/api/knowledge")

OWASP_TOP_10 = [
    {
        "id": "A01:2021",
        "code": "A01",
        "title": "Broken Access Control",
        "risk_level": "Critical",
        "impact": "High",
        "description": "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data, or performing a business function outside the user's limits.",
        "common_flaws": [
            "Insecure Direct Object References (IDOR)",
            "Privilege escalation (vertical or horizontal)",
            "Missing access controls on sensitive API endpoints",
            "CORS misconfigurations allowing unauthorized resource access",
            "Force browsing to protected administration URLs",
        ],
        "remediation": [
            "Deny access by default except for public resources.",
            "Implement access control mechanisms once and re-use them throughout the application.",
            "Enforce record ownership checks rather than accepting user-supplied IDs.",
            "Disable web server directory listing and ensure file metadata is not accessible.",
            "Log access control failures and alert administrators when abnormal spikes occur.",
        ],
        "example_code": "```python\n# INSECURE:\n@app.route('/invoice/<id>')\ndef view_invoice(id):\n    return Invoice.query.get(id).to_json()\n\n# SECURE:\n@app.route('/invoice/<id>')\n@login_required\ndef view_invoice(id):\n    invoice = Invoice.query.filter_by(id=id, user_id=current_user.id).first_or_404()\n    return invoice.to_json()\n```",
        "related_cwes": ["CWE-200", "CWE-284", "CWE-285", "CWE-639"],
        "owasp_url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    },
    {
        "id": "A02:2021",
        "code": "A02",
        "title": "Cryptographic Failures",
        "risk_level": "High",
        "impact": "High",
        "description": "Failures related to cryptography (previously known as Sensitive Data Exposure), which often lead to sensitive data exposure or system compromise. This includes transmitting sensitive data in clear text, using weak or outdated cryptographic algorithms, or default crypto keys.",
        "common_flaws": [
            "Transmitting passwords or payment data over unencrypted HTTP",
            "Use of broken hash functions like MD5 or SHA1 for passwords",
            "Missing HTTP Strict Transport Security (HSTS) headers",
            "Storing credentials in plaintext or with reversible encryption",
            "Hardcoded cryptographic keys in client source code",
        ],
        "remediation": [
            "Classify data processed by the application and encrypt all sensitive data at rest.",
            "Enforce encryption in transit with TLS 1.3 or modern TLS 1.2 and HSTS.",
            "Use salted, adaptive password hashing algorithms (Argon2, bcrypt, PBKDF2).",
            "Ensure proper key management with secure secret managers.",
            "Disable caching for responses that contain sensitive personal or financial data.",
        ],
        "example_code": "```python\n# SECURE PASSWORD HASHING:\nimport bcrypt\n\ndef hash_password(password: str) -> bytes:\n    salt = bcrypt.gensalt(rounds=12)\n    return bcrypt.hashpw(password.encode('utf-8'), salt)\n```",
        "related_cwes": ["CWE-259", "CWE-327", "CWE-331"],
        "owasp_url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    },
    {
        "id": "A03:2021",
        "code": "A03",
        "title": "Injection",
        "risk_level": "Critical",
        "impact": "Critical",
        "description": "An application is vulnerable to attack when user-supplied data is not validated, filtered, or sanitized by the application, or hostile data is used directly within dynamic queries, commands, or interpreters (SQL, NoSQL, OS commands, LDAP, XSS).",
        "common_flaws": [
            "SQL Injection via concatenated query strings",
            "Cross-Site Scripting (Reflected, Stored, or DOM-based XSS)",
            "Command Injection in backend system subprocesses",
            "Server-Side Template Injection (SSTI)",
            "LDAP or XPath injection in authentication lookups",
        ],
        "remediation": [
            "Use safe parameterized APIs or Object Relational Mapping (ORM) tools.",
            "Implement positive server-side input validation with strict allowlists.",
            "Context-aware output encoding for all user-supplied data rendered in HTML/JS.",
            "Use LIMIT and other SQL controls within queries to prevent mass disclosure.",
            "Implement a strict Content Security Policy (CSP) header.",
        ],
        "example_code": "```python\n# INSECURE:\ncursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")\n\n# SECURE (PARAMETERIZED):\ncursor.execute(\"SELECT * FROM users WHERE username = %s\", (username,))\n```",
        "related_cwes": ["CWE-79", "CWE-89", "CWE-78", "CWE-94"],
        "owasp_url": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    {
        "id": "A04:2021",
        "code": "A04",
        "title": "Insecure Design",
        "risk_level": "High",
        "impact": "High",
        "description": "Insecure design represents weaknesses that exist before code is written. It focuses on risks related to design and architectural flaws, calling for more use of threat modeling, secure design patterns, and reference architectures.",
        "common_flaws": [
            "Lack of rate limiting allowing credential stuffing or brute force",
            "Recovery questions with guessable answers",
            "Unrestricted credit card or discount code redemption flows",
            "Failure to isolate tenant data in multi-tenant SaaS architectures",
        ],
        "remediation": [
            "Establish a secure development lifecycle with AppSec professionals.",
            "Use threat modeling for critical authentication, access control, and key logic flows.",
            "Integrate security tests in user stories and architecture reviews.",
            "Limit resource consumption per user or service to mitigate denial of service.",
        ],
        "example_code": "```python\n# IMPLEMENT RATE LIMITING ON SENSITIVE ENDPOINTS\nfrom flask_limiter import Limiter\nlimiter = Limiter(get_remote_address, app=app)\n\n@app.route('/api/login', methods=['POST'])\n@limiter.limit('5 per minute')\ndef login():\n    ...\n```",
        "related_cwes": ["CWE-209", "CWE-256", "CWE-522"],
        "owasp_url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    },
    {
        "id": "A05:2021",
        "code": "A05",
        "title": "Security Misconfiguration",
        "risk_level": "Medium",
        "impact": "Moderate",
        "description": "Security misconfiguration is the most commonly seen issue. It occurs when default settings are unhardened, cloud storage permissions are open, HTTP security headers are missing, or verbose debug stack traces reveal sensitive internals.",
        "common_flaws": [
            "Missing defensive security headers (CSP, HSTS, X-Content-Type-Options)",
            "Default accounts or passwords left unchanged",
            "Detailed error messages containing database stack traces",
            "Open cloud storage buckets or misconfigured CORS headers",
            "Unnecessary features, sample files, or ports enabled",
        ],
        "remediation": [
            "A repeatable hardening process that makes it fast to deploy locked-down environments.",
            "Remove or do not install unused features, documentation, and sample components.",
            "Send defensive security headers with every response.",
            "Automated verification of the effectiveness of configurations in all environments.",
        ],
        "example_code": "```nginx\n# SECURE SECURITY HEADERS (Nginx):\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self'\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header X-Frame-Options \"DENY\" always;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n```",
        "related_cwes": ["CWE-16", "CWE-611", "CWE-1004"],
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    {
        "id": "A06:2021",
        "code": "A06",
        "title": "Vulnerable and Outdated Components",
        "risk_level": "High",
        "impact": "High",
        "description": "Using client-side or server-side software components with known published vulnerabilities (CVEs) undermines application defenses and enables a range of potential attacks.",
        "common_flaws": [
            "Running end-of-life frameworks or libraries with unpatched CVEs",
            "Not scanning dependencies in CI/CD pipeline",
            "Failure to pin and audit open-source packages",
            "Unused or legacy packages left in production artifacts",
        ],
        "remediation": [
            "Remove unused dependencies, unnecessary features, and components.",
            "Continuously inventory client-side and server-side libraries using SCA tools.",
            "Only obtain components from official sources over secure links.",
            "Monitor CVE databases and establish an automated patch management workflow.",
        ],
        "example_code": "```bash\n# AUTOMATED DEPENDENCY AUDIT:\n# Python:\npip-audit\n# Node.js:\nnpm audit --audit-level=high\n```",
        "related_cwes": ["CWE-1104", "CWE-937"],
        "owasp_url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    },
    {
        "id": "A07:2021",
        "code": "A07",
        "title": "Identification and Authentication Failures",
        "risk_level": "High",
        "impact": "Critical",
        "description": "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks such as credential stuffing and session hijacking.",
        "common_flaws": [
            "Permits brute force attacks or automated credential stuffing",
            "Weak or default password policies",
            "Session identifiers exposed in URLs or without HttpOnly/Secure flags",
            "Session fixation or failure to invalidate sessions upon logout",
        ],
        "remediation": [
            "Implement multi-factor authentication (MFA) to prevent automated attacks.",
            "Do not ship or deploy with default credentials.",
            "Align password length and complexity checks with NIST 800-63b guidelines.",
            "Use a hardened session manager that generates random session IDs with Secure/HttpOnly/SameSite attributes.",
        ],
        "example_code": "```python\n# SECURE SESSION COOKIE SETTINGS (Flask):\nSESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SECURE = True\nSESSION_COOKIE_SAMESITE = 'Lax'\nPERMANENT_SESSION_LIFETIME = timedelta(minutes=30)\n```",
        "related_cwes": ["CWE-287", "CWE-384", "CWE-613"],
        "owasp_url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    },
    {
        "id": "A08:2021",
        "code": "A08",
        "title": "Software and Data Integrity Failures",
        "risk_level": "High",
        "impact": "High",
        "description": "Focuses on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. Includes insecure deserialization, where untrusted data causes arbitrary remote code execution.",
        "common_flaws": [
            "Insecure deserialization of Java, Python pickle, or PHP objects",
            "Unsigned firmware or code updates fetched over cleartext",
            "Using untrusted CDNs without Subresource Integrity (SRI) hashes",
            "Insecure auto-update features without signature validation",
        ],
        "remediation": [
            "Use digital signatures or similar mechanisms to verify that software is from expected source.",
            "Ensure libraries and dependencies use trusted repositories.",
            "Use subresource integrity (SRI) hashes on all script and stylesheet tags loaded from external CDNs.",
            "Do not accept serialized objects from untrusted sources; use JSON or Protocol Buffers instead.",
        ],
        "example_code": "```html\n<!-- SUBRESOURCE INTEGRITY (SRI): -->\n<script\n  src=\"https://code.jquery.com/jquery-3.7.1.min.js\"\n  integrity=\"sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo=\"\n  crossorigin=\"anonymous\"></script>\n```",
        "related_cwes": ["CWE-502", "CWE-829"],
        "owasp_url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    },
    {
        "id": "A09:2021",
        "code": "A09",
        "title": "Security Logging and Monitoring Failures",
        "risk_level": "Medium",
        "impact": "Moderate",
        "description": "Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs any time auditable events are not logged or logs are not monitored for suspicious activity.",
        "common_flaws": [
            "Login, access control, and server-side validation failures not logged",
            "Logs only stored locally without tamper resistance",
            "No real-time alerting on suspicious patterns or high-volume error codes",
            "Logging sensitive cleartext credentials or tokens in log files",
        ],
        "remediation": [
            "Ensure all login, access control, and input validation failures generate audit logs.",
            "Ensure logs are formatted in a standard structured format (e.g., JSON) consumable by centralized SIEM.",
            "Establish effective monitoring and alerting so suspicious activities are detected promptly.",
            "Prevent log injection by encoding newlines and special characters.",
        ],
        "example_code": "```python\n# STRUCTURED SECURITY AUDIT LOGGING:\nimport logging\nimport json\n\ndef log_security_event(event_type: str, user_id: str, ip: str, outcome: str):\n    event = {\"timestamp\": datetime.now(timezone.utc).isoformat(), \"event\": event_type, \"user\": user_id, \"ip\": ip, \"outcome\": outcome}\n    logging.warning(json.dumps(event))\n```",
        "related_cwes": ["CWE-778", "CWE-117"],
        "owasp_url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    },
    {
        "id": "A10:2021",
        "code": "A10",
        "title": "Server-Side Request Forgery (SSRF)",
        "risk_level": "High",
        "impact": "High",
        "description": "SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall or VPN.",
        "common_flaws": [
            "Webhooks or image import endpoints accepting raw internal IP addresses",
            "Accessing cloud metadata services (e.g. 169.254.169.254) to steal IAM credentials",
            "Interacting with internal backend microservices or Redis/Memcached ports",
        ],
        "remediation": [
            "Enforce a strict URL allowlist for all outbound requests.",
            "Block requests to private IP ranges (RFC 1918) and cloud metadata services.",
            "Disable HTTP redirections on outbound client libraries.",
            "Segment remote resource fetching functionality in separate networks.",
        ],
        "example_code": "```python\n# PREVENT SSRF: BLOCK PRIVATE IPS & METADATA\nimport ipaddress\nfrom urllib.parse import urlparse\n\ndef is_safe_url(url: str) -> bool:\n    host = urlparse(url).hostname\n    ip = ipaddress.ip_address(socket.gethostbyname(host))\n    return not (ip.is_private or ip.is_loopback or ip.is_link_local)\n```",
        "related_cwes": ["CWE-918"],
        "owasp_url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    },
]


@knowledge_bp.route("", methods=["GET"], strict_slashes=False)
@knowledge_bp.route("/", methods=["GET"], strict_slashes=False)
def list_knowledge():
    """Return all OWASP Top 10 items."""
    return jsonify({
        "total": len(OWASP_TOP_10),
        "categories": OWASP_TOP_10,
    })


@knowledge_bp.route("/<string:category_id>", methods=["GET"])
def get_category(category_id):
    """Retrieve single category by code (e.g. A01 or A01:2021)."""
    norm = category_id.upper().strip()
    for item in OWASP_TOP_10:
        if item["code"].upper() == norm or item["id"].upper() == norm or norm in item["id"].upper():
            return jsonify(item)
    return jsonify({"error": f"OWASP category '{category_id}' not found"}), 404


@knowledge_bp.route("/search", methods=["GET"])
def search_knowledge():
    """Full-text search through descriptions, titles, CWEs, and remediation steps."""
    query = request.args.get("q", "").lower().strip()
    if not query:
        return jsonify({"results": OWASP_TOP_10, "total": len(OWASP_TOP_10)})

    matched = []
    for item in OWASP_TOP_10:
        blob = f"{item['id']} {item['title']} {item['description']} {' '.join(item['common_flaws'])} {' '.join(item['related_cwes'])}".lower()
        if query in blob:
            matched.append(item)

    return jsonify({"results": matched, "total": len(matched), "query": query})


@knowledge_bp.route("/cwe/<string:cwe_id>", methods=["GET"])
def find_by_cwe(cwe_id):
    """Find OWASP categories linked to a given CWE identifier."""
    target_cwe = cwe_id.upper().strip()
    if not target_cwe.startswith("CWE-"):
        target_cwe = f"CWE-{target_cwe}"

    matched = [item for item in OWASP_TOP_10 if target_cwe in item.get("related_cwes", [])]
    return jsonify({"cwe": target_cwe, "matches": matched, "total": len(matched)})
