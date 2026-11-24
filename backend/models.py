import json
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Scan(db.Model):
    """Represents a single security scan run against a target URL."""

    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(2048), nullable=False)
    scan_type = db.Column(db.String(20), nullable=False, default="full")  # "full" | "quick"
    status = db.Column(db.String(20), nullable=False, default="pending")  # pending | running | completed | failed
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)

    # Aggregate vulnerability counts (updated when the scan finishes)
    total_vulnerabilities = db.Column(db.Integer, nullable=False, default=0)
    critical_count = db.Column(db.Integer, nullable=False, default=0)
    high_count = db.Column(db.Integer, nullable=False, default=0)
    medium_count = db.Column(db.Integer, nullable=False, default=0)
    low_count = db.Column(db.Integer, nullable=False, default=0)
    info_count = db.Column(db.Integer, nullable=False, default=0)

    # Reconnaissance & Health Data (JSON serialized)
    tech_fingerprint = db.Column(db.Text, nullable=True)
    ssl_info = db.Column(db.Text, nullable=True)
    dns_info = db.Column(db.Text, nullable=True)

    # Relationships
    vulnerabilities = db.relationship("Vulnerability", backref="scan", lazy="dynamic", cascade="all, delete-orphan")
    attack_paths = db.relationship("AttackPath", backref="scan", lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self):
        def _safe_json(val):
            if not val:
                return None
            if isinstance(val, dict):
                return val
            try:
                return json.loads(val)
            except Exception:
                return None

        return {
            "id": self.id,
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "tech_fingerprint": _safe_json(self.tech_fingerprint),
            "ssl_info": _safe_json(self.ssl_info),
            "dns_info": _safe_json(self.dns_info),
        }


class Vulnerability(db.Model):
    """A single vulnerability discovered during a scan."""

    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)

    vuln_type = db.Column(db.String(100), nullable=False)        # e.g. "SQL Injection", "XSS"
    severity = db.Column(db.String(20), nullable=False)          # Critical | High | Medium | Low | Info
    confidence = db.Column(db.String(20), nullable=False, default="Medium")  # High | Medium | Low
    url = db.Column(db.String(2048), nullable=False)
    parameter = db.Column(db.String(256), nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=True)
    cwe_id = db.Column(db.String(20), nullable=True)             # e.g. "CWE-79"
    owasp_category = db.Column(db.String(100), nullable=False, default="")  # e.g. "A03:2021-Injection"
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    # New Verification & False Positive Classification Metadata
    verification_status = db.Column(db.String(50), nullable=True)           # "Needs verification" | "Verified Exposure"
    http_status = db.Column(db.String(50), nullable=True)                   # e.g. "200 OK"
    response_type = db.Column(db.String(50), nullable=True)                 # e.g. "HTML", "XML", "Plaintext"
    actual_content_detected = db.Column(db.String(100), nullable=True)      # e.g. "Not established", "Established"
    recommended_classification = db.Column(db.String(100), nullable=True)   # e.g. "Informational / False Positive Candidate"
    verification_guidance = db.Column(db.Text, nullable=True)               # e.g. "Do not assign High severity until actual configuration disclosure is verified."

    def to_dict(self):
        # Intelligent fallback for older rows
        v_status = self.verification_status
        if not v_status and (self.confidence == "Low" or "potentially exposed" in self.vuln_type.lower()):
            v_status = "Needs verification"

        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "url": self.url,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "verification_status": v_status,
            "http_status": self.http_status or ("200 OK" if "200" in (self.evidence or "") else None),
            "response_type": self.response_type or ("HTML" if v_status == "Needs verification" else None),
            "actual_content_detected": self.actual_content_detected or ("Not established" if v_status == "Needs verification" else "Established"),
            "recommended_classification": self.recommended_classification or ("Informational / False Positive Candidate" if v_status == "Needs verification" else None),
            "verification_guidance": self.verification_guidance or ("Do not assign High severity until actual configuration disclosure is verified." if v_status == "Needs verification" else None),
        }


class AttackPath(db.Model):
    """An attack path linking multiple vulnerabilities into an exploitation chain."""

    __tablename__ = "attack_paths"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)

    name = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text, nullable=True)
    risk_level = db.Column(db.String(20), nullable=False, default="Medium")  # Critical | High | Medium | Low
    vulnerabilities = db.Column(db.Text, nullable=True)   # JSON list of vulnerability IDs
    attack_steps = db.Column(db.Text, nullable=True)      # JSON list of step descriptions

    def to_dict(self):
        def _safe_json(val):
            if not val:
                return []
            if isinstance(val, list):
                return val
            try:
                return json.loads(val)
            except Exception:
                return []

        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "name": self.name,
            "description": self.description,
            "risk_level": self.risk_level,
            "vulnerabilities": _safe_json(self.vulnerabilities),
            "attack_steps": _safe_json(self.attack_steps),
        }
