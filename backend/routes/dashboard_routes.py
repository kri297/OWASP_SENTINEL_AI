import logging
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify
from sqlalchemy import func

from models import db, Scan, Vulnerability

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


@dashboard_bp.route("/stats", methods=["GET"])
def get_stats():
    """Overall dashboard statistics."""
    try:
        total_scans = Scan.query.count()
        total_vulns = Vulnerability.query.count()

        # Vulnerabilities by severity
        severity_rows = (
            db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
            .group_by(Vulnerability.severity)
            .all()
        )
        vulns_by_severity = {row[0]: row[1] for row in severity_rows}

        # Vulnerabilities by type (top 10)
        type_rows = (
            db.session.query(Vulnerability.vuln_type, func.count(Vulnerability.id))
            .group_by(Vulnerability.vuln_type)
            .order_by(func.count(Vulnerability.id).desc())
            .limit(10)
            .all()
        )
        vulns_by_type = {row[0]: row[1] for row in type_rows}

        # Recent scans (last 10)
        recent_scans = (
            Scan.query
            .order_by(Scan.created_at.desc())
            .limit(10)
            .all()
        )

        return jsonify({
            "total_scans": total_scans,
            "total_vulnerabilities": total_vulns,
            "vulns_by_severity": vulns_by_severity,
            "vulns_by_type": vulns_by_type,
            "recent_scans": [s.to_dict() for s in recent_scans],
        })
    except Exception as exc:
        logger.exception("Failed to fetch dashboard stats: %s", exc)
        return jsonify({"error": "Failed to fetch dashboard stats"}), 500


@dashboard_bp.route("/severity-distribution", methods=["GET"])
def severity_distribution():
    """Severity breakdown suitable for pie / bar charts."""
    try:
        rows = (
            db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
            .group_by(Vulnerability.severity)
            .all()
        )

        distribution = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0,
        }
        for severity, count in rows:
            if severity in distribution:
                distribution[severity] = count

        total = sum(distribution.values())

        return jsonify({
            "distribution": distribution,
            "total": total,
        })
    except Exception as exc:
        logger.exception("Failed to fetch severity distribution: %s", exc)
        return jsonify({"error": "Failed to fetch severity distribution"}), 500


@dashboard_bp.route("/trend", methods=["GET"])
@dashboard_bp.route("/vulnerability-trend", methods=["GET"])
def vulnerability_trend():
    """Vulnerability counts per day over the last 30 days."""
    try:
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

        rows = (
            db.session.query(
                func.date(Vulnerability.created_at).label("day"),
                func.count(Vulnerability.id),
            )
            .filter(Vulnerability.created_at >= thirty_days_ago)
            .group_by(func.date(Vulnerability.created_at))
            .order_by(func.date(Vulnerability.created_at))
            .all()
        )

        trend = [{"date": str(row[0]), "count": row[1]} for row in rows]

        return jsonify({"trend": trend, "days": 30})
    except Exception as exc:
        logger.exception("Failed to fetch vulnerability trend: %s", exc)
        return jsonify({"error": "Failed to fetch vulnerability trend"}), 500
