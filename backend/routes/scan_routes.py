import json
import threading
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Blueprint, request, jsonify, current_app

from models import db, Scan, Vulnerability, AttackPath

logger = logging.getLogger(__name__)

scan_bp = Blueprint("scan", __name__, url_prefix="/api/scans")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_valid_url(url: str) -> bool:
    """Basic URL validation."""
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False


def _run_scan_background(app, scan_id: int, checks=None):
    """Execute the scan in a background thread with its own app context."""
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s not found when background thread started.", scan_id)
            return

        try:
            scan.status = "running"
            db.session.commit()
            logger.info("Scan %s started for %s", scan_id, scan.target_url)

            # ----------------------------------------------------------
            # 1. Run the scan engine
            # ----------------------------------------------------------
            try:
                from scanner.engine import ScanEngine

                engine = ScanEngine(
                    target_url=scan.target_url,
                    scan_type=scan.scan_type,
                    timeout=app.config.get("SCAN_TIMEOUT", 30),
                    max_urls=app.config.get("MAX_URLS_PER_SCAN", 50),
                    checks=checks,
                )
                raw_findings = engine.run()
            except ImportError:
                logger.warning("ScanEngine not available — using empty results.")
                engine = None
                raw_findings = []

            # ----------------------------------------------------------
            # 2. Persist raw vulnerabilities
            # ----------------------------------------------------------
            severity_counter = {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Info": 0,
            }

            for finding in raw_findings:
                vuln = Vulnerability(
                    scan_id=scan.id,
                    vuln_type=finding.get("vuln_type", "Unknown"),
                    severity=finding.get("severity", "Info"),
                    confidence=finding.get("confidence", "Medium"),
                    url=finding.get("url", scan.target_url),
                    parameter=finding.get("parameter"),
                    evidence=finding.get("evidence", ""),
                    description=finding.get("description", ""),
                    remediation=finding.get("remediation", ""),
                    cwe_id=finding.get("cwe_id"),
                    owasp_category=finding.get("owasp_category", ""),
                    verification_status=finding.get("verification_status"),
                    http_status=finding.get("http_status"),
                    response_type=finding.get("response_type"),
                    actual_content_detected=finding.get("actual_content_detected"),
                    recommended_classification=finding.get("recommended_classification"),
                    verification_guidance=finding.get("verification_guidance"),
                )
                db.session.add(vuln)
                sev = vuln.severity if vuln.severity in severity_counter else "Info"
                severity_counter[sev] += 1

            db.session.flush()

            # ----------------------------------------------------------
            # 3. AI enrichment (optional)
            # ----------------------------------------------------------
            try:
                from scanner.ai_analyzer import AIAnalyzer
                from concurrent.futures import ThreadPoolExecutor

                api_key = app.config.get("GEMINI_API_KEY")
                if api_key:
                    analyzer = AIAnalyzer(api_key=api_key)
                    vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()

                    # Prioritize Critical, High, and Medium findings for AI enhancement
                    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
                    sorted_vulns = sorted(vulns, key=lambda v: sev_order.get(v.severity, 5))

                    # Enrich verified findings that don't already have explicit false-positive guidance
                    to_enrich = [v for v in sorted_vulns if v.verification_status != "Needs verification"][:6]

                    def _enrich_single(v):
                        try:
                            return v, analyzer.enrich(v.to_dict())
                        except Exception as e:
                            logger.debug("Enrichment item skipped: %s", e)
                            return v, None

                    with ThreadPoolExecutor(max_workers=3) as executor:
                        results = list(executor.map(_enrich_single, to_enrich))

                    for vuln_obj, enriched in results:
                        if enriched:
                            vuln_obj.description = enriched.get("description", vuln_obj.description)
                            vuln_obj.remediation = enriched.get("remediation", vuln_obj.remediation)

                    db.session.flush()
                    logger.info("AI enrichment completed for scan %s", scan_id)
                else:
                    logger.info("GEMINI_API_KEY not set — skipping AI enrichment.")
            except ImportError:
                logger.info("AIAnalyzer module not available — skipping enrichment.")
            except Exception as exc:
                logger.warning("AI enrichment failed: %s", exc)

            # ----------------------------------------------------------
            # 4. Attack-path analysis (optional)
            # ----------------------------------------------------------
            try:
                from scanner.attack_path_analyzer import AttackPathAnalyzer

                vuln_dicts = [v.to_dict() for v in Vulnerability.query.filter_by(scan_id=scan.id).all()]
                path_analyzer = AttackPathAnalyzer()
                paths = path_analyzer.analyze(vuln_dicts)
                for p in paths:
                    attack_path = AttackPath(
                        scan_id=scan.id,
                        name=p.get("name", "Unnamed Path"),
                        description=p.get("description", ""),
                        risk_level=p.get("risk_level", "Medium"),
                        vulnerabilities=json.dumps(p.get("vulnerabilities", [])),
                        attack_steps=json.dumps(p.get("attack_steps", [])),
                    )
                    db.session.add(attack_path)
                logger.info("Attack-path analysis completed for scan %s", scan_id)
            except ImportError:
                logger.info("AttackPathAnalyzer module not available — skipping.")
            except Exception as exc:
                logger.warning("Attack-path analysis failed: %s", exc)

            # ----------------------------------------------------------
            # 4.5 Save Recon & Diagnostics (Tech Fingerprint, SSL, DNS)
            # ----------------------------------------------------------
            if engine:
                scan.tech_fingerprint = json.dumps(getattr(engine, "tech_data", {}))
                scan.ssl_info = json.dumps(getattr(engine, "ssl_data", {}))
                scan.dns_info = json.dumps(getattr(engine, "dns_data", {}))

            # ----------------------------------------------------------
            # 5. Finalise scan record
            # ----------------------------------------------------------
            scan.total_vulnerabilities = sum(severity_counter.values())
            scan.critical_count = severity_counter["Critical"]
            scan.high_count = severity_counter["High"]
            scan.medium_count = severity_counter["Medium"]
            scan.low_count = severity_counter["Low"]
            scan.info_count = severity_counter["Info"]
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            db.session.commit()
            logger.info("Scan %s completed — %d vulnerabilities found.", scan_id, scan.total_vulnerabilities)

        except Exception as exc:
            logger.exception("Scan %s failed: %s", scan_id, exc)
            try:
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
                db.session.commit()
            except Exception:
                db.session.rollback()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@scan_bp.route("", methods=["POST"], strict_slashes=False)
@scan_bp.route("/", methods=["POST"], strict_slashes=False)
def start_scan():
    """Start a new security scan."""
    data = request.get_json(silent=True) or {}

    target_url = data.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "target_url is required"}), 400
    if not _is_valid_url(target_url):
        return jsonify({"error": "Invalid URL. Must start with http:// or https://"}), 400

    scan_type = data.get("scan_type", "full")
    if scan_type not in ("full", "quick"):
        scan_type = "full"

    checks = data.get("checks")  # optional list of module IDs

    scan = Scan(
        target_url=target_url,
        scan_type=scan_type,
        status="pending",
    )
    db.session.add(scan)
    db.session.commit()

    # Kick off the scan in a background thread
    app = current_app._get_current_object()
    thread = threading.Thread(
        target=_run_scan_background,
        args=(app, scan.id, checks),
        daemon=True,
    )
    thread.start()

    return jsonify({
        "id": scan.id,
        "status": scan.status,
        "message": f"Scan started for {target_url}",
    }), 201


@scan_bp.route("", methods=["GET"], strict_slashes=False)
@scan_bp.route("/", methods=["GET"], strict_slashes=False)
def list_scans():
    """List all scans, newest first, with pagination."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    per_page = min(per_page, 100)  # cap to 100

    pagination = (
        Scan.query
        .order_by(Scan.created_at.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )

    return jsonify({
        "scans": [s.to_dict() for s in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "per_page": pagination.per_page,
        "pages": pagination.pages,
    })


@scan_bp.route("/compare", methods=["GET"])
def compare_scans():
    """Compare two scans side-by-side to highlight fixed, new, and unchanged findings."""
    scan1_id = request.args.get("scan1", type=int)
    scan2_id = request.args.get("scan2", type=int)

    if not scan1_id or not scan2_id:
        return jsonify({"error": "Both scan1 and scan2 query parameters are required"}), 400

    s1 = db.session.get(Scan, scan1_id)
    s2 = db.session.get(Scan, scan2_id)

    if not s1 or not s2:
        return jsonify({"error": "One or both scans could not be found"}), 404

    vulns1 = {f"{v.vuln_type}::{v.url}::{v.parameter or ''}": v.to_dict() for v in s1.vulnerabilities.all()}
    vulns2 = {f"{v.vuln_type}::{v.url}::{v.parameter or ''}": v.to_dict() for v in s2.vulnerabilities.all()}

    keys1 = set(vulns1.keys())
    keys2 = set(vulns2.keys())

    fixed_keys = keys1 - keys2
    new_keys = keys2 - keys1
    common_keys = keys1 & keys2

    return jsonify({
        "scan1": s1.to_dict(),
        "scan2": s2.to_dict(),
        "summary": {
            "total_before": len(keys1),
            "total_after": len(keys2),
            "fixed_count": len(fixed_keys),
            "new_count": len(new_keys),
            "unchanged_count": len(common_keys),
            "critical_delta": s2.critical_count - s1.critical_count,
            "high_delta": s2.high_count - s1.high_count,
        },
        "fixed": [vulns1[k] for k in fixed_keys],
        "new": [vulns2[k] for k in new_keys],
        "unchanged": [vulns2[k] for k in common_keys],
    })


@scan_bp.route("/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    """Get scan details including all vulnerabilities."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    scan_data = scan.to_dict()
    scan_data["vulnerabilities"] = [v.to_dict() for v in scan.vulnerabilities.all()]
    return jsonify(scan_data)


@scan_bp.route("/<int:scan_id>/tech", methods=["GET"])
def get_scan_tech(scan_id):
    """Get tech fingerprint data for a scan."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    data = scan.to_dict()
    return jsonify(data.get("tech_fingerprint") or {})


@scan_bp.route("/<int:scan_id>/ssl", methods=["GET"])
def get_scan_ssl(scan_id):
    """Get SSL analysis data for a scan."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    data = scan.to_dict()
    return jsonify(data.get("ssl_info") or {})


@scan_bp.route("/<int:scan_id>/dns", methods=["GET"])
def get_scan_dns(scan_id):
    """Get DNS recon data for a scan."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    data = scan.to_dict()
    return jsonify(data.get("dns_info") or {})


@scan_bp.route("/<int:scan_id>/vulnerabilities", methods=["GET"])
def get_vulnerabilities(scan_id):
    """Get vulnerabilities for a scan, with optional filtering."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    query = Vulnerability.query.filter_by(scan_id=scan_id)

    # Optional filters
    severity = request.args.get("severity")
    if severity:
        query = query.filter(Vulnerability.severity.ilike(severity))

    vuln_type = request.args.get("vuln_type")
    if vuln_type:
        query = query.filter(Vulnerability.vuln_type.ilike(f"%{vuln_type}%"))

    vulns = query.order_by(Vulnerability.id).all()
    return jsonify({
        "scan_id": scan_id,
        "total": len(vulns),
        "vulnerabilities": [v.to_dict() for v in vulns],
    })


@scan_bp.route("/<int:scan_id>/attack-paths", methods=["GET"])
def get_attack_paths(scan_id):
    """Get attack paths for a scan."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    paths = AttackPath.query.filter_by(scan_id=scan_id).all()
    return jsonify({
        "scan_id": scan_id,
        "total": len(paths),
        "attack_paths": [p.to_dict() for p in paths],
    })


@scan_bp.route("/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    """Delete a scan and all associated data."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    db.session.delete(scan)
    db.session.commit()
    return jsonify({"message": f"Scan {scan_id} deleted successfully."})


@scan_bp.route("/clear-all", methods=["DELETE", "POST"])
def clear_all_scans():
    """Purge all scan history, vulnerabilities, and attack paths for a fresh clean slate."""
    try:
        Vulnerability.query.delete()
        AttackPath.query.delete()
        Scan.query.delete()
        db.session.commit()
        logger.info("All scans and vulnerability records cleared.")
        return jsonify({"message": "All scan records and vulnerabilities cleared successfully."}), 200
    except Exception as exc:
        db.session.rollback()
        logger.exception("Failed to clear scans: %s", exc)
        return jsonify({"error": "Failed to clear scan records."}), 500


@scan_bp.route("/<int:scan_id>/report/pdf", methods=["GET"])
def scan_download_pdf(scan_id):
    """Download PDF report via scans route."""
    from routes.report_routes import download_pdf
    return download_pdf(scan_id)


@scan_bp.route("/<int:scan_id>/report/json", methods=["GET"])
def scan_download_json(scan_id):
    """Download JSON report via scans route."""
    from routes.report_routes import download_json
    return download_json(scan_id)
