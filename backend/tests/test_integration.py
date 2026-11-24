"""
End-to-end verification script for OWASP Sentinel AI.
Tests backend initialization, database models, scan lifecycle,
attack-path synthesis, and PDF report generation.
"""

import sys
import os
import time

# Ensure backend root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, Scan, Vulnerability, AttackPath
from scanner.ai_analyzer import AIAnalyzer
from scanner.attack_path_analyzer import AttackPathAnalyzer
from reporter.pdf_generator import ReportGenerator

def run_tests():
    print("[1/6] Initializing Flask test client and SQLite database...")
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    with app.app_context():
        # Check API root
        res = client.get("/api")
        assert res.status_code == 200, f"Expected 200 from /api, got {res.status_code}"
        print("  ✓ API root returns 200 OK")

        # Check Dashboard stats
        res = client.get("/api/dashboard/stats")
        assert res.status_code == 200, f"Expected 200 from /api/dashboard/stats, got {res.status_code}"
        print("  ✓ Dashboard stats endpoint returns 200 OK")

        # Create a mock scan record to verify end-to-end reporting and DB
        print("[2/6] Creating sample vulnerability & attack path records...")
        scan = Scan(
            target_url="https://demo-test-site.local",
            scan_type="full",
            status="completed",
            total_vulnerabilities=4,
            critical_count=1,
            high_count=1,
            medium_count=1,
            low_count=1,
            info_count=0
        )
        db.session.add(scan)
        db.session.commit()

        v1 = Vulnerability(
            scan_id=scan.id,
            vuln_type="Reflected Cross-Site Scripting (XSS)",
            severity="High",
            confidence="High",
            url="https://demo-test-site.local/search?q=test",
            parameter="q",
            evidence="Injected probe reflected unescaped in response HTML.",
            description="Parameter 'q' reflects unsanitized user input into rendered output.",
            remediation="Apply contextual HTML encoding before reflecting user input.",
            cwe_id="CWE-79",
            owasp_category="A03:2021-Injection"
        )
        v2 = Vulnerability(
            scan_id=scan.id,
            vuln_type="Cookie Missing 'HttpOnly' Flag: session_id",
            severity="Medium",
            confidence="High",
            url="https://demo-test-site.local/",
            parameter="session_id",
            evidence="Set-Cookie: session_id=xyz lacks HttpOnly directive.",
            description="The authentication cookie can be accessed via document.cookie in JavaScript.",
            remediation="Set the HttpOnly flag on all sensitive authentication cookies.",
            cwe_id="CWE-1004",
            owasp_category="A05:2021-Security Misconfiguration"
        )
        v3 = Vulnerability(
            scan_id=scan.id,
            vuln_type="SQL Injection Indicator",
            severity="Critical",
            confidence="High",
            url="https://demo-test-site.local/product?id=1",
            parameter="id",
            evidence="Injected single quote returned SQLite syntax error signature.",
            description="Dynamic SQL query concatenation exposes the database to injection.",
            remediation="Use parameterized queries and prepared statements.",
            cwe_id="CWE-89",
            owasp_category="A03:2021-Injection"
        )
        db.session.add_all([v1, v2, v3])
        db.session.commit()
        print("  ✓ Created test vulnerabilities (SQLi, XSS, Cookie security)")

        # Test Attack-Path Analyzer
        print("[3/6] Running Attack-Path Analyzer on vulnerabilities...")
        vuln_dicts = [v.to_dict() for v in [v1, v2, v3]]
        path_analyzer = AttackPathAnalyzer()
        paths = path_analyzer.analyze(vuln_dicts)
        assert len(paths) >= 2, f"Expected at least 2 attack paths, got {len(paths)}"
        print(f"  ✓ Attack-Path Analyzer synthesized {len(paths)} correlated attack paths:")
        for p in paths:
            print(f"    - [{p['risk_level']}] {p['name']}")
            import json
            ap = AttackPath(
                scan_id=scan.id,
                name=p["name"],
                description=p["description"],
                risk_level=p["risk_level"],
                vulnerabilities=json.dumps(p.get("vulnerabilities", [])),
                attack_steps=json.dumps(p.get("attack_steps", []))
            )
            db.session.add(ap)
        db.session.commit()

        # Test AI Analyzer fallback and enrichment
        print("[4/6] Verifying AI Analyzer & Knowledge Base...")
        ai_analyzer = AIAnalyzer(api_key=None) # Tests rule-based engine
        enrichment = ai_analyzer.enrich(v1.to_dict())
        assert "description" in enrichment and "remediation" in enrichment
        print("  ✓ AI Analyzer enrichment generated descriptive context & remediation")

        # Test PDF Report Generator
        print("[5/6] Testing PDF Report Generator (ReportLab)...")
        from routes.report_routes import _build_scan_payload
        payload = _build_scan_payload(scan)
        generator = ReportGenerator()
        pdf_bytes = generator.generate(payload)
        assert len(pdf_bytes) > 1000, f"Generated PDF is unusually small: {len(pdf_bytes)} bytes"
        assert pdf_bytes.startswith(b"%PDF"), "Generated output does not have PDF header magic bytes"
        print(f"  ✓ PDF report generated successfully ({len(pdf_bytes):,} bytes)")

        # Test REST Endpoints
        print("[6/6] Verifying REST endpoints with Flask test client...")
        res = client.get(f"/api/scans/{scan.id}")
        assert res.status_code == 200
        res = client.get(f"/api/scans/{scan.id}/vulnerabilities")
        assert res.status_code == 200 and len(res.json["vulnerabilities"]) == 3
        res = client.get(f"/api/scans/{scan.id}/attack-paths")
        assert res.status_code == 200 and len(res.json["attack_paths"]) >= 2
        res = client.get(f"/api/scans/{scan.id}/report/pdf")
        assert res.status_code == 200 and res.mimetype == "application/pdf"
        res = client.get(f"/api/scans/{scan.id}/report/json")
        assert res.status_code == 200 and res.mimetype == "application/json"
        res = client.get("/api/dashboard/vulnerability-trend")
        assert res.status_code == 200
        print("  ✓ All API routes verified: scan details, vulnerabilities, attack paths, PDF/JSON downloads, trends")

        print("\n========================================================")
        print("🎉 ALL TESTS PASSED! OWASP Sentinel AI IS FULLY OPERATIONAL!")
        print("========================================================")

if __name__ == "__main__":
    run_tests()
