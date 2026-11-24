import os
import logging
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

from config import Config
from models import db

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app(config_class=Config):
    """Create and configure the Flask application."""

    app = Flask(
        __name__,
        static_folder=None,  # we serve frontend statics manually below
    )
    app.config.from_object(config_class)

    # Extensions
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    db.init_app(app)

    # Ensure the instance directory exists for SQLite
    instance_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), "instance")
    os.makedirs(instance_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Register blueprints
    # ------------------------------------------------------------------
    from routes.scan_routes import scan_bp
    from routes.report_routes import report_bp
    from routes.dashboard_routes import dashboard_bp
    from routes.knowledge_routes import knowledge_bp

    app.register_blueprint(scan_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(knowledge_bp)

    # ------------------------------------------------------------------
    # Create database tables on first request
    # ------------------------------------------------------------------
    with app.app_context():
        db.create_all()
        logger.info("Database tables created / verified.")

    # ------------------------------------------------------------------
    # API root
    # ------------------------------------------------------------------
    @app.route("/api")
    @app.route("/api/")
    def api_root():
        return jsonify({
            "status": "ok",
            "message": "OWASP Sentinel AI API v2.0",
            "endpoints": [
                "/api/scans",
                "/api/dashboard/stats",
                "/api/knowledge",
                "/api/scans/compare",
            ]
        })

    # ------------------------------------------------------------------
    # Serve frontend static files (production build)
    # ------------------------------------------------------------------
    frontend_dist = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "frontend", "dist")
    frontend_dist = os.path.normpath(frontend_dist)

    if os.path.isdir(frontend_dist):
        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def serve_frontend(path):
            file_path = os.path.join(frontend_dist, path)
            if path and os.path.isfile(file_path):
                return send_from_directory(frontend_dist, path)
            return send_from_directory(frontend_dist, "index.html")
    else:
        @app.route("/")
        def index():
            return jsonify({
                "status": "ok",
                "message": "OWASP Sentinel AI API",
                "note": "Frontend not built yet. Run 'npm run build' in the frontend directory.",
            })

    # ------------------------------------------------------------------
    # Global error handlers
    # ------------------------------------------------------------------
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"error": "Internal server error"}), 500

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
app = create_app()

if __name__ == "__main__":
    from waitress import serve

    logger.info("Starting OWASP Sentinel AI on http://0.0.0.0:5000")
    serve(app, host="0.0.0.0", port=5000)
