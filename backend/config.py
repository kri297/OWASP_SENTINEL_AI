import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "owasp-sentinel-ai-secret-key-change-in-production")

    # Database — SQLite stored in backend/instance/sentinel.db
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(os.path.abspath(os.path.dirname(__file__)), "instance", "sentinel.db"),
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Gemini AI (optional — features degrade gracefully when absent)
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", None)

    # Scanner tunables
    SCAN_TIMEOUT = 30          # seconds per request
    MAX_URLS_PER_SCAN = 50     # max URLs crawled in a single scan
