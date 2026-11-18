import os
from datetime import timedelta


def _flag(value):
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def load_config(instance_path):
    scheme = os.environ.get("PREFERRED_URL_SCHEME", "http").lower()
    secure = scheme == "https"
    return {
        "SECRET_KEY": os.environ.get("SECRET_KEY", ""),
        "DATABASE_PATH": os.environ.get(
            "DATABASE_PATH", os.path.join(instance_path, "safevote.db")
        ),
        "SERVER_NAME": os.environ.get("SERVER_NAME", "lvh.me:5000"),
        "PREFERRED_URL_SCHEME": scheme,
        # Host-only cookies (no Domain attribute): the voter, admin and results
        # subdomains never share a session, so a problem on one cannot leak to another.
        "SESSION_COOKIE_NAME": "__Host-sv" if secure else "sv",
        "SESSION_COOKIE_SECURE": secure,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "PERMANENT_SESSION_LIFETIME": timedelta(
            minutes=int(os.environ.get("IDLE_TIMEOUT_MIN", "30"))
        ),
        "ABSOLUTE_SESSION_HOURS": 4,
        "WTF_CSRF_TIME_LIMIT": None,
        "MAX_CONTENT_LENGTH": 256 * 1024,
        "TIMEZONE": os.environ.get("TIMEZONE", "Africa/Nairobi"),
        "ALLOWED_EMAIL_DOMAIN": os.environ.get("ALLOWED_EMAIL_DOMAIN", "")
        .strip()
        .lower()
        .lstrip("@"),
        "MAX_FAILED_LOGINS": 5,
        "LOCKOUT_MINUTES": 15,
        "TRUSTED_PROXY": _flag(os.environ.get("TRUSTED_PROXY")),
    }
