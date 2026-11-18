import os
import secrets
from datetime import datetime
from zoneinfo import ZoneInfo

from flask import Flask, g, render_template, request
from flask_wtf.csrf import CSRFError, CSRFProtect
from markupsafe import Markup
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db as database
from .config import load_config
from .security import load_user

csrf = CSRFProtect()

AREA_LABELS = {"vote": "Vote", "admin": "Election office", "results": "Results"}


def create_app(test_config=None):
    # No built-in static route: the stylesheet is inlined with a CSP nonce, so
    # the app needs no static files and no script at all.
    app = Flask(
        __name__,
        instance_relative_config=True,
        static_folder=None,
        subdomain_matching=True,
    )
    os.makedirs(app.instance_path, exist_ok=True)
    app.config.update(load_config(app.instance_path))
    if test_config:
        app.config.update(test_config)
    if app.config["SECRET_KEY"] in ("", "change-me") and not os.environ.get("FLASK_DEBUG"):
        raise RuntimeError(
            "Set a real SECRET_KEY in .env. Generate one with: "
            'python -c "import secrets; print(secrets.token_hex(32))"'
        )

    if app.config["TRUSTED_PROXY"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    csrf.init_app(app)
    app.teardown_appcontext(database.close_db)
    with app.app_context():
        database.init_db()

    css_path = os.path.join(os.path.dirname(__file__), "assets", "style.css")
    with open(css_path, encoding="utf-8") as fh:
        inline_css = Markup(fh.read())

    from .blueprints import admin, landing, results, vote

    app.register_blueprint(landing.bp)
    app.register_blueprint(vote.bp, subdomain="vote")
    app.register_blueprint(admin.bp, subdomain="admin")
    app.register_blueprint(results.bp, subdomain="results")

    from . import cli

    cli.register(app)

    @app.before_request
    def _prepare():
        g.csp_nonce = secrets.token_urlsafe(16)
        load_user()

    @app.context_processor
    def _context():
        area = request.blueprint or ""
        home = f"{area}.index" if area in AREA_LABELS else "landing.index"
        return {
            "csp_nonce": g.get("csp_nonce", ""),
            "inline_css": inline_css,
            "current_user": g.get("user"),
            "area": area,
            "area_label": AREA_LABELS.get(area),
            "home_endpoint": home,
        }

    @app.template_filter("localdt")
    def localdt(value):
        dt = datetime.fromisoformat(value).astimezone(ZoneInfo(app.config["TIMEZONE"]))
        return dt.strftime("%d %b %Y, %H:%M")

    @app.after_request
    def _headers(resp):
        nonce = g.get("csp_nonce", "")
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            f"style-src 'nonce-{nonce}'; "
            "img-src 'self' data:; form-action 'self'; "
            "frame-ancestors 'none'; base-uri 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = "no-store"
        if app.config["PREFERRED_URL_SCHEME"] == "https":
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    def _error(code, title, message):
        return render_template("error.html", code=code, title=title, message=message), code

    @app.errorhandler(CSRFError)
    def _csrf(_e):
        return _error(400, "Form expired", "Your form expired or was invalid. Go back, reload the page and try again.")

    @app.errorhandler(403)
    def _403(_e):
        return _error(403, "Not allowed", "You do not have access to this page.")

    @app.errorhandler(404)
    def _404(_e):
        return _error(404, "Page not found", "That page does not exist.")

    @app.errorhandler(413)
    def _413(_e):
        return _error(413, "Too large", "That submission is too large.")

    @app.errorhandler(500)
    def _500(_e):
        return _error(500, "Something went wrong", "An unexpected error occurred. Nothing was changed.")

    return app
