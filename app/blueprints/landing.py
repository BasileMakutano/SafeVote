from flask import Blueprint, render_template

bp = Blueprint("landing", __name__)


@bp.get("/")
def index():
    return render_template("landing.html")


@bp.get("/healthz")
def healthz():
    return "ok", 200, {"Content-Type": "text/plain"}
