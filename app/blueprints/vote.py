from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for

from ..accounts import register_voter
from ..db import get_db
from ..elections import (
    ElectionError, cast_vote, election_state, get_candidates, get_election,
    has_voted, results_visible,
)
from ..security import (
    attempt_login, audit, login_user, logout_user, throttle_hit, voter_required,
)
from ..validators import clean_line, validate_email, validate_password, validate_student_id

bp = Blueprint("vote", __name__)


def _visible_election(eid):
    e = get_election(eid)
    if e is None or not e["launched"]:
        abort(404)
    return e


@bp.get("/")
@voter_required
def index():
    rows = get_db().execute(
        """SELECT e.*, EXISTS(SELECT 1 FROM voter_status v
                              WHERE v.election_id = e.id AND v.user_id = ?) AS voted
           FROM elections e WHERE e.launched = 1 ORDER BY e.opens_at DESC""",
        (g.user["id"],),
    ).fetchall()
    elections = [{**dict(r), "state": election_state(r)} for r in rows]
    return render_template("vote/home.html", elections=elections)


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("vote.index"))
    form, errors = {}, {}
    if request.method == "POST":
        if throttle_hit(f"register:ip:{request.remote_addr}", 10, 3600):
            flash("Too many registration attempts. Try again later.", "error")
            return render_template("vote/register.html", form=form, errors=errors), 429
        form = {
            "student_id": clean_line(request.form.get("student_id")),
            "email": clean_line(request.form.get("email")),
        }
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        sid, errors["student_id"] = validate_student_id(form["student_id"])
        email, errors["email"] = validate_email(
            form["email"], current_app.config["ALLOWED_EMAIL_DOMAIN"]
        )
        errors["password"] = validate_password(password, email, sid)
        if password != confirm:
            errors["confirm"] = "Passwords do not match."
        errors = {k: v for k, v in errors.items() if v}
        if not errors:
            if register_voter(sid, email, password):
                flash("Account created. You can sign in now.", "ok")
                return redirect(url_for("vote.login"))
            flash(
                "We could not complete your registration. Check your details, "
                "or contact the election office if you think this is a mistake.",
                "error",
            )
    return render_template("vote/register.html", form=form, errors=errors)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("vote.index"))
    form = {}
    if request.method == "POST":
        form = {"email": clean_line(request.form.get("email")).lower()}
        user, message = attempt_login(form["email"], request.form.get("password", ""), "voter")
        if user:
            login_user(user)
            return redirect(url_for("vote.index"))
        flash(message, "error")
        return render_template("vote/login.html", form=form), 401
    return render_template("vote/login.html", form=form)


@bp.post("/logout")
def logout():
    if g.user:
        audit("logout", actor_id=g.user["id"])
    logout_user()
    return redirect(url_for("vote.login"))


@bp.get("/elections/<int:eid>")
@voter_required
def election(eid):
    e = _visible_election(eid)
    state = election_state(e)
    return render_template(
        "vote/election.html",
        e=e,
        state=state,
        candidates=get_candidates(eid),
        voted=has_voted(eid, g.user["id"]),
        published=results_visible(e),
    )


def _checked_choice(eid):
    """Shared checks for the review and cast steps."""
    e = _visible_election(eid)
    if election_state(e) != "open":
        raise ElectionError("This election is not open for voting.")
    if has_voted(eid, g.user["id"]):
        raise ElectionError("You have already voted in this election.")
    try:
        cid = int(request.form.get("candidate_id", ""))
    except ValueError:
        raise ElectionError("Choose one of the listed candidates.") from None
    match = [c for c in get_candidates(eid) if c["id"] == cid]
    if not match:
        raise ElectionError("Choose one of the listed candidates.")
    return e, match[0]


@bp.post("/elections/<int:eid>/review")
@voter_required
def review(eid):
    try:
        e, candidate = _checked_choice(eid)
    except ElectionError as exc:
        flash(str(exc), "error")
        return redirect(url_for("vote.election", eid=eid))
    return render_template("vote/review.html", e=e, candidate=candidate)


@bp.post("/elections/<int:eid>/cast")
@voter_required
def cast(eid):
    try:
        _e, candidate = _checked_choice(eid)
        receipt = cast_vote(eid, g.user["id"], candidate["id"])
    except ElectionError as exc:
        flash(str(exc), "error")
        return redirect(url_for("vote.election", eid=eid))
    # Rendered directly (not redirected) so the receipt is never stored or put in a URL.
    return render_template("vote/receipt.html", e=_e, receipt=receipt)
