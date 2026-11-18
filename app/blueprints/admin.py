from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for

from ..db import get_db, transaction
from ..elections import (
    ElectionError, close_now, election_state, get_candidates, get_election,
    launch_election, publish_results,
)
from ..security import (
    admin_required, attempt_login, audit, iso, login_user, logout_user,
    utcnow, verify_audit_chain,
)
from ..validators import clean_line, parse_local_datetime, parse_roll, validate_text

bp = Blueprint("admin", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("admin.index"))
    form = {}
    if request.method == "POST":
        form = {"email": clean_line(request.form.get("email")).lower()}
        user, message = attempt_login(form["email"], request.form.get("password", ""), "admin")
        if user:
            login_user(user)
            return redirect(url_for("admin.index"))
        flash(message, "error")
        return render_template("admin/login.html", form=form), 401
    return render_template("admin/login.html", form=form)


@bp.post("/logout")
def logout():
    if g.user:
        audit("logout", actor_id=g.user["id"])
    logout_user()
    return redirect(url_for("admin.login"))


@bp.get("/")
@admin_required
def index():
    db = get_db()
    rows = db.execute("SELECT * FROM elections ORDER BY id DESC").fetchall()
    elections = [{**dict(r), "state": election_state(r)} for r in rows]
    stats = {
        "roll": db.execute("SELECT COUNT(*) FROM voter_roll").fetchone()[0],
        "registered": db.execute("SELECT COUNT(*) FROM users WHERE role='voter'").fetchone()[0],
    }
    return render_template("admin/dashboard.html", elections=elections, stats=stats)


@bp.route("/elections/new", methods=["GET", "POST"])
@admin_required
def new_election():
    form, errors = {}, {}
    if request.method == "POST":
        tz = current_app.config["TIMEZONE"]
        form = {k: request.form.get(k, "") for k in ("title", "description", "opens_at", "closes_at")}
        title, errors["title"] = validate_text(form["title"], "Title", 3, 120)
        desc, errors["description"] = validate_text(
            form["description"], "Description", 0, 1000, multiline=True, required=False
        )
        opens = parse_local_datetime(form["opens_at"], tz)
        closes = parse_local_datetime(form["closes_at"], tz)
        if opens is None:
            errors["opens_at"] = "Enter a valid opening date and time."
        if closes is None:
            errors["closes_at"] = "Enter a valid closing date and time."
        if opens and closes:
            if closes <= opens:
                errors["closes_at"] = "Closing time must be after the opening time."
            elif closes <= utcnow():
                errors["closes_at"] = "Closing time must be in the future."
        errors = {k: v for k, v in errors.items() if v}
        if not errors:
            with transaction() as db:
                cur = db.execute(
                    "INSERT INTO elections (title, description, opens_at, closes_at, created_by, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (title, desc, iso(opens), iso(closes), g.user["id"], iso(utcnow())),
                )
                audit("election_created", f"election={cur.lastrowid}", g.user["id"])
            flash("Election created. Add candidates, then launch it.", "ok")
            return redirect(url_for("admin.election", eid=cur.lastrowid))
    return render_template("admin/election_form.html", form=form, errors=errors)


def _election_or_404(eid):
    e = get_election(eid)
    if e is None:
        abort(404)
    return e


@bp.get("/elections/<int:eid>")
@admin_required
def election(eid):
    e = _election_or_404(eid)
    db = get_db()
    return render_template(
        "admin/election.html",
        e=e,
        state=election_state(e),
        candidates=get_candidates(eid),
        ballots=db.execute("SELECT COUNT(*) FROM ballots WHERE election_id = ?", (eid,)).fetchone()[0],
        registered=db.execute("SELECT COUNT(*) FROM users WHERE role='voter'").fetchone()[0],
        form={}, errors={},
    )


@bp.post("/elections/<int:eid>/candidates")
@admin_required
def add_candidate(eid):
    e = _election_or_404(eid)
    if election_state(e) != "draft":
        flash("Candidates can only be changed before the election is launched.", "error")
        return redirect(url_for("admin.election", eid=eid))
    name, name_err = validate_text(request.form.get("name"), "Name", 2, 80)
    manifesto, man_err = validate_text(
        request.form.get("manifesto"), "Manifesto", 0, 500, multiline=True, required=False
    )
    if name_err or man_err:
        flash(name_err or man_err, "error")
    else:
        with transaction() as db:
            db.execute(
                "INSERT INTO candidates (election_id, name, manifesto) VALUES (?, ?, ?)",
                (eid, name, manifesto),
            )
            audit("candidate_added", f"election={eid}", g.user["id"])
    return redirect(url_for("admin.election", eid=eid))


@bp.post("/elections/<int:eid>/candidates/<int:cid>/delete")
@admin_required
def delete_candidate(eid, cid):
    e = _election_or_404(eid)
    if election_state(e) != "draft":
        flash("Candidates can only be changed before the election is launched.", "error")
    else:
        with transaction() as db:
            db.execute("DELETE FROM candidates WHERE id = ? AND election_id = ?", (cid, eid))
            audit("candidate_removed", f"election={eid}", g.user["id"])
    return redirect(url_for("admin.election", eid=eid))


def _lifecycle(action, success):
    def view(eid):
        _election_or_404(eid)
        try:
            action(eid, g.user["id"])
            flash(success, "ok")
        except ElectionError as exc:
            flash(str(exc), "error")
        return redirect(url_for("admin.election", eid=eid))

    return view


bp.add_url_rule("/elections/<int:eid>/launch", "launch", admin_required(_lifecycle(launch_election, "Election launched.")), methods=["POST"])
bp.add_url_rule("/elections/<int:eid>/close", "close", admin_required(_lifecycle(close_now, "Election closed.")), methods=["POST"])
bp.add_url_rule("/elections/<int:eid>/publish", "publish", admin_required(_lifecycle(publish_results, "Results published.")), methods=["POST"])


@bp.route("/roll", methods=["GET", "POST"])
@admin_required
def roll():
    errors = []
    added = None
    if request.method == "POST":
        rows, errors = parse_roll(request.form.get("roll", ""))
        if rows and not errors:
            with transaction() as db:
                before = db.execute("SELECT COUNT(*) FROM voter_roll").fetchone()[0]
                db.executemany(
                    "INSERT OR IGNORE INTO voter_roll (student_id, full_name) VALUES (?, ?)", rows
                )
                after = db.execute("SELECT COUNT(*) FROM voter_roll").fetchone()[0]
                added = after - before
                audit("roll_uploaded", f"added={added}", g.user["id"])
            flash(f"Added {added} new student(s). Existing IDs were left unchanged.", "ok")
        elif not rows and not errors:
            errors = ["Paste at least one line."]
    db = get_db()
    counts = {
        "total": db.execute("SELECT COUNT(*) FROM voter_roll").fetchone()[0],
        "claimed": db.execute("SELECT COUNT(*) FROM voter_roll WHERE claimed = 1").fetchone()[0],
    }
    return render_template("admin/roll.html", errors=errors[:20], counts=counts)


@bp.get("/audit")
@admin_required
def audit_log():
    ok, bad_id = verify_audit_chain()
    rows = get_db().execute(
        """SELECT a.*, u.email FROM audit_log a LEFT JOIN users u ON u.id = a.actor_id
           ORDER BY a.id DESC LIMIT 200"""
    ).fetchall()
    return render_template("admin/audit.html", rows=rows, chain_ok=ok, bad_id=bad_id)
