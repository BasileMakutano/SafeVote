from flask import Blueprint, Response, abort, flash, render_template, request

from ..db import get_db
from ..elections import (
    ballot_lines, election_state, find_ballot_by_receipt, get_election,
    integrity_report, results_visible, tally,
)
from ..security import throttle_hit

bp = Blueprint("results", __name__)


def _published_or_404(eid):
    e = get_election(eid)
    if e is None or not results_visible(e):
        abort(404)
    return e


@bp.get("/")
def index():
    rows = get_db().execute(
        "SELECT * FROM elections WHERE launched = 1 AND results_published = 1 ORDER BY closes_at DESC"
    ).fetchall()
    return render_template("results/index.html", elections=[r for r in rows if election_state(r) == "closed"])


@bp.get("/election/<int:eid>")
def election(eid):
    e = _published_or_404(eid)
    rows = tally(eid)
    names = {r["id"]: r["name"] for r in rows}
    board = ballot_lines(eid)
    report = integrity_report(e)
    return render_template(
        "results/election.html",
        e=e,
        rows=rows,
        total=sum(r["votes"] for r in rows),
        board=[{"hash": b["receipt_hash"], "candidate": names.get(b["candidate_id"], "?")} for b in board[:500]],
        board_size=len(board),
        report=report,
    )


@bp.get("/election/<int:eid>/ballots.csv")
def ballots_csv(eid):
    _published_or_404(eid)
    lines = "".join(f"{b['receipt_hash']},{b['candidate_id']}\n" for b in ballot_lines(eid))
    return Response(
        "receipt_hash,candidate_id\n" + lines,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=election-{eid}-ballots.csv"},
    )


@bp.route("/verify", methods=["GET", "POST"])
def verify():
    result, searched = None, False
    if request.method == "POST":
        searched = True
        if throttle_hit(f"verify:ip:{request.remote_addr}", 30, 600):
            flash("Too many lookups. Try again in a few minutes.", "error")
            searched = False
        else:
            result = find_ballot_by_receipt(request.form.get("receipt", ""))
    return render_template("results/verify.html", result=result, searched=searched)
