"""Election domain logic: states, voting, tallying, publishing, receipts."""
import hashlib
import secrets
import sqlite3
from datetime import timedelta

from .db import get_db, transaction
from .security import audit, iso, parse_iso, sha256_hex, utcnow


class ElectionError(Exception):
    """A user-presentable rule violation."""


def election_state(e, now=None):
    if not e["launched"]:
        return "draft"
    now = now or utcnow()
    if now < parse_iso(e["opens_at"]):
        return "upcoming"
    if now >= parse_iso(e["closes_at"]):
        return "closed"
    return "open"


def get_election(eid):
    return get_db().execute("SELECT * FROM elections WHERE id = ?", (eid,)).fetchone()


def get_candidates(eid):
    return get_db().execute(
        "SELECT * FROM candidates WHERE election_id = ? ORDER BY name", (eid,)
    ).fetchall()


def results_visible(e):
    return bool(e["results_published"]) and election_state(e) == "closed"


# ------------------------------------------------------------- lifecycle
def launch_election(eid, actor_id):
    with transaction() as db:
        e = get_election(eid)
        if e is None or e["launched"]:
            raise ElectionError("This election cannot be launched.")
        n = db.execute(
            "SELECT COUNT(*) FROM candidates WHERE election_id = ?", (eid,)
        ).fetchone()[0]
        if n < 2:
            raise ElectionError("Add at least two candidates before launching.")
        if parse_iso(e["closes_at"]) <= utcnow():
            raise ElectionError("The closing time has already passed.")
        db.execute("UPDATE elections SET launched = 1 WHERE id = ?", (eid,))
        audit("election_launched", f"election={eid}", actor_id)


def close_now(eid, actor_id):
    with transaction() as db:
        e = get_election(eid)
        if e is None or election_state(e) != "open":
            raise ElectionError("Only an open election can be closed.")
        floor = parse_iso(e["opens_at"]) + timedelta(seconds=1)
        closes = max(utcnow(), floor)
        db.execute("UPDATE elections SET closes_at = ? WHERE id = ?", (iso(closes), eid))
        audit("election_closed_early", f"election={eid}", actor_id)


def publish_results(eid, actor_id):
    with transaction() as db:
        e = get_election(eid)
        if e is None or election_state(e) != "closed":
            raise ElectionError("Results can be published only after the election has closed.")
        if e["results_published"]:
            raise ElectionError("Results are already published.")
        digest = compute_digest(eid)
        db.execute(
            "UPDATE elections SET results_published = 1, tally_digest = ? WHERE id = ?",
            (digest, eid),
        )
        audit("results_published", f"election={eid} digest={digest[:16]}", actor_id)


# ------------------------------------------------------------- voting
def has_voted(eid, user_id):
    return (
        get_db()
        .execute(
            "SELECT 1 FROM voter_status WHERE election_id = ? AND user_id = ?",
            (eid, user_id),
        )
        .fetchone()
        is not None
    )


def normalise_receipt(code):
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def format_receipt(code):
    return "-".join(code[i : i + 4] for i in range(0, len(code), 4))


def cast_vote(eid, user_id, candidate_id):
    """Atomically mark the voter as having voted AND store an anonymous ballot.
    The unique key on voter_status is what enforces one vote per person, even
    under concurrent requests."""
    with transaction() as db:
        e = get_election(eid)
        if e is None or election_state(e) != "open":
            raise ElectionError("This election is not open for voting.")
        ok = db.execute(
            "SELECT 1 FROM candidates WHERE id = ? AND election_id = ?",
            (candidate_id, eid),
        ).fetchone()
        if ok is None:
            raise ElectionError("Choose one of the listed candidates.")
        try:
            db.execute(
                "INSERT INTO voter_status (election_id, user_id) VALUES (?, ?)",
                (eid, user_id),
            )
        except sqlite3.IntegrityError:
            raise ElectionError("You have already voted in this election.") from None
        code = secrets.token_hex(12).upper()  # 96 bits of entropy
        db.execute(
            "INSERT INTO ballots (ballot_id, election_id, candidate_id, receipt_hash)"
            " VALUES (?, ?, ?, ?)",
            (secrets.token_hex(16), eid, candidate_id, sha256_hex(code)),
        )
        audit("vote_cast", f"election={eid}", user_id)  # who voted, never for whom
    return format_receipt(code)


# ------------------------------------------------------------- results
def tally(eid):
    return get_db().execute(
        """SELECT c.id, c.name, c.manifesto, COUNT(b.ballot_id) AS votes
           FROM candidates c LEFT JOIN ballots b ON b.candidate_id = c.id
           WHERE c.election_id = ? GROUP BY c.id ORDER BY votes DESC, c.name""",
        (eid,),
    ).fetchall()


def ballot_lines(eid):
    """Published bulletin board: sorted by receipt hash so order reveals nothing."""
    return get_db().execute(
        "SELECT receipt_hash, candidate_id FROM ballots WHERE election_id = ?"
        " ORDER BY receipt_hash",
        (eid,),
    ).fetchall()


def compute_digest(eid):
    h = hashlib.sha256()
    for row in ballot_lines(eid):
        h.update(f"{row['receipt_hash']},{row['candidate_id']}\n".encode("ascii"))
    return h.hexdigest()


def integrity_report(e):
    db = get_db()
    ballots = db.execute(
        "SELECT COUNT(*) FROM ballots WHERE election_id = ?", (e["id"],)
    ).fetchone()[0]
    voters = db.execute(
        "SELECT COUNT(*) FROM voter_status WHERE election_id = ?", (e["id"],)
    ).fetchone()[0]
    registered = db.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'voter'"
    ).fetchone()[0]
    return {
        "ballots": ballots,
        "voters": voters,
        "registered": registered,
        "counts_match": ballots == voters,
        "digest": e["tally_digest"],
        "digest_ok": bool(e["tally_digest"]) and compute_digest(e["id"]) == e["tally_digest"],
    }


def find_ballot_by_receipt(code):
    """Look a receipt up among PUBLISHED elections only."""
    normalised = normalise_receipt(code)
    if len(normalised) != 24:
        return None
    db = get_db()
    row = db.execute(
        """SELECT b.election_id, b.receipt_hash, c.name AS candidate, e.title
           FROM ballots b
           JOIN elections e ON e.id = b.election_id
           JOIN candidates c ON c.id = b.candidate_id
           WHERE b.receipt_hash = ? AND e.results_published = 1""",
        (sha256_hex(normalised),),
    ).fetchone()
    if row is None:
        return None
    position = db.execute(
        "SELECT COUNT(*) FROM ballots WHERE election_id = ? AND receipt_hash < ?",
        (row["election_id"], row["receipt_hash"]),
    ).fetchone()[0] + 1
    total = db.execute(
        "SELECT COUNT(*) FROM ballots WHERE election_id = ?", (row["election_id"],)
    ).fetchone()[0]
    return {**dict(row), "position": position, "total": total}
