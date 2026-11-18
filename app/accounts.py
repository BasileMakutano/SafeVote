import sqlite3

from .db import transaction
from .security import audit, hash_password, iso, utcnow


def register_voter(student_id, email, password):
    """Create a voter account if the student ID is on the unclaimed roll.
    Returns the new user id, or None (one reason for every failure)."""
    pw_hash = hash_password(password)  # slow hash computed outside the write lock
    with transaction() as db:
        roll = db.execute(
            "SELECT * FROM voter_roll WHERE student_id = ?", (student_id,)
        ).fetchone()
        if roll is None or roll["claimed"]:
            return None
        try:
            cur = db.execute(
                "INSERT INTO users (student_id, email, full_name, password_hash, role, created_at)"
                " VALUES (?, ?, ?, ?, 'voter', ?)",
                (student_id, email, roll["full_name"], pw_hash, iso(utcnow())),
            )
        except sqlite3.IntegrityError:
            return None
        db.execute("UPDATE voter_roll SET claimed = 1 WHERE student_id = ?", (student_id,))
        audit("voter_registered", f"user={cur.lastrowid}", cur.lastrowid)
        return cur.lastrowid
