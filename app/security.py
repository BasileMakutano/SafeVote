"""Password hashing, sign-in throttling, sessions, access control, audit chain."""
import hashlib
from datetime import datetime, timedelta, timezone
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import abort, current_app, g, redirect, request, session, url_for

from .db import get_db, transaction

_ph = PasswordHasher()  # Argon2id with library defaults
_DUMMY_HASH = _ph.hash("not-a-real-password")  # equalises timing for unknown users
GENERIC_LOGIN_ERROR = "Invalid credentials, or the account is temporarily locked."
GENESIS = "0" * 64


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat(timespec="seconds")


def parse_iso(value):
    return datetime.fromisoformat(value)


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- passwords
def hash_password(password):
    return _ph.hash(password)


def verify_password(stored_hash, password):
    try:
        return _ph.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


# ---------------------------------------------------------------- throttling
def throttle_hit(key, limit, window_seconds):
    """Record one attempt. Returns True when the caller is over the limit."""
    now = utcnow()
    with transaction() as db:
        row = db.execute(
            "SELECT count, reset_at FROM throttle WHERE key = ?", (key,)
        ).fetchone()
        if row is None or parse_iso(row["reset_at"]) <= now:
            db.execute(
                "INSERT OR REPLACE INTO throttle (key, count, reset_at) VALUES (?, 1, ?)",
                (key, iso(now + timedelta(seconds=window_seconds))),
            )
            return False
        db.execute("UPDATE throttle SET count = count + 1 WHERE key = ?", (key,))
        return row["count"] + 1 > limit


# ---------------------------------------------------------------- audit log
def _append_audit(db, action, detail, actor_id):
    row = db.execute(
        "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = row["entry_hash"] if row else GENESIS
    ts = iso(utcnow())
    entry_hash = sha256_hex(f"{prev_hash}|{ts}|{actor_id}|{action}|{detail}")
    db.execute(
        "INSERT INTO audit_log (ts, actor_id, action, detail, prev_hash, entry_hash)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (ts, actor_id, action, detail, prev_hash, entry_hash),
    )


def audit(action, detail="", actor_id=None):
    db = get_db()
    if db.in_transaction:
        _append_audit(db, action, detail, actor_id)
    else:
        with transaction():
            _append_audit(db, action, detail, actor_id)


def verify_audit_chain():
    """Returns (ok, first_bad_id)."""
    prev = GENESIS
    for row in get_db().execute("SELECT * FROM audit_log ORDER BY id"):
        expected = sha256_hex(
            f"{row['prev_hash']}|{row['ts']}|{row['actor_id']}|{row['action']}|{row['detail']}"
        )
        if row["prev_hash"] != prev or row["entry_hash"] != expected:
            return False, row["id"]
        prev = row["entry_hash"]
    return True, None


# ---------------------------------------------------------------- sign-in
def attempt_login(email, password, role):
    """Returns (user_row, None) on success or (None, message) on failure.
    One generic message for every failure so accounts cannot be enumerated."""
    cfg = current_app.config
    ip = request.remote_addr or "unknown"
    if throttle_hit(f"login:ip:{ip}", 30, 600):
        return None, "Too many sign-in attempts from this network. Try again in a few minutes."

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    now = utcnow()

    if user is None or user["role"] != role:
        verify_password(_DUMMY_HASH, password)
        audit("login_failed", "unknown account")
        return None, GENERIC_LOGIN_ERROR

    if user["locked_until"] and parse_iso(user["locked_until"]) > now:
        verify_password(_DUMMY_HASH, password)
        audit("login_blocked", "account locked", actor_id=user["id"])
        return None, GENERIC_LOGIN_ERROR

    if not verify_password(user["password_hash"], password):
        with transaction() as tx:
            tx.execute(
                "UPDATE users SET failed_logins = failed_logins + 1 WHERE id = ?",
                (user["id"],),
            )
            fails = tx.execute(
                "SELECT failed_logins FROM users WHERE id = ?", (user["id"],)
            ).fetchone()[0]
            if fails >= cfg["MAX_FAILED_LOGINS"]:
                until = iso(now + timedelta(minutes=cfg["LOCKOUT_MINUTES"]))
                tx.execute(
                    "UPDATE users SET failed_logins = 0, locked_until = ? WHERE id = ?",
                    (until, user["id"]),
                )
                audit("account_locked", f"until {until}", actor_id=user["id"])
            audit("login_failed", "bad password", actor_id=user["id"])
        return None, GENERIC_LOGIN_ERROR

    new_hash = user["password_hash"]
    if _ph.check_needs_rehash(new_hash):
        new_hash = _ph.hash(password)
    with transaction() as tx:
        tx.execute(
            "UPDATE users SET failed_logins = 0, locked_until = NULL, password_hash = ?"
            " WHERE id = ?",
            (new_hash, user["id"]),
        )
        audit("login_ok", actor_id=user["id"])
    return user, None


# ---------------------------------------------------------------- sessions
def login_user(user):
    session.clear()  # new session on every sign-in (prevents fixation)
    session["uid"] = user["id"]
    session["iat"] = int(utcnow().timestamp())
    session.permanent = True  # idle timeout = PERMANENT_SESSION_LIFETIME


def logout_user():
    session.clear()


def load_user():
    g.user = None
    uid = session.get("uid")
    if uid is None:
        return
    max_age = current_app.config["ABSOLUTE_SESSION_HOURS"] * 3600
    if utcnow().timestamp() - session.get("iat", 0) > max_age:
        session.clear()
        return
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if row is None:
        session.clear()
        return
    g.user = row


def _guard(role, login_endpoint):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for(login_endpoint))
            if g.user["role"] != role:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


voter_required = _guard("voter", "vote.login")
admin_required = _guard("admin", "admin.login")
