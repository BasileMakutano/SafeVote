import pytest

from app import create_app
from app.db import get_db, transaction
from app.security import hash_password, iso, utcnow

VOTE = "http://vote.lvh.me"
ADMIN = "http://admin.lvh.me"
RESULTS = "http://results.lvh.me"
PASSWORD = "Correct-horse-42"


@pytest.fixture
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "DATABASE_PATH": str(tmp_path / "test.db"),
        "SERVER_NAME": "lvh.me",
        "PREFERRED_URL_SCHEME": "http",
        "SESSION_COOKIE_NAME": "sv",
        "SESSION_COOKIE_SECURE": False,
        "WTF_CSRF_ENABLED": False,
    })
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def add_roll(app, *ids):
    with app.app_context(), transaction() as db:
        for sid in ids:
            db.execute("INSERT INTO voter_roll (student_id, full_name) VALUES (?, ?)", (sid, f"Student {sid}"))


def add_user(app, email, role="voter", sid=None, password=PASSWORD):
    with app.app_context(), transaction() as db:
        db.execute(
            "INSERT INTO users (student_id, email, full_name, password_hash, role, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (sid or email.split("@")[0].upper() + "01", email, "Test Person", hash_password(password), role, iso(utcnow())),
        )


def make_election(app, state="open", candidates=("Alice", "Bob")):
    """state: draft | open | closed"""
    from datetime import timedelta
    now = utcnow()
    opens, closes = now - timedelta(hours=2), now + timedelta(hours=2)
    if state == "closed":
        closes = now - timedelta(minutes=5)
    with app.app_context(), transaction() as db:
        cur = db.execute(
            "INSERT INTO elections (title, opens_at, closes_at, launched, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Council", iso(opens), iso(closes), 0 if state == "draft" else 1, iso(now)),
        )
        eid = cur.lastrowid
        for name in candidates:
            db.execute("INSERT INTO candidates (election_id, name) VALUES (?, ?)", (eid, name))
        ids = [r[0] for r in db.execute("SELECT id FROM candidates WHERE election_id = ? ORDER BY id", (eid,))]
    return eid, ids


def login(client, base, email, password=PASSWORD):
    return client.post("/login", data={"email": email, "password": password}, base_url=base)
