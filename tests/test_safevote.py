import re

from app import create_app
from app.db import get_db, transaction
from app.elections import cast_vote, publish_results
from app.security import verify_audit_chain
from tests.conftest import ADMIN, PASSWORD, RESULTS, VOTE, add_roll, add_user, login, make_election


# ------------------------------------------------------------ passwords / registration
def test_password_is_stored_as_argon2id_hash(app, client):
    add_roll(app, "S1001")
    r = client.post("/register", base_url=VOTE, data={
        "student_id": "s1001", "email": "a@uni.ac.ke", "password": PASSWORD, "confirm": PASSWORD})
    assert r.status_code == 302
    with app.app_context():
        stored = get_db().execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored.startswith("$argon2id$") and PASSWORD not in stored


def test_registration_requires_roll_and_is_single_use(app, client):
    data = {"student_id": "S2002", "email": "b@uni.ac.ke", "password": PASSWORD, "confirm": PASSWORD}
    assert b"could not complete" in client.post("/register", base_url=VOTE, data=data).data
    add_roll(app, "S2002")
    assert client.post("/register", base_url=VOTE, data=data).status_code == 302
    again = dict(data, email="c@uni.ac.ke")
    assert b"could not complete" in client.post("/register", base_url=VOTE, data=again).data


def test_weak_and_invalid_input_rejected(app, client):
    add_roll(app, "S3003")
    base = {"student_id": "S3003", "email": "d@uni.ac.ke", "password": PASSWORD, "confirm": PASSWORD}
    for bad, needle in [
        ({"password": "short1", "confirm": "short1"}, b"at least 10"),
        ({"password": "onlyletterspassword", "confirm": "onlyletterspassword"}, b"letter and a number"),
        ({"confirm": "Different-pass-42"}, b"do not match"),
        ({"email": "not-an-email"}, b"valid email"),
        ({"student_id": "a b!"}, b"Student ID must be"),
    ]:
        r = client.post("/register", base_url=VOTE, data={**base, **bad})
        assert r.status_code == 200 and needle in r.data, bad


# ------------------------------------------------------------ sign-in
def test_login_errors_are_generic_and_account_locks(app, client):
    add_user(app, "v@uni.ac.ke")
    unknown = login(client, VOTE, "nobody@uni.ac.ke", "whatever-12345")
    wrong = login(client, VOTE, "v@uni.ac.ke", "wrong-pass-123")
    assert unknown.status_code == wrong.status_code == 401
    assert re.search(rb"Invalid credentials", unknown.data) and re.search(rb"Invalid credentials", wrong.data)
    for _ in range(5):
        login(client, VOTE, "v@uni.ac.ke", "wrong-pass-123")
    locked = login(client, VOTE, "v@uni.ac.ke", PASSWORD)  # correct password, still locked
    assert locked.status_code == 401


def test_admin_and_voter_logins_are_separate(app, client):
    add_user(app, "adm@uni.ac.ke", role="admin")
    add_user(app, "vot@uni.ac.ke", role="voter")
    assert login(client, VOTE, "adm@uni.ac.ke").status_code == 401
    assert login(client, ADMIN, "vot@uni.ac.ke").status_code == 401
    assert login(client, ADMIN, "adm@uni.ac.ke").status_code == 302


def test_protected_pages_redirect_when_signed_out(client):
    assert client.get("/", base_url=VOTE).headers["Location"].endswith("/login")
    assert client.get("/", base_url=ADMIN).headers["Location"].endswith("/login")
    assert client.get("/audit", base_url=ADMIN).status_code == 302


def test_voter_session_does_not_reach_admin_subdomain(app, client):
    add_user(app, "vot@uni.ac.ke")
    login(client, VOTE, "vot@uni.ac.ke")
    assert client.get("/", base_url=VOTE).status_code == 200
    assert client.get("/", base_url=ADMIN).status_code == 302  # host-only cookie, not signed in there


# ------------------------------------------------------------ voting
def test_vote_flow_and_double_vote_blocked(app, client):
    add_user(app, "vot@uni.ac.ke")
    eid, cands = make_election(app)
    login(client, VOTE, "vot@uni.ac.ke")
    review = client.post(f"/elections/{eid}/review", base_url=VOTE, data={"candidate_id": cands[0]})
    assert review.status_code == 200 and b"Cast my vote" in review.data
    cast = client.post(f"/elections/{eid}/cast", base_url=VOTE, data={"candidate_id": cands[0]})
    code = re.search(rb"([0-9A-F]{4}(?:-[0-9A-F]{4}){5})", cast.data)
    assert code, cast.data
    second = client.post(f"/elections/{eid}/cast", base_url=VOTE, data={"candidate_id": cands[1]}, follow_redirects=True)
    assert b"already voted" in second.data
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM ballots").fetchone()[0] == 1


def test_cannot_vote_when_draft_closed_or_invalid_candidate(app, client):
    add_user(app, "vot@uni.ac.ke")
    login(client, VOTE, "vot@uni.ac.ke")
    draft, dc = make_election(app, "draft")
    assert client.get(f"/elections/{draft}", base_url=VOTE).status_code == 404
    closed, cc = make_election(app, "closed")
    r = client.post(f"/elections/{closed}/cast", base_url=VOTE, data={"candidate_id": cc[0]}, follow_redirects=True)
    assert b"not open" in r.data
    live, lc = make_election(app)
    r = client.post(f"/elections/{live}/cast", base_url=VOTE, data={"candidate_id": cc[0]}, follow_redirects=True)
    assert b"listed candidates" in r.data
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM ballots").fetchone()[0] == 0


def test_ballots_are_not_linked_to_voters(app):
    with app.app_context():
        cols = [r["name"] for r in get_db().execute("PRAGMA table_info(ballots)")]
    assert cols == ["ballot_id", "election_id", "candidate_id", "receipt_hash"]


# ------------------------------------------------------------ results and verification
def _vote_n(app, eid, cid_list):
    receipts = []
    with app.test_request_context(base_url=VOTE):
        for i, cid in enumerate(cid_list):
            add_user(app, f"u{i}@uni.ac.ke", sid=f"U{i:04d}")
            uid = get_db().execute("SELECT id FROM users WHERE email = ?", (f"u{i}@uni.ac.ke",)).fetchone()[0]
            receipts.append(cast_vote(eid, uid, cid))
    return receipts


def test_results_hidden_until_published_then_verifiable(app, client):
    eid, cands = make_election(app)
    receipts = _vote_n(app, eid, [cands[0], cands[0], cands[1]])
    with app.app_context(), transaction() as db:  # close the election
        db.execute("UPDATE elections SET closes_at = '2000-01-01T00:00:00+00:00', opens_at = '1999-01-01T00:00:00+00:00' WHERE id = ?", (eid,))
    assert client.get(f"/election/{eid}", base_url=RESULTS).status_code == 404
    assert client.post("/verify", base_url=RESULTS, data={"receipt": receipts[0]}).data.count(b"was counted") == 0

    with app.test_request_context(base_url=ADMIN):
        publish_results(eid, None)

    page = client.get(f"/election/{eid}", base_url=RESULTS)
    assert page.status_code == 200 and b"3 ballots counted" in page.data
    assert b"Alice" in page.data and b"2 (66.7%)" in page.data
    assert b"still matches" in page.data and b"match the number of voters" in page.data

    ok = client.post("/verify", base_url=RESULTS, data={"receipt": receipts[2].lower()})
    assert b"was counted" in ok.data and b"Bob" in ok.data
    bad = client.post("/verify", base_url=RESULTS, data={"receipt": "0" * 24})
    assert b"No match found" in bad.data


def test_digest_detects_tampering(app, client):
    eid, cands = make_election(app)
    _vote_n(app, eid, [cands[0], cands[1]])
    with app.app_context(), transaction() as db:
        db.execute("UPDATE elections SET closes_at = '2000-01-01T00:00:00+00:00', opens_at = '1999-01-01T00:00:00+00:00' WHERE id = ?", (eid,))
    with app.test_request_context(base_url=ADMIN):
        publish_results(eid, None)
    with app.app_context(), transaction() as db:
        db.execute("UPDATE ballots SET candidate_id = ? WHERE election_id = ?", (cands[1], eid))
    page = client.get(f"/election/{eid}", base_url=RESULTS)
    assert b"no longer matches" in page.data


# ------------------------------------------------------------ audit log
def test_audit_chain_verifies_and_detects_edits(app, client):
    add_user(app, "vot@uni.ac.ke")
    login(client, VOTE, "vot@uni.ac.ke")
    login(client, VOTE, "vot@uni.ac.ke", "wrong-pass-123")
    with app.app_context():
        assert verify_audit_chain() == (True, None)
        with transaction() as db:
            db.execute("UPDATE audit_log SET detail = 'edited' WHERE id = 1")
        ok, bad = verify_audit_chain()
        assert not ok and bad == 1


# ------------------------------------------------------------ platform security
def test_security_headers_present(client):
    r = client.get("/login", base_url=VOTE)
    csp = r.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "script" not in csp.replace("default-src 'none'", "")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Cache-Control"] == "no-store"


def test_csrf_is_enforced(tmp_path):
    app = create_app({
        "TESTING": True, "SECRET_KEY": "k", "DATABASE_PATH": str(tmp_path / "c.db"),
        "SERVER_NAME": "lvh.me", "SESSION_COOKIE_NAME": "sv", "SESSION_COOKIE_SECURE": False,
    })
    r = app.test_client().post("/login", base_url=VOTE, data={"email": "a@b.co", "password": "x"})
    assert r.status_code == 400 and b"Form expired" in r.data


def test_xss_is_escaped(app, client):
    add_user(app, "adm@uni.ac.ke", role="admin")
    login(client, ADMIN, "adm@uni.ac.ke")
    with app.app_context(), transaction() as db:
        db.execute("INSERT INTO elections (title, opens_at, closes_at, created_at) VALUES ('<script>alert(1)</script>', '2030-01-01T00:00:00+00:00', '2030-01-02T00:00:00+00:00', '2026-01-01T00:00:00+00:00')")
    page = client.get("/", base_url=ADMIN)
    assert b"<script>alert(1)</script>" not in page.data and b"&lt;script&gt;" in page.data


def test_unknown_host_and_apex(client):
    assert client.get("/", base_url="http://evil.lvh.me").status_code == 404
    assert client.get("/", base_url="http://lvh.me").status_code == 200
    assert client.get("/healthz", base_url="http://lvh.me").data == b"ok"
