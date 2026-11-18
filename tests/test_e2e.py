"""Full browser-like journey with CSRF enabled, driving real forms."""
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from app import create_app
from tests.conftest import ADMIN, PASSWORD, RESULTS, VOTE


def token(html):
    return re.search(rb'name="csrf_token" value="([^"]+)"', html).group(1).decode()


def post(client, base, path, data, page=None):
    t = token(client.get(page or path, base_url=base).data)
    return client.post(path, base_url=base, data={**data, "csrf_token": t})


def test_full_journey(tmp_path):
    app = create_app({"TESTING": True, "SECRET_KEY": "k", "DATABASE_PATH": str(tmp_path / "e.db"),
                      "SERVER_NAME": "lvh.me", "SESSION_COOKIE_NAME": "sv", "SESSION_COOKIE_SECURE": False})
    runner = app.test_cli_runner()
    r = runner.invoke(args=["create-admin", "--email", "office@uni.ac.ke", "--name", "Election Office",
                            "--password", PASSWORD], input=PASSWORD + "\n")
    assert r.exit_code == 0, r.output

    admin, voter, public = app.test_client(), app.test_client(), app.test_client()
    assert post(admin, ADMIN, "/login", {"email": "office@uni.ac.ke", "password": PASSWORD}).status_code == 302

    post(admin, ADMIN, "/roll", {"roll": "S1001,Amani Njoroge\nS1002,Brian Otieno"})
    tz = ZoneInfo("Africa/Nairobi")
    now = datetime.now(tz)
    fmt = "%Y-%m-%dT%H:%M"
    created = post(admin, ADMIN, "/elections/new", {
        "title": "Council 2026", "description": "Test", "opens_at": (now - timedelta(hours=1)).strftime(fmt),
        "closes_at": (now + timedelta(hours=3)).strftime(fmt)})
    assert created.status_code == 302
    eid = int(created.headers["Location"].rstrip("/").split("/")[-1])
    page = f"/elections/{eid}"
    early = post(admin, ADMIN, f"{page}/launch", {}, page)
    assert b"Add at least two" in admin.get(page, base_url=ADMIN).data
    post(admin, ADMIN, f"{page}/candidates", {"name": "Alice A", "manifesto": "Wi-Fi"}, page)
    post(admin, ADMIN, f"{page}/candidates", {"name": "Bob B", "manifesto": ""}, page)
    post(admin, ADMIN, f"{page}/launch", {}, page)
    assert b"open" in admin.get(page, base_url=ADMIN).data

    for sid, mail in (("S1001", "a@uni.ac.ke"), ("S1002", "b@uni.ac.ke")):
        v = app.test_client()
        assert post(v, VOTE, "/register", {"student_id": sid, "email": mail, "password": PASSWORD, "confirm": PASSWORD}).status_code == 302
        assert post(v, VOTE, "/login", {"email": mail, "password": PASSWORD}).status_code == 302
        board = v.get(page, base_url=VOTE).data
        cid = re.search(rb'name="candidate_id" value="(\d+)"', board).group(1).decode()
        assert b"Cast my vote" in post(v, VOTE, f"{page}/review", {"candidate_id": cid}, page).data
        receipt = re.search(rb"([0-9A-F]{4}(?:-[0-9A-F]{4}){5})", post(v, VOTE, f"{page}/cast", {"candidate_id": cid}, page).data)
        assert receipt
    last_receipt = receipt.group(1).decode()

    post(admin, ADMIN, f"{page}/close", {}, page)
    post(admin, ADMIN, f"{page}/publish", {}, page)
    res = public.get(f"/election/{eid}", base_url=RESULTS)
    assert res.status_code == 200 and b"2 ballots counted" in res.data
    ver = post(public, RESULTS, "/verify", {"receipt": last_receipt})
    assert b"was counted" in ver.data
    assert b"The log's hash chain is intact" in admin.get("/audit", base_url=ADMIN).data
    csv = public.get(f"/election/{eid}/ballots.csv", base_url=RESULTS)
    assert csv.data.count(b"\n") == 3
