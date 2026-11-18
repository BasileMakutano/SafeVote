# SafeVote

A secure student election system. Voters register against an official roll, cast one secret ballot, and receive a receipt code they can later check against the published results.

Built with Flask, SQLite and server-rendered HTML. The pages use no JavaScript at all, so the Content Security Policy can forbid scripts entirely.

## How it maps to the project requirements

| Requirement | Where it lives |
|---|---|
| Hosted in the cloud | `deploy/DEPLOY.md` (VM, systemd, nginx) |
| DNS and valid domain | `deploy/DEPLOY.md` section 2 |
| Subdomains | `vote.`, `admin.`, `results.` routed by `SERVER_NAME` in `app/__init__.py` |
| SSL certificate and HTTPS | `deploy/nginx.conf`, ZeroSSL steps in `deploy/DEPLOY.md`, HSTS header, Secure cookies |
| Passwords hashed securely | Argon2id in `app/security.py` |
| Input validation | HTML5 constraints in every form plus server checks in `app/validators.py` |
| Creative and innovative | Verifiable receipts, public ballot list with a SHA-256 fingerprint, tamper-evident audit log |
| Cohesive team | Clear module split (see layout below) so two people can work in parallel |

## Run it locally

    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements-dev.txt
    cp .env.example .env
    python -c "import secrets; print(secrets.token_hex(32))"   # paste into SECRET_KEY in .env
    flask --app wsgi create-admin
    flask --app wsgi seed-demo
    flask --app wsgi run

Then open:

- http://lvh.me:5000 for the landing page
- http://vote.lvh.me:5000 to register and vote (demo student IDs `DEMO0001` to `DEMO0010`)
- http://admin.lvh.me:5000 for the election office
- http://results.lvh.me:5000 for results and receipt checks

`lvh.me` and every subdomain of it point to 127.0.0.1, so subdomains work locally without editing your hosts file. If you are offline, add `127.0.0.1 vote.lvh.me admin.lvh.me results.lvh.me lvh.me` to your hosts file.

Run the tests with `pytest`.

## Demo script (about five minutes)

1. Admin: sign in, add students on the Voter roll page, create an election, add two candidates, launch it.
2. Voter: register with a roll ID, sign in, choose a candidate, review, cast. Copy the receipt code.
3. Try to vote again. The app refuses, and the database key would refuse even if the app did not.
4. Admin: close voting, publish results.
5. Results site: see the tally and integrity checks, then paste the receipt on the Check a receipt page.
6. Admin: open the Audit log and show the intact hash chain.

## Security design

**Accounts.** Argon2id hashes. Generic sign-in errors, with a dummy hash check for unknown emails so timing does not reveal which accounts exist. Five failed attempts lock the account for 15 minutes. A per-IP limit applies as well, and nginx adds a rate limit on `/login`.

**Sessions.** A fresh session on every sign-in, 30 minute idle timeout, 4 hour absolute limit. Cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` with the `__Host-` prefix in production. Cookies are host-only, so the admin session never exists on the voter subdomain.

**Forms.** CSRF tokens on every POST. Parameterised SQL everywhere. Jinja auto-escaping for all output. Validation runs on the server for every field.

**Browser hardening.** CSP with `default-src 'none'` (no scripts, a nonce for the one inline stylesheet), HSTS in production, `X-Frame-Options: DENY`, `nosniff`, no referrer, `no-store` caching.

**Eligibility.** Only student IDs on the roll can register, and each ID can be claimed once.

**One vote each.** `voter_status` has a primary key of (election, user). Marking a voter and storing the ballot happen in one `BEGIN IMMEDIATE` transaction, so even simultaneous requests cannot both succeed.

**Ballot secrecy.** Ballots live in a separate table with no user id and no timestamp, a random primary key, and `WITHOUT ROWID` storage so insertion order is not preserved. The audit log records that someone voted, never for whom.

**Verifiability.** The voter gets a random 96-bit receipt code. The server stores only its SHA-256. After results are published, the public ballot list (receipt fingerprint plus candidate, sorted by fingerprint) can be downloaded, and its SHA-256 matches the fingerprint recorded at publication. Anyone can recount from the CSV.

**Audit log.** Each entry hashes the one before it. The admin page re-verifies the chain on every view.

## Known limitations (state these honestly in your report)

- **Receipts and coercion.** A receipt shows which candidate it counted for, which lets a voter check their ballot but also lets someone prove their vote to a person pressuring them. Real elections must choose; this project favours verifiability and says so on the page.
- **No email verification.** Identity rests on the roll. Adding email confirmation needs an SMTP service.
- **Trusted administrator.** The election office controls the roll and publishes results. The audit log and fingerprint make tampering detectable, not impossible.
- **Audit log truncation.** The chain detects edits and removals in the middle of the log, but cutting off the newest entries is not detectable without external anchoring (for example, emailing the latest hash).
- **SQLite.** Suitable for a campus election on one server. Move to PostgreSQL for several servers.
- **Votes are not end-to-end encrypted.** An attacker with database and server access could read ballots, though not link them to voters by storage order.

## Layout

    app/
      __init__.py       app factory, headers, error pages
      security.py       hashing, throttling, sessions, audit chain
      elections.py      states, voting transaction, tally, receipts
      accounts.py       roll-checked registration
      validators.py     server-side validation
      blueprints/       vote.py, admin.py, results.py, landing.py
      templates/        server-rendered pages
      assets/style.css  inlined into each page
    tests/              unit tests and a full CSRF-enabled journey
    deploy/             nginx, systemd, step-by-step guide
