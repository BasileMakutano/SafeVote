CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  student_id TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'voter' CHECK (role IN ('voter', 'admin')),
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  created_at TEXT NOT NULL
);

-- Eligibility list uploaded by the election office. Registration is only
-- possible for a student ID on this list, and each ID can be claimed once.
CREATE TABLE IF NOT EXISTS voter_roll (
  student_id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  claimed INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS elections (
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  opens_at TEXT NOT NULL,
  closes_at TEXT NOT NULL,
  launched INTEGER NOT NULL DEFAULT 0,
  results_published INTEGER NOT NULL DEFAULT 0,
  tally_digest TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL,
  CHECK (closes_at > opens_at)
);

CREATE TABLE IF NOT EXISTS candidates (
  id INTEGER PRIMARY KEY,
  election_id INTEGER NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  manifesto TEXT NOT NULL DEFAULT ''
);

-- WHO has voted. Deliberately separate from WHAT was voted.
CREATE TABLE IF NOT EXISTS voter_status (
  election_id INTEGER NOT NULL REFERENCES elections(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  PRIMARY KEY (election_id, user_id)
) WITHOUT ROWID;

-- WHAT was voted. No user id, no timestamp, random primary key and
-- WITHOUT ROWID, so neither content nor storage order links a ballot to a voter.
CREATE TABLE IF NOT EXISTS ballots (
  ballot_id TEXT PRIMARY KEY,
  election_id INTEGER NOT NULL REFERENCES elections(id),
  candidate_id INTEGER NOT NULL REFERENCES candidates(id),
  receipt_hash TEXT NOT NULL UNIQUE
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_ballots_election ON ballots(election_id);

-- Tamper-evident log: every row hashes the previous row.
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor_id INTEGER,
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS throttle (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  reset_at TEXT NOT NULL
);
