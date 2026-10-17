"""Shared SQLite schema. Everyone opens the DB through connect() so the tables
always exist and WAL mode lets the API read while the consumer writes."""
import os
import sqlite3

DEFAULT_DB = os.environ.get("SCAM_DB", "data/scamouflage.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    cert_id    TEXT NOT NULL,          -- sha256 of the leaf cert (lowercase hex), "sn:..." for empty-DER precerts
    domain     TEXT NOT NULL,          -- the domain that triggered the alert
    domains    TEXT,                   -- JSON list: all domains on the cert
    score      REAL NOT NULL,
    reasons    TEXT,                   -- JSON list of strings
    seen_at    REAL NOT NULL,          -- unix seconds when the log entry was seen
    issuer     TEXT,
    log        TEXT,
    verify     TEXT,                   -- ok | fail | unknown_issuer
    crtsh_url  TEXT,
    sig        TEXT,
    key_id     TEXT
);
CREATE INDEX IF NOT EXISTS alerts_seen ON alerts(seen_at);
CREATE INDEX IF NOT EXISTS alerts_domain ON alerts(domain);

CREATE TABLE IF NOT EXISTS labels (
    domain     TEXT NOT NULL,
    feed       TEXT NOT NULL,          -- phishingdb | phishunt | openphish | unit42
    first_seen REAL,                   -- unix seconds, NULL if feed has no date
    brand      TEXT,
    PRIMARY KEY (domain, feed)
);

CREATE TABLE IF NOT EXISTS seen (
    domain          TEXT PRIMARY KEY,
    first_cert_seen REAL NOT NULL,     -- first time WE saw a cert for it
    cert_id         TEXT
);
"""

# Engine Decision fields on every alert (model/engine.py DECISION_FIELDS minus host/domain:
# `domain` above already holds the decision's host). Added with ALTER TABLE so existing DBs keep
# their rows; NULL on rows written before the engine or by `--no-engine`.
DECISION_COLUMNS = (
    ("verdict", "TEXT"),          # scam (only scams are saved)
    ("stage", "INTEGER"),         # 0 known list, 2 scored (Stage 3 gave no answer), 3 verified
    ("s1", "REAL"),               # Stage 1 name score
    ("s2_boost", "REAL"),         # Stage 2 certificate boost
    ("brand", "TEXT"),
    ("category", "TEXT"),         # toll | delivery | gov | other
    ("verified", "INTEGER"),      # 1 if Stage 3 (RDAP) answered
    ("age_days", "REAL"),         # domain age from RDAP
    ("registrar", "TEXT"),
    ("risky_registrar", "INTEGER"),
    ("model_version", "TEXT"),
    ("cert_seen_at", "TEXT"),     # ISO UTC
    ("decided_at", "TEXT"),       # ISO UTC
)


def migrate(con: sqlite3.Connection) -> None:
    """Add any missing Decision columns. Never drops or rebuilds the table."""
    have = {r[1] for r in con.execute("PRAGMA table_info(alerts)")}
    for name, typ in DECISION_COLUMNS:
        if name not in have:
            try:
                con.execute(f"ALTER TABLE alerts ADD COLUMN {name} {typ}")
            except sqlite3.OperationalError as e:  # another process added it first
                if "duplicate column" not in str(e):
                    raise
    con.execute("CREATE INDEX IF NOT EXISTS alerts_stage ON alerts(stage)")
    con.commit()


def connect(path: str = DEFAULT_DB) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    con = sqlite3.connect(path, timeout=30, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.executescript(SCHEMA)
    migrate(con)
    return con
