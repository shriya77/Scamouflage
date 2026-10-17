"""Shared SQLite schema. Everyone opens the DB through connect() so the tables
always exist and WAL mode lets the API read while the consumer writes."""
import os
import sqlite3

DEFAULT_DB = os.environ.get("SCAM_DB", "data/scamouflage.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    cert_id    TEXT NOT NULL,          -- sha256 of the leaf cert (lowercase hex)
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


def connect(path: str = DEFAULT_DB) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    con = sqlite3.connect(path, timeout=30, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.executescript(SCHEMA)
    return con
