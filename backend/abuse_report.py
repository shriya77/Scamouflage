"""Abuse dispatcher: turn a Scamouflage alert into an abuse report for the domain's registrar.

What it does
    1. Looks up the registrar's *abuse contact* over RDAP. Stage 3 only stores the registrar's
       name ("NameSilo, LLC"); the abuse mailbox (abuse@namesilo.com) sits in the RDAP record as
       an entity with role "abuse" nested under the registrar entity. gTLD registrars must
       publish it (ICANN RDAP Response Profile 2.1.3 / RAA 3.18), ccTLDs often don't.
    2. Builds the report: a plain-text e-mail a human abuse desk can act on, plus a JSON
       attachment (the signed alert itself, so the registrar can verify we didn't make it up).
    3. Depending on SCAM_ABUSE_MODE:
         off      the routes answer 503, nothing is built or sent
         preview  (default) builds the report and returns it; the dashboard offers
                  "Open in mail app" (mailto:) and "Copy". Nothing leaves the server.
         send     also sends it from the server over SMTP when the request says send=true.
    4. Every report (preview, mailto hand-off, sent, failed) is logged in its own SQLite file
       (DATA_DIR/takedowns.db) so the dashboard can show "Reported 2 h ago" and so the same
       domain isn't reported twice in a day.

Who may call it
    Port 8000 is open to the internet and these routes *act*, so everything except
    GET /api/abuse/config is operator-only: the caller must come from loopback (operators reach
    the API through the SSH tunnel, so their peer address on the VM is 127.0.0.1) or send
    `X-Scamouflage-Token: <SCAM_ABUSE_TOKEN>` (compared with hmac.compare_digest). Anyone else
    gets 403. The dashboard still shows the button, labelled "operator only".

What may be reported
    - Only alerts that exist in the alerts DB. Contact lookups take a hostname and refuse it
      unless an alert carries it, so a stranger can't use us to query RDAP for arbitrary names.
    - Only high-confidence alerts: score >= the blocklist threshold (0.85, the same THRESHOLD as
      backend/blocklist_route.py; SCAM_ABUSE_MIN_SCORE overrides) and either Stage 3 verified
      the registration (verified=1) or the name was already on a public scam list (stage 0).
      SCAM_ABUSE_REQUIRE_VERIFIED=0 drops the second condition. A takedown request for a false
      positive, sent in our name, is the worst outcome, so the bar is high on purpose.

Safety rails
    - Never contacts the suspected scam site. Evidence is what the pipeline already has:
      the CT log entry, crt.sh, RDAP, the model's reasons and the Ed25519-signed alert.
    - SCAM_ABUSE_TEST_TO=you@example.org reroutes *every* outgoing mail to that address, so the
      send path can be exercised end to end without mailing a real registrar.
    - Per-domain dedupe (SCAM_ABUSE_DEDUPE_HOURS, 24) and a global cap
      (SCAM_ABUSE_MAX_PER_HOUR, 20), checked and recorded under one lock, stop a stuck button
      or a script from flooding a registrar.
    - RDAP: this process has its own limiter (1 request / 2 s). It is NOT shared with Stage 3,
      which runs in the consumer process on the same IP, so lookups here still count against
      rdap.org's per-IP budget. That is why they are operator-only, limited to alerted domains,
      and cached for 24 h.
    - Credentials come from the environment only (SCAM_SMTP_*). Nothing is written to the repo.

Routes (mounted by setup_abuse_routes(app)):
    GET  /api/abuse/config                  public: mode, limits, whether *this caller* is an operator
    GET  /api/abuse/contact?domain=x.top    operator: registrar abuse contact via RDAP (cached 24 h)
    POST /api/abuse/report                  operator: {"alert_id": 123, "send": false, "reporter": {...}, "note": ""}
    GET  /api/abuse/reports?limit=100       operator: dispatch log (also ?domain=)
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hmac
import ipaddress
import json
import logging
import os
import re
import smtplib
import sqlite3
import threading
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from urllib.parse import quote

import requests
from aiohttp import web

log = logging.getLogger("scamouflage.abuse")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# ---------------------------------------------------------------------------
# Settings (environment only; nothing secret lives in the repo)
# ---------------------------------------------------------------------------
DATA_DIR = os.environ.get("DATA_DIR") or (
    os.path.dirname(os.environ["SCAM_DB"]) if os.environ.get("SCAM_DB") else os.path.join(REPO, "data"))
ALERTS_DB = os.environ.get("SCAM_DB") or os.path.join(DATA_DIR, "scamouflage.db")
TAKEDOWN_DB = os.environ.get("SCAM_ABUSE_DB") or os.path.join(DATA_DIR, "takedowns.db")

MODES = ("off", "preview", "send")
MODE = (os.environ.get("SCAM_ABUSE_MODE") or "preview").strip().lower()
if MODE not in MODES:
    log.warning("SCAM_ABUSE_MODE=%r is not one of %s; using preview", MODE, MODES)
    MODE = "preview"

SMTP_HOST = os.environ.get("SCAM_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SCAM_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SCAM_SMTP_USER", "")
SMTP_PASS = os.environ.get("SCAM_SMTP_PASS", "")
SMTP_STARTTLS = os.environ.get("SCAM_SMTP_STARTTLS", "1") != "0"
SMTP_TIMEOUT = float(os.environ.get("SCAM_SMTP_TIMEOUT", "20"))

FROM_ADDR = os.environ.get("SCAM_ABUSE_FROM", "")          # e.g. "Scamouflage Abuse Desk <abuse@scamouflage.example>"
REPLY_TO = os.environ.get("SCAM_ABUSE_REPLY_TO", "")
ORG_NAME = os.environ.get("SCAM_ABUSE_ORG", "Scamouflage (IBM Z Datathon 2026 team)")
CC_ADDRS = [a.strip() for a in os.environ.get("SCAM_ABUSE_CC", "").split(",") if a.strip()]
TEST_TO = os.environ.get("SCAM_ABUSE_TEST_TO", "").strip()  # reroute every mail here (safe testing)
PUBLIC_BASE = os.environ.get("SCAM_PUBLIC_BASE", "").rstrip("/")  # e.g. http://148.100.79.76:8000

MAX_PER_HOUR = int(os.environ.get("SCAM_ABUSE_MAX_PER_HOUR", "20"))
DEDUPE_HOURS = float(os.environ.get("SCAM_ABUSE_DEDUPE_HOURS", "24"))
CONTACT_TTL_S = 24 * 3600
RDAP_TIMEOUT = float(os.environ.get("SCAM_ABUSE_RDAP_TIMEOUT", "8"))
RDAP_INTERVAL = float(os.environ.get("SCAM_ABUSE_RDAP_INTERVAL", "2.0"))  # this process only
USER_AGENT = "Scamouflage/1.0 abuse-dispatcher (+https://github.com/shriya77/Scamouflage)"

# Operator access: loopback peer, or the shared token header.
TOKEN = os.environ.get("SCAM_ABUSE_TOKEN", "")
TOKEN_HEADER = "X-Scamouflage-Token"

# Which alerts may be reported. Same bar as the extension's blocklist.
try:
    from backend.blocklist_route import THRESHOLD as _BLOCKLIST_THRESHOLD
except Exception:  # pragma: no cover
    _BLOCKLIST_THRESHOLD = 0.85
MIN_SCORE = float(os.environ.get("SCAM_ABUSE_MIN_SCORE") or _BLOCKLIST_THRESHOLD)
REQUIRE_VERIFIED = os.environ.get("SCAM_ABUSE_REQUIRE_VERIFIED", "1") != "0"

_EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")

# Registered domain: the same bundled PSL extractor Stage 3 uses (never downloads).
try:
    from model.stage3 import _extract_domain as _registered_domain
except Exception:  # pragma: no cover - tests run without the model package deps
    import tldextract
    _PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

    def _registered_domain(host):
        e = _PSL(host)
        if not e.suffix:
            parts = host.split(".")
            return (".".join(parts[-2:]) if len(parts) >= 2 else ""), False
        if not e.domain:
            return "", False
        return f"{e.domain}.{e.suffix}", bool(getattr(e, "is_private", False))


class _Limiter:
    """At least `s` seconds between rdap.org requests from this process. Stage 3 has its own
    limiter in the consumer process; rdap.org counts both against the same IP."""

    def __init__(self, s=RDAP_INTERVAL):
        self.s, self._next, self._lock = s, 0.0, threading.Lock()

    def wait(self):
        with self._lock:
            d = self._next - time.monotonic()
            if d > 0:
                time.sleep(d)
            self._next = time.monotonic() + self.s


_rdap_limiter = _Limiter()


def now_iso(t=None):
    t = time.time() if t is None else t
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def registered_domain(host: str) -> str:
    h = str(host or "").strip().lower().rstrip(".")
    while h.startswith("*."):
        h = h[2:]
    dom, _shared = _registered_domain(h) if h else ("", False)
    return dom


# ---------------------------------------------------------------------------
# RDAP: registrar abuse contact
# ---------------------------------------------------------------------------
def _vcard_fields(entity: dict) -> dict:
    """fn / email / tel from an RDAP jCard. Emails may repeat; keep them all, in order."""
    out = {"fn": None, "emails": [], "tel": None}
    vc = entity.get("vcardArray")
    if not (isinstance(vc, list) and len(vc) > 1 and isinstance(vc[1], list)):
        return out
    for item in vc[1]:
        if not (isinstance(item, list) and len(item) >= 4):
            continue
        key, val = str(item[0]).lower(), item[3]
        if key == "fn" and val and not out["fn"]:
            out["fn"] = str(val).strip()
        elif key == "email" and val:
            v = str(val).strip().lower()
            if _EMAIL_RE.match(v) and v not in out["emails"]:
                out["emails"].append(v)
        elif key == "tel" and val and not out["tel"]:
            out["tel"] = str(val).replace("tel:", "").strip()
    return out


def _walk(entities, depth=0):
    for ent in entities or []:
        if isinstance(ent, dict):
            yield ent, depth
            yield from _walk(ent.get("entities"), depth + 1)


def parse_abuse_contact(data: dict) -> dict:
    """Registrar name/IANA id and the abuse mailbox from an RDAP domain response.

    Looks for an entity with role "abuse" under the registrar entity first (the ICANN profile
    layout), then anywhere in the document, then falls back to the registrar entity's own
    email if it has one. Also collects "remarks"/"notices" that mention an abuse address,
    which some registries use instead of a proper entity."""
    out = {"registrar": None, "registrar_iana_id": None, "emails": [], "phone": None,
           "abuse_source": None, "registered_at": None, "statuses": list(data.get("status") or [])}
    for ev in data.get("events") or []:
        if str(ev.get("eventAction", "")).lower() in ("registration", "created", "registered"):
            out["registered_at"] = ev.get("eventDate")
            break

    registrar = None
    for ent, _d in _walk(data.get("entities")):
        roles = [str(r).lower() for r in ent.get("roles") or []]
        if "registrar" in roles and registrar is None:
            registrar = ent
            f = _vcard_fields(ent)
            out["registrar"] = f["fn"] or (ent.get("handle") if not str(ent.get("handle", "")).isdigit() else None)
            for pid in ent.get("publicIds") or []:
                if "iana" in str(pid.get("type", "")).lower():
                    out["registrar_iana_id"] = str(pid.get("identifier"))
    # 1) abuse entity nested under the registrar
    scopes = [(registrar.get("entities") if registrar else None, "registrar/abuse"),
              (data.get("entities"), "abuse")]
    for ents, label in scopes:
        for ent, _d in _walk(ents):
            if "abuse" in [str(r).lower() for r in ent.get("roles") or []]:
                f = _vcard_fields(ent)
                if f["emails"]:
                    out["emails"], out["phone"], out["abuse_source"] = f["emails"], f["tel"], label
                    return out
    # 2) the registrar entity's own mailbox
    if registrar:
        f = _vcard_fields(registrar)
        if f["emails"]:
            out["emails"], out["phone"], out["abuse_source"] = f["emails"], f["tel"], "registrar"
            return out
    # 3) free text (remarks/notices) that names an abuse mailbox
    text = json.dumps([data.get("remarks") or [], data.get("notices") or []])
    found = []
    for m in re.finditer(r"[A-Za-z0-9._%+-]*abuse[A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
        v = m.group(0).lower()
        if v not in found:
            found.append(v)
    if found:
        out["emails"], out["abuse_source"] = found, "remarks"
    return out


def fetch_rdap(domain: str, timeout: float = RDAP_TIMEOUT) -> tuple[dict | None, str | None]:
    """(json, error). Only rdap.org is contacted (it redirects to the right registry)."""
    url = f"https://rdap.org/domain/{quote(domain)}"
    try:
        _rdap_limiter.wait()
        r = requests.get(url, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"},
                         timeout=timeout, allow_redirects=True)
    except requests.Timeout:
        return None, "timeout"
    except requests.RequestException:
        return None, "other"
    if r.status_code == 404:
        return None, "not_found"
    if r.status_code == 429:
        return None, "rate_limited"
    if r.status_code != 200:
        return None, f"http_{r.status_code}"
    try:
        return r.json(), None
    except ValueError:
        return None, "other"


def lookup_abuse_contact(host: str, store: "TakedownStore | None" = None, fetch=fetch_rdap) -> dict:
    """Abuse contact for the registered domain of `host`, from the cache or RDAP."""
    domain = registered_domain(host)
    base = {"domain": domain, "registrar": None, "registrar_iana_id": None, "emails": [],
            "phone": None, "abuse_source": None, "registered_at": None, "statuses": [],
            "rdap_url": f"https://rdap.org/domain/{domain}" if domain else None,
            "error": None, "cached": False, "fetched_at": None}
    if not domain or "." not in domain:
        return dict(base, error="no_registered_domain")
    if store is not None:
        hit = store.get_contact(domain)
        if hit is not None:
            return dict(base, **hit, cached=True)
    data, err = fetch(domain)
    res = dict(base, fetched_at=now_iso())
    if err:
        res["error"] = err
    else:
        res.update(parse_abuse_contact(data))
        if not res["emails"]:
            res["error"] = "no_abuse_contact"
    if store is not None and res["error"] in (None, "no_abuse_contact", "not_found"):
        store.put_contact(res)
    return res


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------
BRAND_NAMES = {
    "ezpass": "E-ZPass", "e-zpass": "E-ZPass", "ezdrive": "EZDriveMA", "ntta": "NTTA",
    "tolltag": "NTTA TollTag", "txtag": "TxTag", "hctra": "HCTRA", "eztag": "EZ TAG",
    "sunpass": "SunPass", "fastrak": "FasTrak", "thetollroads": "The Toll Roads",
    "ipass": "Illinois Tollway I-PASS", "peachpass": "Peach Pass", "pikepass": "PikePass",
    "goodtogo": "Good To Go", "quickpass": "Quick Pass", "epass": "E-PASS", "usps": "USPS",
    "fedex": "FedEx", "dhl": "DHL", "ups": "UPS", "irs": "the IRS", "dmv": "the DMV",
    "txdmv": "the Texas DMV", "txdot": "TxDOT",
}
CATEGORY_WORDS = {"toll": "a toll-road operator", "delivery": "a parcel carrier",
                  "gov": "a government agency", "other": "a well-known organisation"}


def _fmt_age(days):
    if days is None:
        return "unknown"
    days = float(days)
    if days < 1:
        return f"{max(1, round(days * 24))} hour(s)"
    if days < 60:
        return f"{round(days)} day(s)"
    return f"{days / 30.4:.0f} month(s)"


def _age_from(iso):
    """Days since an RDAP registration timestamp, or None if it can't be parsed."""
    if not iso or not isinstance(iso, str):
        return None
    try:
        t = dt.datetime.fromisoformat(iso.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return round(max(0.0, (dt.datetime.now(dt.timezone.utc) - t).total_seconds() / 86400), 2)


def _impersonated(alert: dict) -> str:
    brand = (alert.get("brand") or "").lower()
    cat = (alert.get("category") or "other").lower()
    if brand in BRAND_NAMES:
        return BRAND_NAMES[brand]
    if brand:
        return f'"{brand}" ({CATEGORY_WORDS.get(cat, CATEGORY_WORDS["other"])})'
    return CATEGORY_WORDS.get(cat, CATEGORY_WORDS["other"])


def _as_list(v):
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            return [v]
    return list(v or [])


def build_report(alert: dict, contact: dict, reporter: dict | None = None, note: str = "",
                 public_base: str = PUBLIC_BASE, org: str = ORG_NAME) -> dict:
    """The e-mail (to/cc/subject/body) plus the JSON attachment, from the stored alert row."""
    reporter = reporter or {}
    domain = str(alert.get("domain") or "")
    site = contact.get("domain") or registered_domain(domain)
    brand = _impersonated(alert)
    score = float(alert.get("score") or 0)
    reasons = _as_list(alert.get("reasons"))
    sans = [d for d in _as_list(alert.get("domains")) if d]
    cert_id = str(alert.get("cert_id") or "")
    first_seen = alert.get("cert_seen_at") or (now_iso(alert["seen_at"]) if alert.get("seen_at") else None)
    decided = alert.get("decided_at") or first_seen
    alert_id = alert.get("id")
    registrar = contact.get("registrar") or alert.get("registrar") or "the sponsoring registrar"
    reporter_name = reporter.get("name") or org
    reporter_email = reporter.get("email") or REPLY_TO or (FROM_ADDR if "@" in FROM_ADDR else "")
    reporter_org = reporter.get("org") or org

    alert_url = f"{public_base}/api/alerts/{alert_id}" if public_base and alert_id is not None else None
    pubkey_url = f"{public_base}/api/alerts/pubkey" if public_base else None

    subject = f"[Phishing] {domain} impersonates {brand} - abuse report, please suspend"

    lines = [
        f"Hello {registrar} abuse team,",
        "",
        f"We are reporting the domain {site} for phishing. The hostname below carries a TLS",
        f"certificate issued {first_seen or 'recently'} and is built to impersonate {brand}.",
        "We ask that you review it under your abuse policy and, if you agree, suspend the",
        "domain (clientHold / serverHold) so it stops resolving.",
        "",
        "DOMAIN",
        f"  Registered domain:   {site}",
        f"  Hostname on cert:    {domain}",
    ]
    if len(sans) > 1:
        shown = [d for d in sans if d != domain][:15]
        lines.append(f"  Other names on cert: {', '.join(shown)}" + (" ..." if len(sans) - 1 > 15 else ""))
    reg_at = contact.get("registered_at")
    age_days = _age_from(reg_at)
    if age_days is None:
        age_days = alert.get("age_days")
    if reg_at or age_days is not None:
        lines.append(f"  Registered:          {reg_at or 'unknown'} (age {_fmt_age(age_days)})")
    lines.append(f"  Registrar (RDAP):    {registrar}"
                 + (f" (IANA {contact['registrar_iana_id']})" if contact.get("registrar_iana_id") else ""))
    lines += [
        "",
        "EVIDENCE (from public Certificate Transparency logs and RDAP; we did not visit the site)",
        f"  Certificate SHA-256: {cert_id}",
        f"  Issuer:              {alert.get('issuer') or 'unknown'}",
        f"  CT log:              {alert.get('log') or 'unknown'}",
        f"  First seen in CT:    {first_seen or 'unknown'}",
        f"  Public record:       {alert.get('crtsh_url') or ('https://crt.sh/?q=' + quote(domain))}",
        f"  RDAP record:         {contact.get('rdap_url') or ('https://rdap.org/domain/' + quote(site))}",
        "",
        f"WHY WE FLAGGED IT (classifier score {score:.2f} of 1.00, decided {decided or 'n/a'})",
    ]
    lines += [f"  - {r}" for r in reasons] or ["  - (no reasons recorded)"]
    if note.strip():
        lines += ["", "ADDITIONAL NOTES FROM THE REPORTER", *[f"  {l}" for l in note.strip().splitlines()]]
    lines += [
        "",
        "VERIFYING THIS REPORT",
        f"  This alert was produced automatically by {org} by scanning Certificate Transparency",
        "  logs for look-alike toll, delivery and government domains, then checking RDAP.",
    ]
    if alert.get("sig"):
        lines.append(f"  The alert is Ed25519-signed (key {alert.get('key_id')}).")
    if alert_url:
        lines.append(f"  Signed alert JSON:   {alert_url}")
    if pubkey_url:
        lines.append(f"  Public key:          {pubkey_url}")
    lines.append("  The same record is attached as JSON.")
    lines += [
        "",
        "REQUESTED ACTION",
        "  1. Verify the registration (registrant data is likely false or privacy-proxied).",
        "  2. Suspend the domain and remove its name servers.",
        "  3. Reply with a ticket number so we can track the outcome.",
        "",
        "We are happy to provide anything else you need.",
        "",
        f"{reporter_name}",
        f"{reporter_org}",
    ]
    if reporter_email:
        lines.append(reporter_email)

    body = "\n".join(lines) + "\n"
    to = list(contact.get("emails") or [])
    attachment = {
        "format": "scamouflage-abuse-report/1",
        "report_type": "phishing",
        "generated_at": now_iso(),
        "reporter": {"name": reporter_name, "org": reporter_org, "email": reporter_email or None},
        "target": {"registered_domain": site, "hostname": domain, "all_names_on_cert": sans,
                   "impersonates": brand, "category": alert.get("category")},
        "registrar": {"name": registrar, "iana_id": contact.get("registrar_iana_id"),
                      "abuse_emails": to, "abuse_phone": contact.get("phone"),
                      "rdap": contact.get("rdap_url")},
        "evidence": {"cert_sha256": cert_id, "issuer": alert.get("issuer"), "ct_log": alert.get("log"),
                     "first_seen_in_ct": first_seen, "crtsh_url": alert.get("crtsh_url"),
                     "domain_registered_at": reg_at, "domain_age_days": age_days,
                     "site_visited": False},
        "classification": {"score": score, "reasons": reasons, "stage": alert.get("stage"),
                           "model_version": alert.get("model_version"), "decided_at": decided},
        "signed_alert": {k: alert.get(k) for k in (
            "id", "cert_id", "domain", "domains", "score", "reasons", "seen_at", "issuer", "log",
            "verify", "crtsh_url", "verdict", "stage", "s1", "s2_boost", "brand", "category",
            "verified", "age_days", "registrar", "risky_registrar", "model_version",
            "cert_seen_at", "decided_at", "sig", "key_id")},
        "verify_url": alert_url, "pubkey_url": pubkey_url,
    }
    return {"to": to, "cc": list(CC_ADDRS), "subject": subject, "body": body,
            "attachment_name": f"scamouflage-alert-{alert_id or cert_id[:12] or 'report'}.json",
            "attachment": attachment,
            "mailto": _mailto(to, CC_ADDRS, subject, body)}


def _mailto(to, cc, subject, body):
    if not to:
        return None
    q = f"subject={quote(subject)}&body={quote(body)}"
    if cc:
        q = f"cc={quote(','.join(cc))}&" + q
    return f"mailto:{','.join(to)}?{q}"


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------
def smtp_configured() -> bool:
    return bool(SMTP_HOST and FROM_ADDR)


def send_report(report: dict, smtp_factory=None) -> dict:
    """Send over SMTP. Blocking; call from an executor. Returns {message_id, to}."""
    if not smtp_configured():
        raise RuntimeError("SMTP sender not configured (SCAM_SMTP_HOST, SCAM_ABUSE_FROM)")
    to = [TEST_TO] if TEST_TO else list(report["to"])
    cc = [] if TEST_TO else list(report.get("cc") or [])
    if not to:
        raise RuntimeError("no recipient")
    msg = EmailMessage()
    msg["From"] = FROM_ADDR
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    if REPLY_TO:
        msg["Reply-To"] = REPLY_TO
    msg["Subject"] = (("[TEST, would go to %s] " % ", ".join(report["to"])) if TEST_TO else "") + report["subject"]
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=(FROM_ADDR.split("@")[-1].strip("> ") or None))
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Scamouflage-Domain"] = report["attachment"]["target"]["registered_domain"]
    msg.set_content(report["body"])
    msg.add_attachment(json.dumps(report["attachment"], indent=2, sort_keys=True).encode(),
                       maintype="application", subtype="json", filename=report["attachment_name"])
    factory = smtp_factory or (lambda: smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT))
    with factory() as s:
        if SMTP_STARTTLS:
            s.starttls()
        if SMTP_USER:
            s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg, to_addrs=to + cc)
    return {"message_id": msg["Message-ID"], "to": to, "cc": cc}


# ---------------------------------------------------------------------------
# Store: contacts cache + dispatch log (own file; the alerts DB stays read-only)
# ---------------------------------------------------------------------------
class TakedownStore:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS abuse_contacts (
        domain            TEXT PRIMARY KEY,
        registrar         TEXT,
        registrar_iana_id TEXT,
        emails            TEXT,      -- JSON list
        phone             TEXT,
        abuse_source      TEXT,
        registered_at     TEXT,
        rdap_url          TEXT,
        error             TEXT,
        fetched_at        REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS reports (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id    INTEGER,
        domain      TEXT NOT NULL,      -- registered domain
        hostname    TEXT,
        registrar   TEXT,
        to_emails   TEXT,               -- JSON list
        subject     TEXT,
        body        TEXT,
        status      TEXT NOT NULL,      -- preview | mailto | sent | failed
        message_id  TEXT,
        error       TEXT,
        reporter    TEXT,
        created_at  REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS reports_domain ON reports(domain, created_at);
    """

    def __init__(self, path: str = TAKEDOWN_DB):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.con = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.executescript(self.SCHEMA)
        self.lock = threading.Lock()

    def close(self):
        self.con.close()

    def get_contact(self, domain: str) -> dict | None:
        with self.lock:
            r = self.con.execute("SELECT * FROM abuse_contacts WHERE domain = ?", (domain,)).fetchone()
        if r is None or time.time() - r["fetched_at"] > CONTACT_TTL_S:
            return None
        return {"registrar": r["registrar"], "registrar_iana_id": r["registrar_iana_id"],
                "emails": json.loads(r["emails"] or "[]"), "phone": r["phone"],
                "abuse_source": r["abuse_source"], "registered_at": r["registered_at"],
                "rdap_url": r["rdap_url"], "error": r["error"], "fetched_at": now_iso(r["fetched_at"])}

    def put_contact(self, c: dict) -> None:
        with self.lock, self.con:
            self.con.execute(
                "INSERT OR REPLACE INTO abuse_contacts(domain, registrar, registrar_iana_id, emails, phone,"
                " abuse_source, registered_at, rdap_url, error, fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (c["domain"], c.get("registrar"), c.get("registrar_iana_id"), json.dumps(c.get("emails") or []),
                 c.get("phone"), c.get("abuse_source"), c.get("registered_at"), c.get("rdap_url"),
                 c.get("error"), time.time()))

    def log(self, **r) -> int:
        with self.lock, self.con:
            cur = self.con.execute(
                "INSERT INTO reports(alert_id, domain, hostname, registrar, to_emails, subject, body, status,"
                " message_id, error, reporter, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (r.get("alert_id"), r["domain"], r.get("hostname"), r.get("registrar"),
                 json.dumps(r.get("to") or []), r.get("subject"), r.get("body"), r["status"],
                 r.get("message_id"), r.get("error"), json.dumps(r.get("reporter") or {}), time.time()))
        return cur.lastrowid

    def last_dispatch(self, domain: str) -> dict | None:
        """Newest sent/mailto record for the domain (previews don't count)."""
        with self.lock:
            r = self.con.execute(
                "SELECT * FROM reports WHERE domain = ? AND status IN ('sent','mailto')"
                " ORDER BY id DESC LIMIT 1", (domain,)).fetchone()
        return self._row(r) if r else None

    def sent_last_hour(self) -> int:
        with self.lock:
            return self.con.execute("SELECT COUNT(*) FROM reports WHERE status = 'sent' AND created_at > ?",
                                    (time.time() - 3600,)).fetchone()[0]

    def recent(self, limit=100, domain=None) -> list:
        sql, args = "SELECT * FROM reports", []
        if domain:
            sql += " WHERE domain = ?"
            args.append(domain)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self.lock:
            rows = self.con.execute(sql, args).fetchall()
        return [self._row(r) for r in rows]

    @staticmethod
    def _row(r) -> dict:
        d = {k: r[k] for k in r.keys() if k != "body"}
        d["to"] = json.loads(d.pop("to_emails") or "[]")
        d["reporter"] = json.loads(d.get("reporter") or "{}")
        d["created_at"] = now_iso(d["created_at"])
        return d


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
def _json_error(status, msg, **extra):
    return web.json_response({"error": msg, **extra}, status=status)


def load_alert(alert_id, db_path: str = ALERTS_DB) -> dict | None:
    if not os.path.exists(db_path):
        return None
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
    con.row_factory = sqlite3.Row
    try:
        if str(alert_id).isdigit():
            r = con.execute("SELECT * FROM alerts WHERE id = ?", (int(alert_id),)).fetchone()
        else:
            r = con.execute("SELECT * FROM alerts WHERE cert_id = ? ORDER BY id DESC LIMIT 1",
                            (str(alert_id),)).fetchone()
    except sqlite3.OperationalError:
        return None
    finally:
        con.close()
    if r is None:
        return None
    a = {k: r[k] for k in r.keys()}
    for k in ("domains", "reasons"):
        a[k] = _as_list(a.get(k))
    return a


def alerted_host(host: str, db_path: str = ALERTS_DB) -> bool:
    """True if some alert was raised for exactly this hostname."""
    if not os.path.exists(db_path):
        return False
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
    try:
        return con.execute("SELECT 1 FROM alerts WHERE domain = ? LIMIT 1", (host,)).fetchone() is not None
    except sqlite3.OperationalError:
        return False
    finally:
        con.close()


def eligibility(alert: dict) -> str | None:
    """None if the alert may be reported, else a short reason why not."""
    score = float(alert.get("score") or 0)
    if score < MIN_SCORE:
        return f"score {score:.2f} is below the reporting threshold {MIN_SCORE:.2f}"
    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None
    if REQUIRE_VERIFIED and not (_int(alert.get("verified")) == 1 or _int(alert.get("stage")) == 0):
        return "the registration was not verified by Stage 3 (RDAP) and the name is not on a public scam list"
    return None


def is_loopback(remote: str | None) -> bool:
    try:
        return ipaddress.ip_address((remote or "").split("%")[0]).is_loopback
    except ValueError:
        return False


def is_operator(request, peer=None) -> bool:
    """Loopback peer (SSH tunnel) or the shared token header."""
    remote = peer(request) if peer else request.remote
    if is_loopback(remote):
        return True
    given = request.headers.get(TOKEN_HEADER, "")
    return bool(TOKEN) and bool(given) and hmac.compare_digest(given, TOKEN)


def setup_abuse_routes(app: web.Application, store: TakedownStore | None = None,
                       alerts_db: str = ALERTS_DB, lookup=None, sender=None, peer=None) -> None:
    """Mount the four routes. `lookup`/`sender`/`peer` are injectable for tests
    (`peer(request) -> remote address`, default request.remote)."""
    store = store or TakedownStore()
    lookup = lookup or (lambda host: lookup_abuse_contact(host, store))
    sender = sender or send_report
    app["abuse_store"] = store
    locks: dict = {}   # created on first use, inside the running loop (Python 3.9 binds Lock to a loop)

    def send_lock():
        """Dedupe check + cap check + send + log happen as one unit."""
        if "send" not in locks:
            locks["send"] = asyncio.Lock()
        return locks["send"]

    async def in_thread(fn, *a):
        return await asyncio.get_running_loop().run_in_executor(None, fn, *a)

    def guard(request):
        if MODE == "off":
            raise web.HTTPServiceUnavailable(
                text=json.dumps({"error": "abuse dispatcher is off (SCAM_ABUSE_MODE=off)"}),
                content_type="application/json")
        if not is_operator(request, peer):
            raise web.HTTPForbidden(
                text=json.dumps({"error": "operator only: call from the VM (SSH tunnel) or send the "
                                          f"{TOKEN_HEADER} header"}),
                content_type="application/json")

    async def config(request):
        return web.json_response({
            "mode": MODE, "operator": is_operator(request, peer),
            "can_send": MODE == "send" and smtp_configured(),
            "sender_configured": smtp_configured(), "test_to": bool(TEST_TO),
            "max_per_hour": MAX_PER_HOUR, "dedupe_hours": DEDUPE_HOURS,
            "min_score": MIN_SCORE, "require_verified": REQUIRE_VERIFIED, "org": ORG_NAME})

    async def contact(request):
        guard(request)
        host = (request.query.get("domain") or "").strip().lower().rstrip(".")
        if not host or len(host) > 253 or not re.fullmatch(r"[a-z0-9.\-]+", host):
            return _json_error(400, "domain required")
        if not alerted_host(host, alerts_db):
            return _json_error(404, "no alert for that hostname; lookups are limited to alerted names")
        res = await in_thread(lookup, host)
        return web.json_response(res)

    async def report(request):
        guard(request)
        try:
            body = await request.json()
        except Exception:
            return _json_error(400, "JSON body required")
        alert_id = body.get("alert_id")
        if alert_id is None:
            return _json_error(400, "alert_id required")
        alert = load_alert(alert_id, alerts_db)
        if alert is None:
            return _json_error(404, "alert not found")
        why_not = eligibility(alert)
        if why_not:
            return _json_error(409, f"not eligible for a takedown request: {why_not}",
                               alert_id=alert.get("id"), hostname=alert["domain"], eligible=False)
        want_send = bool(body.get("send"))
        force = bool(body.get("force"))
        reporter = body.get("reporter") if isinstance(body.get("reporter"), dict) else {}
        reporter = {k: str(reporter.get(k) or "")[:200] for k in ("name", "email", "org")}
        if reporter["email"] and not _EMAIL_RE.match(reporter["email"]):
            return _json_error(400, "reporter.email is not an e-mail address")
        note = str(body.get("note") or "")[:4000]

        contact = await in_thread(lookup, alert["domain"])
        rep = build_report(alert, contact, reporter, note)
        site = contact.get("domain") or registered_domain(alert["domain"])
        previous = store.last_dispatch(site)
        out = {"alert_id": alert.get("id"), "domain": site, "hostname": alert["domain"],
               "contact": contact, "report": rep, "previous": previous,
               "can_send": MODE == "send" and smtp_configured() and bool(rep["to"])}

        if not want_send:
            if not body.get("handoff"):          # preview: build only, nothing is logged
                return web.json_response(dict(out, status="preview", report_id=None))
            if not rep["to"]:
                return _json_error(409, "no abuse contact for this registrar", **out)
            # the user is sending it from their own mail client: remember that
            rid = store.log(alert_id=alert.get("id"), domain=site, hostname=alert["domain"],
                            registrar=contact.get("registrar"), to=rep["to"], subject=rep["subject"],
                            body=rep["body"], status="mailto", reporter=reporter)
            return web.json_response(dict(out, status="mailto", report_id=rid))

        # ---- send path
        if MODE != "send":
            return _json_error(403, "server sending is disabled (SCAM_ABUSE_MODE is not 'send')", **out)
        if not smtp_configured():
            return _json_error(503, "no SMTP sender configured (SCAM_SMTP_HOST / SCAM_ABUSE_FROM)", **out)
        if not rep["to"]:
            return _json_error(409, "no abuse contact for this registrar; nothing to send", **out)
        async with send_lock():   # serialize: nobody else may slip between the checks and the log
            previous = store.last_dispatch(site)
            out["previous"] = previous
            if previous and not force:
                age_h = (time.time() - dt.datetime.strptime(previous["created_at"], "%Y-%m-%dT%H:%M:%SZ")
                         .replace(tzinfo=dt.timezone.utc).timestamp()) / 3600
                if age_h < DEDUPE_HOURS:
                    return _json_error(409, f"{site} was already reported {age_h:.1f} h ago", **out)
            if store.sent_last_hour() >= MAX_PER_HOUR:
                return _json_error(429, f"send limit reached ({MAX_PER_HOUR}/hour)", **out)
            try:
                sent = await in_thread(sender, rep)
            except Exception as e:  # SMTP refused, DNS, auth...
                log.warning("abuse report for %s failed: %s", site, e)
                rid = store.log(alert_id=alert.get("id"), domain=site, hostname=alert["domain"],
                                registrar=contact.get("registrar"), to=rep["to"], subject=rep["subject"],
                                body=rep["body"], status="failed", error=f"{type(e).__name__}: {e}",
                                reporter=reporter)
                return _json_error(502, f"sending failed: {type(e).__name__}: {e}", **dict(out, report_id=rid))
            rid = store.log(alert_id=alert.get("id"), domain=site, hostname=alert["domain"],
                            registrar=contact.get("registrar"), to=sent["to"], subject=rep["subject"],
                            body=rep["body"], status="sent", message_id=sent["message_id"], reporter=reporter)
        log.info("abuse report %s sent for %s to %s", rid, site, sent["to"])
        return web.json_response(dict(out, status="sent", report_id=rid, sent_to=sent["to"],
                                      message_id=sent["message_id"], rerouted=bool(TEST_TO)))

    async def reports(request):
        guard(request)   # the log names reporters and recipients: operators only
        try:
            limit = max(1, min(int(request.query.get("limit", 100)), 1000))
        except ValueError:
            limit = 100
        domain = (request.query.get("domain") or "").strip().lower() or None
        return web.json_response({"items": store.recent(limit, domain), "mode": MODE})

    app.router.add_get("/api/abuse/config", config)
    app.router.add_get("/api/abuse/contact", contact)
    app.router.add_post("/api/abuse/report", report)
    app.router.add_get("/api/abuse/reports", reports)


if __name__ == "__main__":  # quick manual check: python -m backend.abuse_report example.com
    import sys
    logging.basicConfig(level=logging.INFO)
    for h in sys.argv[1:]:
        print(json.dumps(lookup_abuse_contact(h), indent=2))
