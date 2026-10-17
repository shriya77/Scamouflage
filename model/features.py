"""
Scamouflage — model/features.py  (owner: Vaishnavi)

Shared helpers for the detection engine. Nothing here visits a website; it only reads the name.

  clean_host(raw)       -> str | None     normalise a certificate name ("*.Foo.com." -> "foo.com")
  registered_domain(h)  -> str            "pay.ezpass.com-xk2.win" -> "ezpass.com-xk2.win"
  is_official(h)        -> bool           on labels/official.txt (never flagged)
  brand_gate(h)         -> (bool, brand, category)   the brand-word gate (MODEL_SPEC §3)
  name_features(h)      -> dict           numbers for the Stage 1 handcrafted-feature model
"""
import ipaddress
import math
import os
import re
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _read_list(path, with_cat=False):
    out = []
    if not os.path.exists(path):
        return out
    for line in open(path):
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        if with_cat:
            w, _, c = line.partition(",")
            out.append((w.strip(), c.strip() or "other"))
        else:
            out.append(line)
    return out


BRANDS = sorted(_read_list(os.path.join(ROOT, "labels", "brands.txt"), True), key=lambda b: -len(b[0]))
OFFICIAL = set(_read_list(os.path.join(ROOT, "labels", "official.txt")))
# Misspelling targets: only brand words of 6+ letters. Shorter ones (fedex, ipass, tolls, txtag) sit one or two
# letters away from ordinary words (codex, class, tools, titan) and let lots of normal sites through the gate.
TYPO_TARGETS = [(w, set(w), c) for w, c in BRANDS if len(w) >= 6 and "-" not in w]

# Registered domains that host many different scam pages (weebly.com, 000webhostapp.com, ...). Generated from
# our own known-scam list by labels/hosting_platforms.py. On these, a domain's age belongs to the platform,
# not to whoever made the page, so Stage 3's "old domain -> probably a real business" rule must not apply.
HOSTING_PLATFORMS = set(_read_list(os.path.join(ROOT, "labels", "hosting_platforms.txt")))

# Cheap / abused endings seen in smishing reports (Unit 42 and others). Tunable.
RISKY_TLDS = {
    "xin", "win", "top", "vip", "icu", "bid", "cfd", "sbs", "shop", "online", "site", "xyz", "live",
    "click", "cyou", "buzz", "rest", "lol", "mom", "today", "store", "cc", "pw", "tk", "ml", "ga",
    "cf", "gq", "life", "world", "fun", "best", "monster", "quest", "bond", "boats", "hair", "skin",
    "autos", "beauty", "makeup", "work", "info", "cn", "su",
}
LURE_WORDS = [
    "pay", "fee", "fees", "toll", "verify", "secure", "login", "account", "update", "billing", "refund",
    "citation", "violation", "invoice", "track", "deliver", "parcel", "claim", "notice", "alert",
    "support", "confirm", "service", "unpaid", "due", "fine", "penalty", "redeliver", "customs", "package",
]
VOWELS = set("aeiou")
_HOST_OK = re.compile(r"^[a-z0-9.-]+$")
# kits use "com-" / "gov-" at the start (com-ezpass.top, gov-dmv.win); "org-"/"net-"/"us-" start too many
# normal names (org-domivka.shop was a false alarm), so they only count in the ".org-" infix form below.
_FAKE_PREFIX = re.compile(r"(com|gov)-")
_FAKE_TLD_IN_HOST = re.compile(r"\.(com|gov|org|net)-")

try:
    import tldextract
    # private PSL domains ON: "x.github.io" is its own registered domain, so shared hosting
    # never makes a whole platform look like one scam domain.
    # suffix_list_urls=() -> use tldextract's BUNDLED Public Suffix List snapshot (no download), the same
    # one Stage 0 and Stage 2 use, so all stages agree on registered domains.
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
except Exception as _e:  # pragma: no cover - fallback when tldextract is missing
    import logging
    logging.getLogger("scamouflage.features").warning(
        "tldextract unavailable (%s: %s); using simple last-two-labels domain split", type(_e).__name__, _e)
    _EXTRACT = None


# ----------------------------------------------------------------------------- names
def clean_host(raw):
    """'*.WWW.Foo.com.' -> 'foo.com'. Returns None for junk, IP addresses and names without a dot."""
    h = str(raw or "").strip().lower().rstrip(".")
    while h.startswith("*."):
        h = h[2:]
    if h.startswith("www."):
        h = h[4:]
    if not h or "." not in h or not _HOST_OK.match(h) or ".." in h:
        return None
    try:
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    return h


def split_host(host):
    """ezpass.com-xk2.win -> ('ezpass', 'com-xk2', 'win')   (subdomain, name, ending)"""
    host = host.lower().strip(".")
    if _EXTRACT is not None:
        e = _EXTRACT(host)
        if e.domain and e.suffix:
            return e.subdomain, e.domain, e.suffix
    parts = host.split(".")
    if len(parts) < 2:
        return "", host, ""
    return ".".join(parts[:-2]), parts[-2], parts[-1]


def registered_domain(host):
    _, name, tld = split_host(host)
    return f"{name}.{tld}" if tld else name


def is_official(host):
    return host in OFFICIAL or registered_domain(host) in OFFICIAL


# ----------------------------------------------------------------------------- brand words
def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _lev_le2(a, b):
    """True if edit distance(a, b) <= 2 (banded, fast)."""
    if abs(len(a) - len(b)) > 2:
        return False
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [99] * len(b)
        for j in range(max(1, i - 2), min(len(b), i + 2) + 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != b[j - 1]))
        if min(cur) > 2:
            return False
        prev = cur
    return prev[-1] <= 2


def _tokens(text):
    return [t for t in re.split(r"[^a-z0-9]+", text) if t]


def brand_hits(text):
    """[(brand, category), ...] for every brand word in `text`.
    Words of 4 letters or fewer must START a token (so 'irs' doesn't match 'first')."""
    tokens = _tokens(text)
    hits = []
    for w, c in BRANDS:
        if len(w) <= 4:
            if any(t.startswith(w) for t in tokens):
                hits.append((w, c))
        elif w in text:
            hits.append((w, c))
    return hits


_LURE_SET = None


def brand_whole_word(host):
    """True if a brand word appears as a WHOLE word in the subdomain/owner name: its own token (usps, dhl), or
    glued only to digits or a lure word (ezpasspay, paytoll, usps24). False for brands hidden inside other
    words (irshadwoodworks -> 'irs', coffeepass -> 'epass', denvercuredelivery -> 'redeliver')."""
    global _LURE_SET
    if _LURE_SET is None:
        _LURE_SET = set(LURE_WORDS)
    sub, name, _ = split_host(host)
    for t in _tokens(f"{sub}.{name}"):
        for w, _c in BRANDS:
            if t == w:
                return True
            if t.startswith(w) and len(t) > len(w):
                rest = t[len(w):]
                if rest.isdigit() or rest in _LURE_SET:
                    return True
            if t.endswith(w) and len(t) > len(w):
                rest = t[:-len(w)]
                if rest.isdigit() or rest in _LURE_SET:
                    return True
    return False


def on_hosting_platform(host):
    """True if the host sits on (or is) a known scam-hosting platform from labels/hosting_platforms.txt."""
    if not HOSTING_PLATFORMS:
        return False
    parts = host.split(".")
    return any(".".join(parts[i:]) in HOSTING_PLATFORMS for i in range(len(parts) - 1))


def _lev_le(a, b, k):
    """True if edit distance(a, b) <= k (k = 1 or 2)."""
    if k >= 2:
        return _lev_le2(a, b)
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) <= 1
    s, l = (a, b) if len(a) < len(b) else (b, a)
    return any(s == l[:i] + l[i + 1:] for i in range(len(l)))


def brand_typo(host):
    """(brand, category) if a token is a near-miss spelling of a brand, else None.
    Rules (kept strict so ordinary words don't pass the gate):
      - only the subdomain + the owner's name are checked, never the platform ending
        (x.vercel.app: "vercel" is part of the ending, so it can't look like "parcel")
      - brand words of 6+ letters only; 1 letter off for 6-7 letter brands, 2 for 8+ letters
      - the first letter must match (ezpas, sunpas, turnpik, redelivr)"""
    sub, name, _ = split_host(host)
    for t in _tokens(f"{sub}.{name}"):
        if 5 <= len(t) <= 14:
            ts = set(t)
            for w, ws, c in TYPO_TARGETS:
                k = 1 if len(w) <= 7 else 2
                if (t != w and t[0] == w[0] and abs(len(t) - len(w)) <= k and len(ts & ws) >= len(ws) - k
                        and _lev_le(t, w, k)):
                    return w, c
    return None


def fake_pattern(host):
    """'.com-' / 'gov-' tricks used by smishing kits (usps.com-track.win, gov-ezpass.top)."""
    _, name, _ = split_host(host)
    return bool(_FAKE_TLD_IN_HOST.search(host) or _FAKE_PREFIX.match(name) or _FAKE_PREFIX.match(host))


def brand_gate(host):
    """The brand-word gate (MODEL_SPEC §3). Returns (passes, brand, category).
    Passes if the name has a toll/delivery/gov brand word, a misspelled brand, or a fake '.com-'/'gov-' pattern."""
    hits = brand_hits(host)
    if hits:
        return True, hits[0][0], hits[0][1]
    typo = brand_typo(host)
    if typo:
        return True, typo[0], typo[1]
    if fake_pattern(host):
        return True, None, "other"
    return False, None, None


# ----------------------------------------------------------------------------- Stage 1 features
def name_features(host):
    host = (host or "").lower().strip(".")
    sub, name, tld = split_host(host)
    letters = re.sub(r"[^a-z]", "", host)
    tokens = _tokens(host)
    all_hits = brand_hits(host)
    cats = {c for _, c in all_hits}
    runs = re.findall(r"[^aeiou\d\W_]+", host)
    n_digits = sum(ch.isdigit() for ch in host)
    return {
        "len_host": len(host),
        "len_name": len(name),
        "len_sub": len(sub),
        "n_labels": host.count(".") + 1,
        "sub_depth": sub.count(".") + 1 if sub else 0,
        "n_hyphens": host.count("-"),
        "n_digits": n_digits,
        "digit_ratio": n_digits / max(len(host), 1),
        "vowel_ratio": sum(ch in VOWELS for ch in letters) / max(len(letters), 1),
        "max_consonant_run": max((len(r) for r in runs), default=0),
        "entropy_name": entropy(name),
        "entropy_host": entropy(host),
        "n_tokens": len(tokens),
        "max_token_len": max((len(t) for t in tokens), default=0),
        "tld_len": len(tld),
        "risky_tld": int(tld.split(".")[-1] in RISKY_TLDS),
        "brand_any": int(bool(all_hits)),
        "brand_in_sub": int(bool(brand_hits(sub))),
        "brand_in_name": int(bool(brand_hits(name))),
        "brand_toll": int("toll" in cats),
        "brand_delivery": int("delivery" in cats),
        "brand_gov": int("gov" in cats),
        "brand_typo": int(not all_hits and brand_typo(host) is not None),
        "official": int(is_official(host)),
        "com_gov_prefix": int(bool(_FAKE_PREFIX.match(name))),
        "fake_tld_in_host": int(bool(_FAKE_TLD_IN_HOST.search(host))),
        "lure_words": sum(1 for w in LURE_WORDS if w in host),
        "punycode": int("xn--" in host),
        "www_inside": int(bool(re.search(r".www|www\d", host))),
    }


FEATURE_NAMES = list(name_features("example.com").keys())


def name_vector(host):
    f = name_features(host)
    return [f[k] for k in FEATURE_NAMES]
