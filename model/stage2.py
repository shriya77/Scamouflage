"""
Scamouflage — model/stage2.py  (owner: Shriya)

Stage 2: the certificate check (MODEL_SPEC §7). Stage 1 scores ONE name; Stage 2 looks at the
whole certificate that name came on. Smishing kits buy one certificate for a batch of lookalikes
(ezpass.com-xk2.win + sunpass.com-xk2.win + txtag.com-xk2.win ...), which a single name can't show.

    s2 = Stage2()
    s2.boost("ezpass.com-xk2.win", leaf_cert)     # 0.0 ... 0.6, added on top of Stage 1:
    # final = 1 - (1 - s1) * (1 - boost)          (engine.py; can only go up)

v1 = a points table, no training. Era-stable features only: the names on the certificate.
NO issuer, NO validity length, NO dates (crt.sh certs of old scams are from another era than
live normals, so those would teach "old CA = scam").

Rules (MODEL_SPEC §2 rule 8, §7):
  - never negative, never above MAX_BOOST (0.6), never raises: on any error 0.0, logged once;
  - no leaf_cert, or a host that is not on it: 0.0;
  - a certificate that also covers an official site (labels/official.txt, or a name under one)
    gets 0.0: a CA only issues that after the real owner proved control, so it isn't a kit.

CLI (names are printed as plain text, never links):
    python -m model.stage2 explain FIXTURE.json [host]
    python -m model.stage2 eval --recording data/recordings/ct-*.jsonl.gz [--n-certs N]
                                [--labels-db PATH] [--out reports/stage2_eval]
"""
from __future__ import annotations

import logging
import os
import re

from . import features as F
from .stage0 import registered_domain

log = logging.getLogger("scamouflage.stage2")

MAX_BOOST = 0.6

# ------------------------------------------------------------------------------- the points table
# (feature, minimum value, points, reason shown on the alert). Every row that holds adds its
# points; the sum is capped at MAX_BOOST. Tuned on real certificates: reports/stage2_eval.md.
POINTS = [
    ("brand_names_on_cert", 2, 0.25, "{v} brand lookalikes on one certificate"),
    ("brand_names_on_cert", 4, 0.15, "4+ brand lookalikes on one certificate"),
    ("brand_registered_domains", 3, 0.15, "brand names on {v} different registered domains"),
    ("fake_pattern_names_on_cert", 2, 0.10, "{v} fake '.com-'/'gov-' names on one certificate"),
    ("wildcard_brand", 1, 0.05, "wildcard certificate for a brand-word name"),
]

FEATURE_NAMES = [
    "n_names",                     # distinct cleaned names on the certificate
    "n_registered_domains",        # distinct registered domains (private PSL, like Stage 0)
    "brand_names_on_cert",         # names with a brand word or a misspelled brand (not official)
    "brand_registered_domains",    # distinct registered domains among those brand names
    "brand_categories_on_cert",    # distinct categories among them (toll / delivery / gov)
    "distinct_brands_on_cert",     # distinct brand words among them (ezpass, sunpass, ...)
    "wildcard",                    # any "*." name
    "wildcard_brand",              # a "*." name that carries a brand word
    "fake_pattern_names_on_cert",  # names with the ".com-" / "gov-" trick
    "risky_tld_names_on_cert",     # names ending in a cheap / abused TLD
    "official_on_cert",            # a name that is, or is under, an official site
]

_TLD_RE = re.compile(r"\.([a-z0-9-]+)$")


def _official(name: str) -> bool:
    if name in F.OFFICIAL:
        return True
    i = name.find(".")
    while i != -1:
        if name[i + 1:] in F.OFFICIAL:
            return True
        i = name.find(".", i + 1)
    return False


def _brand(name: str):
    """(brand, category) for a brand word or a misspelled brand, else None (same as the gate)."""
    hits = F.brand_hits(name)
    if hits:
        return hits[0]
    return F.brand_typo(name)


def cert_features(leaf_cert: dict) -> dict:
    """Era-stable features of one certificate (names only). All zeros if there is no cert."""
    f = dict.fromkeys(FEATURE_NAMES, 0)
    raw_names = (leaf_cert or {}).get("all_domains") or []
    names, wild = {}, set()  # clean name -> raw had "*."
    for raw in raw_names:
        if not isinstance(raw, str):
            continue
        h = F.clean_host(raw)
        if not h:
            continue
        names[h] = names.get(h, False) or raw.strip().startswith("*.")
        if names[h]:
            wild.add(h)
    if not names:
        return f
    regs, brand_regs, cats, brands = set(), set(), set(), set()
    for h, is_wild in names.items():
        rd = registered_domain(h) or h
        regs.add(rd)
        if _official(h):
            f["official_on_cert"] = 1
            continue
        if F.fake_pattern(h):
            f["fake_pattern_names_on_cert"] += 1
        m = _TLD_RE.search(h)
        if m and m.group(1) in F.RISKY_TLDS:
            f["risky_tld_names_on_cert"] += 1
        b = _brand(h)
        if b:
            f["brand_names_on_cert"] += 1
            brand_regs.add(rd)
            brands.add(b[0])
            cats.add(b[1])
            if is_wild:
                f["wildcard_brand"] = 1
    f["n_names"] = len(names)
    f["n_registered_domains"] = len(regs)
    f["brand_registered_domains"] = len(brand_regs)
    f["brand_categories_on_cert"] = len(cats)
    f["distinct_brands_on_cert"] = len(brands)
    f["wildcard"] = int(bool(wild))
    return f


def points(feats: dict) -> tuple[float, list[str]]:
    """The points table applied to cert_features(). (boost, reasons)."""
    if feats.get("official_on_cert"):
        return 0.0, []
    total, reasons = 0.0, []
    for feat, minimum, pts, why in POINTS:
        v = feats.get(feat, 0)
        if v >= minimum:
            total += pts
            reasons.append(why.format(v=v))
    return min(MAX_BOOST, max(0.0, round(total, 4))), reasons


class Stage2:
    """v1: points table, no model file. model_dir is accepted for the engine's interface."""

    version = "stage2-v1-points"

    def __init__(self, model_dir=None):
        self.model_dir = model_dir
        self._last_key = None
        self._last = None
        self._warned = False

    def _cert(self, leaf_cert: dict):
        """(clean names on the cert, features, boost, reasons). The engine calls boost() once per
        gated name of the same certificate, so the last certificate is cached."""
        key = tuple(leaf_cert.get("all_domains") or ())
        if key != self._last_key:
            feats = cert_features(leaf_cert)
            b, reasons = points(feats)
            names = {F.clean_host(n) for n in key if isinstance(n, str)}
            self._last_key, self._last = key, (names, feats, b, reasons)
        return self._last

    def explain(self, host: str, leaf_cert: dict) -> dict:
        """{"boost", "reasons", "features"} for one name on one certificate. Never raises."""
        try:
            if not leaf_cert or not isinstance(leaf_cert, dict):
                return {"boost": 0.0, "reasons": [], "features": cert_features({})}
            names, feats, b, reasons = self._cert(leaf_cert)
            if F.clean_host(host) not in names:
                return {"boost": 0.0, "reasons": [], "features": feats}
            return {"boost": b, "reasons": list(reasons), "features": dict(feats)}
        except Exception:
            if not self._warned:
                self._warned = True
                log.exception("Stage 2 failed on %r; boost 0.0 (logged once)", host)
            return {"boost": 0.0, "reasons": [], "features": {}}

    def boost(self, host: str, leaf_cert: dict) -> float:
        """0.0 ... 0.6. Only raises a score (MODEL_SPEC §2 rule 8). 0.0 if leaf_cert is missing."""
        return self.explain(host, leaf_cert)["boost"]


if __name__ == "__main__":
    from .stage2_eval import main
    main()
