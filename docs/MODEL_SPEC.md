# Scamouflage — Detection Engine Spec (the "brain")

> **Read this whole file before writing any code.** It is the single source of truth for the
> detection engine. If something here conflicts with `CONTRACTS.md` about API/JSON field names,
> `CONTRACTS.md` wins for those names; for everything about how the engine decides, this file wins.
> If a requirement is unclear, ask the human instead of guessing.

Owners: **Vaishnavi** (Data, Stage 1, engine/decider + thresholds, evaluation) ·
**Shriya** (Stage 0 known list, Stage 2 certificate check, cert data, live pipeline, sealing) ·
**Shadow** (Stage 3 verifier: domain age + registrar, and the evidence stats).

---

## 1. What we are building (one paragraph)

Every new HTTPS certificate in the world is published in public Certificate Transparency logs.
Shriya's `certstream-server-go` on our IBM LinuxONE VM streams them (~700–900 unique certificates
per second, ~69 million per day). The engine looks at **each new website name** and decides, within
milliseconds, whether it is a **toll / delivery / government smishing scam site** (fake E-ZPass,
USPS, NTTA, DMV, IRS…). Scams are written to an **alerts database**; the website shows the latest
15, and the browser extension downloads a signed list of them to warn users. The point is to catch
scam sites **when their certificate is issued — before they appear on public blocklists.**

## 2. Hard rules (never break these)

1. **No synthetic data.** Every training/test example comes from a real source (phishing feeds,
   Tranco, official sites, the live certificate stream, crt.sh). Do not generate fake domains.
2. **Never visit a scam domain.** No HTTP requests, no browsers, no screenshots of label=1 names.
   Treat them as text. Stage 3 queries only registry metadata (RDAP), never the site itself.
3. **Never train on our own detections.** Only labels confirmed by outside feeds are training
   positives. (Training on our own output turns mistakes into "truth".)
4. **Never let the test set touch training** — not for fitting, not for picking thresholds, not for
   choosing features. Thresholds are picked on a validation split carved out of *train*.
5. **Train and run on the LinuxONE VM** (s390x, big-endian). Don't ship pickles trained on a Mac.
6. **Don't commit data.** `data/*.csv`, `labels.db*`, `models/*.joblib` stay out of git
   (`.gitignore`). Commit code, `thresholds.json`, and evaluation reports only.
7. **Fault-tolerant at runtime.** If Stage 2 or Stage 3 is temporarily unavailable (crash, timeout,
   network down), the engine keeps running with what it has and follows the fallback rules in §3.
   Wrap them in try/except + timeouts so one failure never stops the live stream.
8. **Stage 2 can only raise a score, never lower it.** A plain certificate is neutral, not innocent.
9. **Precision first.** A wrong alert on a real business is worse than a missed scam. When unsure
   and Stage 3 is unavailable, do not alert.
10. **Official sites are never flagged.** `labels/official.txt` is checked before any alert is saved.

## 3. The decision flow (exact order)

```
NEW CERTIFICATE (from certstream: leaf_cert with all_domains, issuer, not_before, not_after)
  │  for each name in all_domains (clean: lowercase, strip "*." and "www.")
  ▼
ALLOWLIST ── registered domain in official.txt? ──yes──► SAFE (stop)
  ▼
STAGE 0 — Known list ── exact host (or its registered domain) on our known-scam list? ──yes──►
          SCAM (stage=0, score=1.0) → save
  ▼
BRAND GATE ── name has a toll/delivery/gov brand word (labels/brands.txt) or a fake
              ".com-" / "gov-" / typo-of-brand pattern? ──no──► SAFE (stop)   ← ~99.9% stop here
  ▼
STAGE 1 — Name model → s1 ∈ [0,1]
          (runs after the gate: names failing the gate are SAFE whatever Stage 1 says, so
           skipping Stage 1 for them gives the identical result with ~1000× less model work)
  ▼
STAGE 2 — Certificate check → boost b ∈ [0, 0.6]
          final = 1 − (1 − s1) × (1 − b)          # can only go up
  ▼
SORT
  ├── final ≥ T_high          → HIGH  → Stage 3 "confirm"
  ├── T_low ≤ final < T_high  → MAYBE → Stage 3 "decide"
  └── final < T_low           → SAFE (stop)
  ▼
STAGE 3 — Verify (RDAP: domain age + registrar). Only HIGH and MAYBE names reach here.
  HIGH : age > 365 days and final < 0.99         → SAFE   (false alarm removed)
         otherwise                                → SCAM
         lookup failed / Stage 3 not installed    → SCAM   (trust the score)
  MAYBE: age ≤ 7 days, or (age ≤ 30 days and registrar in risky list) → SCAM (rescued)
         otherwise                                → SAFE
         lookup failed / Stage 3 not installed    → SAFE   (precision first)
  ▼
SCAM → write to alerts DB → seal (Ed25519, AFTER all fields are final) → website + extension
SAFE → not saved; only dashboard counters increase
```

Stages 0–2 run inline (must keep up with the stream). Stage 3 runs in a **separate worker** fed by
a queue, because RDAP calls take ~1 s. HIGH names are not visible as alerts until Stage 3 answers
or its timeout (10 s) passes.

Worked examples (use these as unit tests):

| name | s1 | gate | Stage 2 | final | sort | Stage 3 | result |
|---|---|---|---|---|---|---|---|
| `dallas-pizza.com` | 0.04 | no | – | – | – | – | SAFE |
| `ezpass.com-xk2.win` | 0.97 | yes | 5 toll lookalikes on cert, b=0.6 | 0.99 | HIGH | 2 h old | SCAM |
| `ezpas-toll.cfd` | 0.55 | yes | 1 name, b=0 | 0.55 | MAYBE | 4 h old, risky registrar | SCAM (rescued) |
| `austin-toll-repair.com` | 0.65 | yes | b=0 | 0.65 | HIGH | 8 years old | SAFE (false alarm removed) |
| `ntta.org` | – | – | – | – | – | – | SAFE (allowlist) |

## 4. Data

### 4.1 What exists (owner Vaishnavi; `labels/feeds.py`, `labels/build_dataset.py`)

| Source | Rows (approx.) | Label | Notes |
|---|---|---|---|
| Phishing feeds (OpenPhish, Phishing Database, Phishing Army, malware-filter, CERT.pl, phishunt, Unit 42 smishing files) | ~697,000 (growing hourly) | 1 | ~3,900 are toll/delivery/gov |
| Tranco top sites (minus anything on a scam list) | ~300,000 | 0 | includes brand-word sites as hard negatives |
| `labels/official.txt` | ~17 | 0 | real toll/USPS/IRS/DMV sites |
| Live stream sample (`seen` table, Shriya's VM) → `data/ct_sample.txt` | 20,000+ | 0 | most realistic normals; add before training |

All of it lives in **SQLite `labels.db`** (tables `labels`, `negatives`, `crtsh`, `pulls`).
`feeds.py loop` (tmux `v-feeds`) adds new feed entries every hour.

### 4.2 Training set (built by `build_dataset.py`)

- Clean → dedupe → drop names on both lists → keep **all** toll/delivery/gov scams + a stable sample
  of 150,000 generic scams → ~154k scam vs ~300k+ normal.
- Columns: `host, domain, group, label, category, source, first_listed`.
- **Split by `group` (campaign)**, 80/20, stable hash: lookalikes from one kit
  (`usps.com-abc.bid`, `usps.com-xyz.bid` → group `usps.com-*.bid`) never straddle train/test.
- `--cutoff <ISO time>` additionally writes `test_future.csv` (scams first listed after the cutoff)
  → the honest "catches new scams" number.
- **`source` and `first_listed` must never be used as features.**

### 4.3 The known-scam list for Stage 0 (owner Shriya)

Stage 0 checks against **all** known scams (~697k and growing), not the 154k training sample.

- Source of truth: `labels` table in `labels.db`.
- Move the live DB to a **shared path** on Shriya's VM, e.g. `~/scamouflage-data/labels.db`, and run
  the feeds loop with `SCAM_DB=~/scamouflage-data/labels.db` so both the loop and the engine use the
  same file (not someone's personal clone).
- The engine **loads all hosts into an in-memory `set`** at startup (~700k strings ≈ 100 MB, lookup
  is instant) and every 15 minutes loads only rows with `last_seen > last_refresh`. Never query
  SQLite per certificate.
- Match rule: exact host, or the registered domain if the registered domain itself is listed.
  Do **not** match on shared-hosting suffixes (github.io, pages.dev, firebaseapp.com…): use
  `tldextract` with private PSL domains so `x.github.io` is its own registered domain.
- SQLite must be opened in WAL mode with `timeout=30` (the feeds loop writes while we read).

### 4.4 Certificate data for Stage 2 (owner Shriya)

Stage 2 needs real certificates, not just names:

- **Live normals + live suspects:** extend the stream recorder to store the full `leaf_cert` JSON
  (`all_domains`, `issuer`, `not_before`, `not_after`, `seen_at`) for (a) every name that passes the
  brand gate and (b) a random 0.1% of everything else → table `certs` in a separate DB file
  (`certs.db`) so it never locks `labels.db`.
- **Positives:** (a) recorded certs whose names later show up on a feed (join `certs` with `labels`)
  — best quality; (b) crt.sh lookups for brand-tagged known-scam hosts (`feeds.py crtsh N`, extend to
  save SAN list + issuer + dates).
- **Era leak warning:** crt.sh certs of known scams are older than live normals. Use only
  era-stable features (§6.2). **Do not use issuer or validity length.**

## 5. Stage 0 — Known list (owner Shriya) — `model/stage0.py`

```python
class KnownList:
    def __init__(self, db_path: str): ...      # loads everything into a set
    def refresh(self) -> int: ...               # loads new rows, returns how many were added
    def check(self, host: str) -> dict | None:  # {"brand":..,"category":..,"feed":..} or None
```

**As built** (`python -m model.stage0 stats|check|bench`, tests in `tests/test_stage0.py`):
- **DB:** `default_db_path()` = `$LABELS_DB`, else `~/scamouflage-data/labels.db`. Opened read-only
  (`mode=ro`, `timeout=30`) only while loading; never queried per certificate.
- **Cleaning:** `features.clean_host` (same as the engine), on load and in `check()`.
- **Match:** (a) exact host, or (b) the host's registered domain (tldextract, private PSL on,
  bundled snapshot, never downloaded) is itself listed. An ending not on the PSL uses the last two
  labels. The PSL is only consulted when some parent of the name is listed (LRU cached).
- **Guards:** drop listed names that are a public suffix (107 rows), official or under an official
  site (2), or also in `negatives` (0); rule (b) never fires through a negative's registered domain
  (1 host). `both_lists` stops nothing because `feeds.py negatives` leaves out every name already
  on a scam list, so a poisoned big site (e.g. `nflxvideo.net`, listed by phishing_database) got
  through. **tranco_top guard:** if labels.db has a `tranco_top` table (Tranco top 100k by rank,
  NOT minus the scam lists; proposed `feeds.py tranco`, pending), drop a listed name that is itself
  in it. A listed name under a top site (`evil.weebly.com`) keeps its exact match; rule (b) never
  fires through a top site because a top site is never in the list. No table = guard off.
  Measured on a scratch copy of the VM DB (2026-10-17): removes 136 rows / 113 hosts (linkedin.com,
  github.com, nflxvideo.net, ups.com, bit.ly, ...; 1 branded: dhl24.com.pl). 59,089 listed tenants
  under 1,095 top domains (weebly.com, 000webhostapp.com, ...) stay as exact matches. Bench: 54 → 50
  hits, only the two `*.nflxvideo.net` names gone. Load 2.5 → 2.7 s, RSS +68.5 → +72.7 MB.
- **Refresh column:** `rowid` (not `last_seen`: feeds.py rewrites `last_seen` on every row each
  pull). Full reload if rows were deleted, the file replaced, or `official.txt` changed.
- **Measured on the VM** (2026-10-17, 697,829 rows → 544,038 hosts): load 2.8 s, +68.5 MB RSS per
  process (peak 135 MB); `check()` 326,862 names/s on one core; on 200,000 recorded CT names
  (114,840 certs), 54 hits (0.027 %), 35 certs (0.031 %).

## 6. Stage 1 — Name model (owner Vaishnavi) — `model/features.py`, `model/stage1.py`, `model/train_stage1.py`

### 6.1 Models
Two models, averaged after calibration:
1. **Char n-gram model:** `HashingVectorizer(analyzer="char_wb", ngram_range=(3,5), n_features=2**20)`
   → `LogisticRegression` (or `SGDClassifier(loss="log_loss")`), `class_weight="balanced"`.
2. **Handcrafted-feature model:** `name_features(host)` (~29 numbers: lengths, hyphens, digits,
   entropy, vowel ratio, risky TLD, brand-word flags by category, brand in subdomain vs name,
   brand typo (edit distance ≤ 2), fake `.com-`/`gov-` pattern, lure-word count, punycode…)
   → `HistGradientBoostingClassifier`. Optional IBM bonus: try `snapml` (IBM Snap ML, runs on Z)
   for this model and report its speed; fall back to sklearn if it isn't available on the VM.
- Calibrate each (`CalibratedClassifierCV`, isotonic or sigmoid) on the validation split, then
  `s1 = (p_ngram + p_feat) / 2`. Keep the option to report each alone in the eval.
- `official` feature is allowed but the allowlist (§3) is the real guard.

### 6.2 Validation and thresholds
- From `train.csv`, hold out a validation split **by `group`** (`GroupShuffleSplit`, 15%).
  Fit on the rest, calibrate + pick thresholds on validation, then refit on all of train with the
  same hyperparameters if time allows (thresholds stay).
- **Thresholds are about false alarms per day, measured honestly:**
  - `unique_names_per_day` = measured unique (deduped) **names** per day from the live stream
    (ask Shriya for the consumer's count; not the raw certificate count, not 69M certs).
  - `gate_rate` = fraction of live names passing **our** gate: run `features.brand_gate()` over the
    **1% random sample rows** of the `seen` table (`sampled = 1`) and take the pass fraction.
    Do NOT use the brand rows in `seen` — they were selected by Shriya's older regex.
  - `fpr_gated(T)` = fraction of **brand-gated normal** names in validation with final ≥ T
    (Tranco brand-word sites + gated `ct_stream` names are the hard negatives here).
  - `false_alarms_per_day(T) = unique_names_per_day × gate_rate × fpr_gated(T)`.
  - **T_high** = lowest T with `false_alarms_per_day(T) ≤ 50` *before* Stage 3.
  - **T_low** = lowest T where the estimated MAYBE volume (`unique_names_per_day/24 × gate_rate ×
    share of gated names between T_low and T_high`) ≤ 1,000 per hour (what Stage 3 can check).
    Never below 0.30.
  - If validation has too few gated normals to measure (<2,000), say so in the report and report
    the confidence interval; don't pretend.
- Write `models/thresholds.json`: `{t_high, t_low, gate_rate, unique_names_per_day, model_version,
  trained_at, n_train, n_val}`. Until it exists the engine uses placeholders 0.90 / 0.50.

### 6.2b Environment on the VM (check before training)
1. `~/scamouflage/.venv/bin/python -c "import sklearn, numpy, joblib; print(sklearn.__version__)"`
2. If that fails: `~/snapml-venv/bin/python -c "import sklearn, snapml; print(sklearn.__version__)"`
3. If neither has it: `~/scamouflage/.venv/bin/pip install scikit-learn joblib` (s390x wheels may
   need to build; if pip fails, ask Shriya before installing system packages).
Use whichever venv works for both training and the engine (the engine must load the same model).

### 6.3 Interface
```python
class Stage1:
    def __init__(self, model_dir="models"): ...
    def score(self, host: str) -> float: ...
    def score_many(self, hosts: list[str]) -> list[float]: ...   # batched; use this in the pipeline
```
Speed requirement: `score_many` ≥ **1,000 names/s** on one VM core (only gated names reach it, a
tiny fraction of the stream, but bursts happen). Measure and print it in the eval.

### 6.4 Evaluation — `model/evaluate.py` → `reports/stage1_eval.json` + `reports/stage1_eval.md`
On `test.csv` (and `test_future.csv` if present), report:
- PR-AUC, ROC-AUC; precision / recall at T_high and at T_low.
- **Toll / delivery / gov slice** separately (recall at T_high). This is the headline.
- Normal sites: FPR overall and FPR among gated; **estimated false alarms per day**.
- `official.txt` sites: must be 0 flagged.
- `test_future.csv` recall ("caught scams newer than anything we trained on").
- **Baseline:** "brand word present → scam" rule on the same test set. The model must beat it on
  precision at equal recall; show both. (Proves the ML adds value.)
- Speed (names/s), model sizes, train time, VM architecture (`uname -m`).
- 20 example rows each: true catches, misses, false alarms (as plain text, never links).

## 7. Stage 2 — Certificate check (owner Shriya) — `model/stage2.py`

```python
def cert_features(leaf_cert: dict) -> dict:
    # era-stable only:
    # n_names, n_registered_domains, brand_names_on_cert, brand_categories_on_cert,
    # wildcard (any "*." name), fake_pattern_names_on_cert (".com-", "gov-"),
    # risky_tld_names_on_cert
class Stage2:
    def __init__(self, model_dir="models"): ...
    def boost(self, host: str, leaf_cert: dict) -> float:   # 0.0 … 0.6, 0.0 if leaf_cert missing
```
- **v1 (must ship): points table, no training.** Example: +0.25 if ≥2 brand lookalikes on the cert,
  +0.15 more if ≥4; +0.15 if ≥3 registered domains on one cert with a brand word; +0.10 if ≥2 fake
  `.com-` names; +0.05 wildcard on a brand-word name; cap 0.6. Tune by looking at real certs.
- **v2 (only if time allows and ≥500 labeled scam certs):** small logistic regression on `cert_features` predicting
  scam, mapped to a boost with `b = min(0.6, max(0, p − 0.5) × 1.2)`. Report v1 vs v2 on held-out
  certs (split by registered domain).
- Must never return a negative number. Must not raise; on any error return 0.0 and log once.

## 8. Stage 3 — Verifier (owner Shadow) — `model/stage3.py`

Stage 3 is what turns a score into a confident verdict: it removes false alarms on long-established
sites (HIGH → SAFE) and rescues brand-new scam domains the name model was unsure about
(MAYBE → SCAM). It also supplies the facts shown on every alert ("registered 3 hours ago").

```python
def verify(host: str, timeout: float = 5.0) -> dict:
    # {"ok": bool, "domain": "ezpass.com-xk2.win", "age_days": 0.1 | None,
    #  "registered_at": "2026-10-17T14:02:00Z" | None, "registrar": "Gname.com Pte. Ltd." | None,
    #  "risky_registrar": bool, "error": None | "timeout" | "not_found" | ...}
```
- RDAP via `https://rdap.org/domain/<registered-domain>` (follows redirects to the right registry);
  read the `registration` event date and the registrar entity name. Python `requests` or `aiohttp`.
- Risky registrars (Unit 42 smishing research): Dominet (HK) (68.06%), NameSilo (11.85%), Gname
  (7.94%) — keep the list in `labels/risky_registrars.txt` so it's editable; match case-insensitively.
- Cache by registered domain (in memory + SQLite `rdap_cache.db`, 24 h). Max 2 requests/second
  overall; exponential backoff on 429. Never raise; return `ok=False` with an `error`.
- Standalone CLI for testing: `python3 model/stage3.py ezpass.com-xk2.win ntta.org`.
- The engine imports it inside try/except so the live stream never stops if RDAP is slow or down;
  in that case the "lookup failed" rules in §3 apply.

## 9. The engine — `model/engine.py` (owner Vaishnavi; called from `ingest/consumer.py`)

```python
from model.engine import Engine, load_stage3
engine = Engine.from_disk(labels_db="~/scamouflage-data/labels.db", model_dir="models")
verify = load_stage3()                                    # None if Stage 3 isn't installed
engine.decide_cert(leaf_cert, seen_at=None) -> list[dict] # one Decision per unique clean name; inline stages
engine.needs_verify(decision) -> bool                     # True for "high" / "maybe"
engine.finalize(decision, verify_result_or_None) -> dict  # applies §3 Stage 3 rules -> "scam" / "safe"
engine.decide_host(host) -> dict                          # one name, no cert (tests, "check a site")
```
Decision dict (all fields always present; `DECISION_FIELDS` in engine.py):
```json
{"host": "ezpass.com-xk2.win", "domain": "ezpass.com-xk2.win", "verdict": "safe|high|maybe|scam",
 "stage": 2, "score": 0.99, "s1": 0.97, "s2_boost": 0.6, "brand": "ezpass", "category": "toll",
 "verified": false, "age_days": null, "registrar": null, "risky_registrar": null,
 "model_version": "stage1-20261017T1900",
 "cert_seen_at": "2026-10-17T19:04:11Z", "decided_at": "2026-10-17T19:04:11Z"}
```
- `stage` = the last stage that decided: -1 allowlist, 0 known list, 1 brand gate, 2 scored
  (Stage 1+2), 3 verified by Stage 3.
- `verdict` after `decide_cert`: `safe`, `scam` (Stage 0 only), `high`, or `maybe`.
  After `finalize`: `scam` or `safe`.
- **The engine skeleton with stubs (Stage 0 knows nothing, Stage 1 returns 0.0, Stage 2 returns
  0.0, no Stage 3) is committed FIRST**, so Shriya can wire the consumer against the real interface.
  The engine logic (gate, combine, sort, finalize) is real from the start; only the stages are stubs.
- `tests/test_engine.py` covers the worked examples in §3 using fake stages.

## 10. Live integration (owner Shriya) — inside the existing `ingest/consumer.py`

No new pipeline script. `ingest/consumer.py` already does stream reading, batching, dedupe, stats,
lag, cert verification and signing (tested on 3.8M live certs). Shriya plugs in:
1. `engine.decide_cert(leaf_cert, seen_at)` per certificate (batch where convenient).
2. `scam` (Stage 0) → alert. `high`/`maybe` → Stage 3 queue (asyncio, concurrency 2) →
   `engine.finalize(d, verify(d["host"]) if verify else None)` → alert if `scam`.
   If `load_stage3()` returned None, finalize immediately with `None`.
3. Alerts table gets the Decision fields; the signed fields include them. Sign **after** finalize,
   when every field is set. Shriya syncs the schema with Jahir in `CONTRACTS.md`.
4. Dashboard counters (names checked, gate passes, high, maybe, scams by category, Stage 3
   confirms / removes / rescues) alongside the consumer's existing stats.
5. **Lead-time stats ("caught X hours before the blocklists") exclude `stage = 0`** — those were
   already on a blocklist when we saw them, so they can't count as caught early.

## 11. Repo layout and branches

```
labels/   feeds.py  build_dataset.py  brands.txt  official.txt                    (Vaishnavi)
          risky_registrars.txt                                                    (Shadow)
model/    features.py stage1.py train_stage1.py evaluate.py engine.py             (Vaishnavi)
          stage0.py stage2.py                                                     (Shriya)
          stage3.py                                                                (Shadow)
ingest/   consumer.py (existing; Engine plugged in)  cert recorder                 (Shriya)
tests/    test_engine.py test_stage1.py (V) · test_stage2.py (S) · test_stage3.py (Shadow)
          fixtures/leaf_cert_scam.json  fixtures/leaf_cert_normal.json  fixtures/hosts.txt
models/   stage1 files + thresholds.json                       (gitignored except thresholds.json)
reports/  stage1_eval.md/json  stage2_eval.md                  (committed)
```
Branches: `vaishnavi/engine`, `shriya/stage2-pipeline`, `shadow/stage3`. PRs to `main`.
Each person only edits their own files; shared files (`brands.txt`, `engine.py` interface) change
only by telling the owner first.

## 12. Work split and timeline

Model is trained **once** on the dataset snapshot (no retraining — hackathon scope).
Stage 0 stays current anyway because it reads the live-updated known list.

| When | Vaishnavi | Shriya | Shadow |
|---|---|---|---|
| 1:30–2 PM | 15-min call: agree on the interfaces in §5–§9 | same call | same call; §13 brief |
| 2–5 PM | rebuild dataset, push; train Stage 1 | move `labels.db` to shared path, restart feeds loop; start cert recorder; Stage 0 | builds Stage 3 |
| 5–8 PM | engine/decider, pick T_high/T_low, evaluation report | Stage 2 v1 (points); plug Engine into `ingest/consumer.py` (stub Stage 1 until the model lands) | tests + PR by 8 PM; start evidence stats (§13 step 11) |
| 8–11 PM | **together: plug everything in, run on the live stream** | together | together: watch Stage 3 on live alerts, tune rate limits |
| Sunday AM | final numbers for the docs | demo stats ("caught X h before the lists"), Stage 2 v2 if time | evidence stats for the deck (§13 step 11) |

Nobody is blocked: Shriya's first tasks need nothing from Vaishnavi, the pipeline can run against
the engine with a stub Stage 1 until the real model lands, and Stage 3 plugs in as soon as its PR
is merged.

## 13. Shadow's brief — Stage 3 step by step

Goal: one file, `model/stage3.py`. Give it a website name → it returns how old the domain is and
which company (registrar) sold it. It does **not** decide scam/safe; the engine does that.

1. Learn RDAP (10 min): open `https://rdap.org/domain/ntta.org` in a browser (safe domains only —
   never open scam sites). Find `events` → `eventAction: "registration"` → `eventDate`, and
   `entities` → role `registrar` → its name inside `vcardArray`.
2. Reduce to the registered domain first with `tldextract`: `pay.ezpass.com-xk2.win` → `ezpass.com-xk2.win`.
3. `requests.get("https://rdap.org/domain/<domain>", timeout=5)`, follow redirects.
4. Parse registration date → `age_days` (float); parse registrar name.
5. `labels/risky_registrars.txt` (one per line: `Dominet`, `NameSilo`, `Gname`); case-insensitive
   "contains" match → `risky_registrar: true`.
6. Never crash: timeout → `error:"timeout"`; 404 → `"not_found"`; 429 → wait, retry once, then
   `"rate_limited"`; anything else → `"other"`. Always return every key (None when unknown).
7. Cache answers 24 h in `data/rdap_cache.db` (SQLite); max 2 lookups/second.
8. CLI: `python3 model/stage3.py ntta.org usps.com google.com` prints one line per domain.
9. Tests (`tests/test_stage3.py`) with safe domains only: ntta.org, usps.com, google.com (old) and a
   made-up domain (not_found). Mock the network for the error cases.
10. Branch `shadow/stage3`, PR to main, **by 8 PM**. Touch only `model/stage3.py`,
    `tests/test_stage3.py`, `labels/risky_registrars.txt`, and `reports/stage3_evidence.*`.
11. **Evidence stats (for the deck), `model/stage3_stats.py`:** run `verify()` (cached, rate-limited)
    over the brand-tagged known toll/delivery/gov scams in `labels.db` (registry metadata only,
    never the sites) and write `reports/stage3_evidence.md` + `.json`:
    - age at first listing: median, and "X of N were under 3 days old";
    - registrar share vs Unit 42's published figures (Dominet / NameSilo / Gname);
    - the same for a sample of normal brand-word sites (should be years old);
    - once live alerts exist: how many HIGH were removed, how many MAYBE were rescued.
    Domains whose records are gone are counted as `not_found`, not dropped. Report N everywhere.

Prompt for Shadow's Claude: *"Read docs/MODEL_SPEC.md sections 2, 8 and 13. Build model/stage3.py
exactly to that interface, with tests, then the evidence stats in step 11. Never make requests to the
domains themselves, only rdap.org."*

## 14. Definition of done

- [ ] `test.csv` toll/delivery/gov recall at T_high reported; false alarms/day ≤ 50 (est.).
- [ ] 0 official sites flagged; baseline comparison in the report.
- [ ] `test_future.csv` recall reported.
- [ ] Engine runs on the live stream for ≥ 1 hour with lag < 60 s, with Stage 2 and Stage 3 on.
- [ ] Stage 3 evidence report: age/registrar of confirmed scams vs normal sites; HIGH removed / MAYBE rescued counts.
- [ ] Alerts appear in the DB, sealed, visible on the website's latest-15 and in `/api/blocklist`.
- [ ] Count of our alerts (stage ≥ 1 only — never stage 0) that later appeared on a feed, with
      median "hours earlier" (headline demo stat).
