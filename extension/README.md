# Scamouflage browser extension

Scamouflage is a Chrome extension (Manifest V3). It downloads Scamouflage's signed
list of flagged toll, delivery, USPS, DMV, and IRS scam domains, and shows a
full-page red warning before you use a flagged site.

**Privacy:** every check happens inside your browser. The extension downloads
the same list as everyone else (`GET /api/blocklist`) and compares SHA-256
hashes of hostnames locally. The server never learns which sites you visit,
with one exception you control: pressing **Report this site** on the warning
page sends that one hostname to `POST /api/abuse/draft` so the server can look
up the registrar's abuse contact and draft the e-mail (see below).

## Report this site

The red warning page has a third button, **Report this site**. It turns the
alert into a takedown request to the company the domain was registered with:

1. background.js sends the flagged hostname to `POST /api/abuse/draft`
   (`backend/abuse_report.py`). This is the only time a visited hostname leaves
   the browser, and the panel on the page says so. It is off in Demo mode.
2. The server finds the alert for that name (or a parent, down to the registered
   domain) and only continues if it clears the same bar as the blocklist: score
   ≥ 0.85 and a registration Stage 3 verified over RDAP (or a name already on a
   public scam list). Below that it answers 409 and the page explains why.
3. The server looks up the registrar's **abuse mailbox** in the domain's RDAP
   record (rdap.org only; the scam site is never contacted) and drafts a
   plain-text report: registered domain, registrar and IANA id, registration
   date, certificate SHA-256, issuer, CT log, first-seen time, crt.sh and RDAP
   links, the model's reasons and score, and the requested action
   (`clientHold`).
4. A dialog opens over the page with To / Registrar / Subject / the full text, **Open in my
   mail app** (a `mailto:` link) and **Copy text**. The person sends it from
   their own address, in their own name. The server sends nothing on this route
   and logs nothing about who asked.

The route is rate-limited per address (6/min, 40/h) and refuses names without
an eligible alert, so it cannot be used to look up arbitrary domains. Operators
on the VM additionally get `POST /api/abuse/report` (server-side sending, see
`RUNBOOK.md`); the extension never uses that.

## How it works

```
alerts table (SQLite) ──► backend/blocklist_route.py ──► GET /api/blocklist
                              hashes domains, signs the list with Ed25519
                                              │  (every 30 min, via SSH tunnel)
                                              ▼
extension/background.js ── verify signature ── save in chrome.storage.local
        │
        └─ on every page: hash hostname + parents locally ── match? ── warning.html
```

1. The backend returns `{payload, signature, key_id}`. `payload` is a JSON
   **string**, and the signature covers its exact UTF-8 bytes.
2. The extension checks the signature over that raw string with tweetnacl
   **before** calling `JSON.parse`. It rejects the new list (and keeps the old one)
   if the signature fails, the `key_id` is unknown, or `generated_at` is older
   than the saved list. That last check stops an attacker from replaying an old list.
3. For `a.b.com-xk2.win` it hashes `a.b.com-xk2.win`, `b.com-xk2.win`, and
   `com-xk2.win`. It never checks a single label like `win`.
4. If any of those hashes is on the allowlist (official sites), the site is not flagged.
   It is flagged if the full hostname matches an entry, or if a parent matches an
   entry with `match_subdomains: true`.

## Files

```
backend/
  blocklist_route.py      GET /api/blocklist + GET /api/pubkey (aiohttp). Assumed column names at the top.
  make_keys.py            creates the Ed25519 signing key, prints the public key
  sign_demo_list.py       builds + signs extension/demo_blocklist.json
  test_vectors.py         prints hashes/signature to compare with the JS tests
  official_domains.txt    official sites -> allowlist (labels/official.txt is merged in)
  no_wildcard_domains.txt big platforms that never get match_subdomains
extension/
  manifest.json
  config.js               backend URL default + trusted public keys
  background.js           service worker: sync, verify, check pages, badge
  matcher.js              pure functions: normalize, candidates, hash, match, verify
  warning.html/.js/.css   the red warning page
  popup.html/.js/.css     toolbar popup
  options.html/.js        settings page
  demo_blocklist.json     signed demo list (flags *.localhost test names only)
  lib/nacl-fast.min.js    tweetnacl 1.0.3 (bundled; MV3 forbids remote code)
  icons/
  tests/matcher.test.html in-browser tests (plus run-in-node.js for the terminal)
demo/
  index.html              harmless fake "pay your toll" page, clearly marked DEMO
```

## 1. Generate keys

On the VM, from the repo root:

```bash
.venv/bin/pip install -r requirements.txt       # adds tldextract
.venv/bin/python -m backend.make_keys
```

This writes the private key to `keys/blocklist_ed25519.pem` (chmod 600,
git-ignored) and prints the public key line for `config.js`, for example:

```
'scamouflage-vm-1': 'eugJKnIzUa+nVMw0SCTIGIpPGUvlNfWGYkYutLzV3gM=',
```

The VM key `scamouflage-vm-1` already exists, and `extension/config.js` `LIVE_KEYS`
already trusts it, so you don't need to run this again. Running `make_keys` again
just prints the existing public key. `GET /api/pubkey` returns the same key.

**Only if the key is lost or leaked:** on the VM, run
`.venv/bin/python -m backend.make_keys --force --key-id scamouflage-vm-2`. Then
replace the `LIVE_KEYS` entry in `config.js`, start the API with
`TOLLTRAP_KEY_ID=scamouflage-vm-2`, and click reload on the extension in
`chrome://extensions`. An extension that wasn't reloaded rejects the new list with
`unknown key_id` and keeps its last good list. See CONTRACTS.md §5. Never copy the
private key off the VM, and never commit or paste it.

## 2. Add the route to the aiohttp app

`api/server.py` already mounts it (it prints `blocklist route: on` at startup).
To add it to any other aiohttp app:

```python
from aiohttp import web
from backend.blocklist_route import setup_blocklist_route

app = web.Application()
setup_blocklist_route(app)          # adds GET /api/blocklist and GET /api/pubkey
web.run_app(app, host="127.0.0.1", port=8000)
```

Or run the route on its own (localhost only):

```bash
.venv/bin/python -m backend.blocklist_route --host 127.0.0.1 --port 8000
curl -s http://localhost:8000/api/blocklist | head -c 300
```

It signs with `keys/blocklist_ed25519.pem` and sends `key_id` `scamouflage-vm-1`
by default. Without the key it answers `503`.

Optional environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `TOLLTRAP_SIGNING_KEY` | `keys/blocklist_ed25519.pem` | path to the Ed25519 private key (never logged) |
| `TOLLTRAP_KEY_ID` | `scamouflage-vm-1` | `key_id` sent in the envelope; must be in `config.js` `LIVE_KEYS` |
| `SCAM_DB` | `$DATA_DIR/scamouflage.db` | SQLite file with the `alerts` table (same lookup as `api/server.py`) |
| `DATA_DIR` | the repo's `data/` folder | also where `models/thresholds.json` (training stats for the popup) is read from |
| `TOLLTRAP_BLOCKLIST_THRESHOLD` | `0.85` | minimum score to include |
| `TOLLTRAP_LIST_SOURCE` | `live` (`replay` if the DB name contains "replay") | the `source` field shown in the popup |
| `TOLLTRAP_BLOCKLIST_CACHE_S` | `60` | seconds to reuse a signed list before rebuilding |

If your `alerts` table uses other column names, edit `ALERTS_TABLE` and the
`COL_*` names at the top of `backend/blocklist_route.py`.

**What the backend emits:** for each flagged hostname, one entry for the exact
hostname (`match_subdomains: false`) and one for its registrable domain from
tldextract (`match_subdomains: true`). Entries are de-duplicated by hash, keeping
the highest score. A few safety rules apply:

- A public suffix (`win`, `co.uk`) is never emitted.
- For shared hosting in the Public Suffix List's private section (`evil.github.io`,
  `x.pages.dev`), the platform itself (`github.io`) is never emitted, and the
  tenant site (`evil.github.io`) never gets `match_subdomains`.
- Registrable domains in `no_wildcard_domains.txt` (for example `google.com`) never
  get `match_subdomains`, so one bad `sites.google.com` page can't flag all of Google.
- Official domains (`official_domains.txt`) and anything under them are never flagged.

tldextract uses its bundled Public Suffix List snapshot. It never downloads, so it
works on a VM without internet access.

## 3. Open the SSH tunnel

The API listens on localhost only. From your laptop:

```bash
ssh -L 8000:localhost:8000 user@vm
```

Keep that terminal open. `http://localhost:8000/api/blocklist` on your laptop now
reaches the VM.

## 4. Load the extension

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and pick the `extension/` folder.
4. Pin Scamouflage from the puzzle-piece menu. Click it: the popup shows how
   many flagged sites you're compared against, the last sync time, and the list
   source (with an "Open dashboard" link).

When you open a flagged site, the tab switches to the full-page red warning and
the popup also opens by itself as a red "Scam alert" (Chrome 127 or newer, and
only while the window is focused; otherwise just the warning page appears).

After editing any extension file, click the reload icon on the extension's card.

If the tunnel isn't up, the popup says **List unavailable** and the badge is a
grey `?`. It never says a site is safe. Once a list has loaded, a failed sync keeps
using the last good list, and the popup shows the error.

Badges: red `!` = flagged, green check = not on Scamouflage's list, grey `?` = no
list loaded yet, empty = page not checked (chrome://, the extension's own pages, localhost).

## 5. Run the demo (never open real scam sites)

```bash
# 1) serve the harmless demo page on this computer only
python3 -m http.server 5500 --bind 127.0.0.1 --directory demo
```

2. In the extension's options (popup, then **Settings**), turn on **Demo mode** and click **Save**.
   The popup shows a yellow DEMO MODE pill and "List source: demo". In demo mode the
   extension doesn't contact the backend.
3. Open these addresses. Chrome sends every `*.localhost` name to your own computer.

| URL | Expected |
|---|---|
| `http://ezpass.com-demo.localhost:5500/` | red warning (exact match) |
| `http://pay.ezpass.com-demo.localhost:5500/` | red warning (parent `com-demo.localhost` has `match_subdomains`) |
| `http://parent-only.localhost:5500/` | red warning (exact match) |
| `http://sub.parent-only.localhost:5500/` | no warning (that parent entry has no `match_subdomains`) |
| `http://localhost:5500/` | no warning: "Not on Scamouflage's list" |

To re-sign the demo list (for example after changing the demo entries):

```bash
.venv/bin/python -m backend.sign_demo_list
```

The demo key is stored in `keys/demo_ed25519.pem` (git-ignored). On a machine
without that file, the script creates a new demo key and prints the line to put in
`DEMO_KEYS` in `config.js`. The demo key is trusted **only** for the bundled demo
list, so it can't be used to fake a live list.

## 6. Run the tests

**Check that Python and JavaScript produce the same hashes:**

```bash
.venv/bin/python -m backend.test_vectors
```

The same hashes and the Python-signed test envelope are hard-coded in
`extension/tests/matcher.test.js`.

**Browser tests:** open `extension/tests/matcher.test.html` in Chrome, either directly
from disk or, with the extension loaded, at
`chrome-extension://<extension id>/tests/matcher.test.html` (the ID is on
`chrome://extensions`). The page title and summary say PASS or FAIL. The tests cover
exact match, parent match, a parent entry without `match_subdomains` (must not
match), the allowlist, never checking a single label like `win`, the hash vectors,
and signature checks (valid, tampered, re-formatted, unknown key, wrong key).

**Same tests in a terminal (Node 18+):**

```bash
node extension/tests/run-in-node.js
```

## Permissions (and why)

| Permission | Why |
|---|---|
| `storage` | Save the verified list and settings (`chrome.storage.local`), and the hostnames you chose to continue to (`chrome.storage.session`, cleared when the browser closes). |
| `alarms` | Re-download the list every 30 minutes, even after the service worker sleeps. |
| `webNavigation` | See when a tab starts loading a page (main frame only) so it can be checked before you use it. Chrome shows this as "Read your browsing history". The URLs stay in the browser. |
| `activeTab` | Lets the popup read the current tab's address while you have it open, to show its status. No broad `tabs` permission is needed: redirecting a tab to our own warning page works without it. |
| host `http://148.100.79.76:8000/*` | Lets the service worker download `/api/blocklist` from our LinuxONE server (the default backend), and ask `/api/abuse/draft` for a report when you press **Report this site**. |
| host `http://localhost:8000/*`, `http://127.0.0.1:8000/*` | The same through an SSH tunnel, if the server isn't reachable directly. |
| optional host `http://*/*`, `https://*/*` | **Not granted at install.** If you set a different backend URL in the options, Chrome asks for permission for just that one origin. |

No content scripts are injected into pages, and nothing loads from the network
except the list (and the report draft, when you ask for one). tweetnacl is
bundled because Manifest V3 forbids remote code.

## tweetnacl

`extension/lib/nacl-fast.min.js` is tweetnacl-js **1.0.3**, copied unchanged from
the npm package (license in `lib/tweetnacl-LICENSE.txt`).
SHA-256: `3ec535c004aeeb225785d8e93fb33bf99f52e399bd7dfc01969b5629baea5131`.

To fetch it again yourself:

```bash
npm pack tweetnacl@1.0.3 && tar xzf tweetnacl-1.0.3.tgz
cp package/nacl-fast.min.js extension/lib/
shasum -a 256 extension/lib/nacl-fast.min.js   # must match the hash above
```

## Wording rules

- Say "likely scam" or "flagged". Never say "confirmed scam".
- A site that isn't on the list is "Not on Scamouflage's list". Never "This site is
  safe": not being on the list doesn't prove a site is legitimate.
