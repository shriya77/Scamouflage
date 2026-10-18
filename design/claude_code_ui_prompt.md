# Task: restyle the Scamouflage website to match the approved design

The approved design is a single self-contained HTML file in this repo:

    design/scamouflage_demo.html

Open it and read it fully before changing anything. It is the visual reference: layout, colours, fonts, spacing, copy, and animations. It uses DUMMY data (hard-coded domains, scores and ticking numbers). The real website must keep using REAL data from our API.

## The one rule: change the look, not the behaviour

Only the UI changes. Nothing that already works may break.

- Do NOT change any backend code: the API (Jahir), the engine, the model, ingest/stream, crypto/signing, the database, or the extension logic.
- Do NOT rename, remove or change the shape of any API endpoint, or any field the frontend reads. Keep every existing fetch/poll call, its URL and its refresh interval.
- Do NOT add new backend endpoints. If a design section needs data the API doesn't provide, tell me and use the fallback described below. Don't invent an endpoint.
- Keep the three tabs and their routes/URLs exactly as they work now: Live (dashboard), Latest catches (15 newest), Get the extension.
- Keep the existing build setup and framework. Don't switch frameworks or add heavy libraries. If the design's CSS and JS can be ported as plain CSS and small components, do that.
- Scam domains are always plain text, never clickable links, and never fetched, opened or resolved by the site.

## Step 1: look before you touch (report back first)

Before editing, give me a short report:

1. Where the website code lives (folder, framework, entry file), and how it is served and built.
2. Every API call the frontend makes: URL, interval, and the fields it uses.
3. For each section of `design/scamouflage_demo.html`, which real data feeds it (table below). Mark anything with no data source.

Then wait for me to say go.

## Step 2: section-by-section mapping

Match the design exactly for each section, but wire it to real data:

| Design section | What it shows in the design | Real data to use |
|---|---|---|
| Header + tabs | Scamouflage wordmark, 3 tabs | Existing routes |
| Hero | Headline + short lead | Static copy from the design |
| Dark stream band | Blurred scrolling domain names; every ~5th is a scam in rust red (#A8432F) with a glow; a "catch" sign pops up with the domain, a one-line reason, category and score inside the rust box | Scam names and the sign come from the real latest alerts (domain, category, score, reason). The grey background names can stay decorative. Use the real recent safe names only if the API already gives them. |
| Stat line under the stream | Certificates checked, checked per second, chip signatures | Real live stats from the existing stats endpoint. Remove the design's random ticking. |
| "26 minutes of the internet, filtered down to the scams" funnel | 1,359,910 → 503 → 87, ratio captions, growing bars | These are real numbers from our recorded replay. Keep them as static copy exactly as in the design. |
| "How accurate is it?" bento | 99.8% caught (413 of 414), 99% right when it warns, 0.5 false alarms per 10k, 11,485 checked/sec, 432,589 real sites studied | Read from `/api/results` (results.json) if the field exists. Otherwise keep the design's numbers as static copy. Keep the count-up-on-scroll. |
| IBM LinuxONE section | Dark section, chip SVG with pulsing pins, race bars 4,386 vs 1,010/s, speedup list | Static copy and animation from the design |
| Trust strip | As in design | Static |
| Latest catches tab | "Receipt roll" list, newest first, rows expand to show why | Real 15 latest alerts from the existing endpoint, same polling. Expanded row shows the real reasons/fields we already have. The "Already known" group uses real Stage 0 alerts if the API marks them. Otherwise omit that group. |
| Get the extension tab | Install steps + warning page mock | Keep the real download link and install steps. The mock is static. |

If the API has no value for a design element, hide that element rather than showing fake data. Never ship the design's dummy domains or random numbers as if they were live.

## Style details to copy exactly

- Colours (CSS variables): `--paper #F6F4EE`, `--ink #22382C`, `--green #2C4A3A`, `--night #18211C`, `--rust #A8432F`, `--sand #F4E7CF`, gold `#C69B4E`.
- Fonts (Google Fonts): Overpass (headings), IBM Plex Sans (body), IBM Plex Mono (domains).
- Keep every animation from the design: stream drift, sign pop, rust glow pulse on scam names, funnel bars growing, count-ups, chip pin pulse, receipt rows arriving. Respect `prefers-reduced-motion` like the design does.
- Keep it responsive, matching the design's mobile rules (no horizontal scroll at phone width).

## Step 3: check nothing broke

When done:

1. Build and run the site locally, and click through all three tabs.
2. Confirm in the browser network tab / logs that every API call from Step 1 still fires and still succeeds.
3. Run the existing tests (`pytest` and any frontend tests). All must pass.
4. Show me `git diff --stat`. Only frontend files plus `design/` should appear. If any backend, engine, model, API or extension file changed, undo that change.
5. Don't commit data, models, databases or CSVs.

Commit on my branch `vaishnavi` with a clear message. Don't push to main until I've looked at it.
