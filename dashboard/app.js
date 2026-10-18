/* Scamouflage dashboard
 * Every number comes live from the LinuxONE API. If the connection drops,
 * pipeline counters fall back to example values and one banner says so.
 * Accuracy numbers are NEVER faked: until /api/results has them, the card says "Evaluation running…".
 */

// ===================== CONFIG: edit these =====================
const CONFIG = {
  // If the API serves this page (http://localhost:8000/), leave '' (same origin).
  // Otherwise (Live Server / python http.server) it uses localhost:8000 through your SSH tunnel.
  API_BASE: location.port === '8000' ? '' : 'http://localhost:8000',

  ENDPOINTS: {
    stats:   '/api/stats',       // live pipeline counters (+ recent domain names for the firehose, when added)
    alerts:  '/api/alerts',      // { items: [...] }
    catches: '/api/alerts?limit=200', // "Latest 15 scams" tab: filtered and deduped on the client
    summary: '/api/alerts/summary', // { known_total, new_total, total }
    results: '/api/results',     // model evaluation: precision, recall, pr_auc, false_alarms_per_10k, baselines
    leadtime: '/api/leadtime',   // median_days, share_before_any_feed, n
    bench:   '/api/hardware',    // CPACF on/off benchmark (static, fetched once)
    cpacf:   '/api/cpacf/live',  // live CPACF activity counters
  },
  WS_PATH: '/ws/live',           // live stream (domain names + alerts), optional

  EXTENSION_URL: '#',            // optional: a download link for the extension folder (shows a Download button)
  POLL_MS: 2000,
  CATCHES_LIMIT: 15,
  FIREHOSE_PX_PER_S: 45,         // stream scroll speed (slow enough to read, not distracting)
  CATCH_PAUSE_MS: 4500,          // how long the stream freezes on a catch
};
// Add ?replay to the URL to run a clearly-labelled demo replay (sample domains + a sample catch).
const REPLAY = new URLSearchParams(location.search).has('replay');
// ===============================================================

const $ = (s, el = document) => el.querySelector(s);
const fmt = n => (n == null || isNaN(n)) ? '–' : Math.round(n).toLocaleString();
const pick = (o, ...keys) => { for (const k of keys) if (o && o[k] != null) return o[k]; return undefined; };

async function getJSON(key) {
  try {
    const r = await fetch(CONFIG.API_BASE + CONFIG.ENDPOINTS[key], { cache: 'no-store' });
    if (!r.ok) return null;
    const data = await r.json();
    // The API marks placeholder responses with source: "mock". Never show those as live numbers.
    if (data && data.source === 'mock') return null;
    return data;
  } catch { return null; }
}
// Which data sources are showing example values. One banner covers them all.
const simSources = new Set();
function setSim(key, isSim) {
  if (isSim) simSources.add(key); else simSources.delete(key);
  $('#offline-banner').hidden = simSources.size === 0;
}
function setStatus(state, text) {
  const s = $('#status');
  s.classList.remove('live', 'offline');
  if (state) s.classList.add(state);
  $('#status-text').textContent = text;
}
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;     // textContent only: domain names are untrusted
  return e;
}

// ---------- Numbers: set directly (they refresh every 2 s, so no count-up animation) ----------
function countTo(id, target, decimals = 0, suffix = '') {
  const node = document.getElementById(id);
  if (!node) return;
  node.textContent = (target == null || isNaN(target))
    ? '–'
    : (decimals ? (+target).toFixed(decimals) : Math.round(target).toLocaleString()) + suffix;
}

// ---------- Alerts: tolerant of field names ----------
const TOLL = ['ntta','zipcash','tolltag','txtag','txdot','hctra','eztag','e-zpass','ezpass','sunpass','fastrak','thetollroads','ipass','ezdrive','quickpass','pikepass','peachpass','goodtogo','toll'];
const DELIVERY = ['usps','ups','fedex','dhl','deliver','redeliver','parcel','package','shipping','tracking'];
const GOV = ['dmv','irs','gov','citation','court','violation','ticket','fine'];
function guessCategory(d = '') {
  d = d.toLowerCase();
  if (TOLL.some(w => d.includes(w))) return 'toll';
  if (DELIVERY.some(w => d.includes(w))) return 'delivery';
  if (GOV.some(w => d.includes(w))) return 'gov';
  return 'other';
}
const toScore = v => { const n = Number(v); return isNaN(n) ? 0 : (n > 1 ? n / 100 : n); };
const toDate = v => {
  if (v == null) return null;
  if (typeof v === 'number') return new Date(v < 1e12 ? v * 1000 : v);
  const d = new Date(v); return isNaN(d) ? null : d;
};
const REASON_TEXT = {
  brand_in_subdomain: 'Brand name in front of a fake site', cheap_tld: 'Cheap web address ending',
  campaign_match: 'Matches a known scam campaign', typosquat: 'Misspelled brand name',
  random_token: 'Random-looking characters', burst: 'Many look-alike sites created at once',
  new_registrar: 'Registrar often used by scammers',
};
function humanReason(r) {
  if (typeof r !== 'string') r = r?.text || r?.label || r?.reason || String(r);
  return REASON_TEXT[r] || (r.charAt(0).toUpperCase() + r.slice(1)).replace(/_/g, ' ');
}
function normalizeAlert(a) {
  const domain = String(pick(a, 'domain', 'name', 'host', 'fqdn') ?? '');
  let reasons = pick(a, 'reasons', 'why', 'tags', 'explanations') ?? [];
  if (typeof reasons === 'string') reasons = reasons.split(/[;,|]/).map(s => s.trim()).filter(Boolean);
  const time = toDate(pick(a, 'ts', 'time', 'timestamp', 'cert_time', 'seen_at', 'created_at'));
  const sig = pick(a, 'signature', 'sig', 'seal', 'signed', 'signature_verified', 'seal_verified', 'sig_valid');
  return {
    id: String(pick(a, 'cert_id', 'id', 'alert_id', 'uid') ?? `${domain}|${time?.getTime() ?? ''}`),
    domain,
    score: toScore(pick(a, 'score', 'risk', 'risk_score', 'prob', 'probability')),
    reasons: reasons.map(humanReason),
    category: String(pick(a, 'category', 'brand_type', 'type') ?? guessCategory(domain)).toLowerCase(),
    time,
    stage: pick(a, 'stage'),
    sealed: sig === undefined ? null : !!sig,
    crtsh: pick(a, 'crtsh_url', 'crtsh') || `https://crt.sh/?q=${encodeURIComponent(domain)}`,
    confirmedBy: pick(a, 'confirmed_by', 'confirmed'),
    campaign: pick(a, 'campaign', 'campaign_template'),
    brand: pick(a, 'brand'),
    demo: !!a.__demo,
  };
}
function normalizeAlerts(raw) {
  const arr = Array.isArray(raw) ? raw : (raw?.items || raw?.alerts || raw?.data || raw?.results || []);
  return arr.map(normalizeAlert).sort((x, y) => (y.time?.getTime() || 0) - (x.time?.getTime() || 0));
}
const isKnown = a => Number(a.stage) === 0;   // stage 0 = already on a known public list

// ---------- Offline samples (pipeline counters only; never accuracy) ----------
const SAMPLE = {
  stats: { checked: 8563272, rate: 447, verifiedPct: 100, failed: 0, verifyMs: 0.21, lag: 0.09 },
  bench: {
    machine_type: '9175',
    results: {
      'verify (real CT certs)': { on: 8122, off: 1871, speedup: 4.34 },
      'Ed25519 sign (alerts)':  { on: 28082, off: 13949, speedup: 2.01 },
      'SHA-256 (cert DER)':     { on: 1437062, off: 219422, speedup: 6.55 },
      'SHA-256 (bulk)':         { on: 4543, off: 275, speedup: 16.53 },
    },
    verify_by_algo: { 'ecdsa-p384': { speedup: 7.18 }, 'ecdsa-p256': { speedup: 5.02 }, 'rsa-2048': { speedup: 1.04 } },
  },
  cpacf: { groups: { ecdsa_verify_per_s: 264, sha_per_s: 22150 }, totals: { 'KDSA ECDSA Verify P256': 1690866, 'KDSA ECDSA Verify P384': 1775204 } },
};
const REPLAY_DOMAINS = ['shop-autumn-sale.com','mail.northwind-co.net','api.trailcam.io','blog.greenleafgardens.org','cdn.pixelforge.app','portal.lakeside-dental.com','www.quietharbor.inn','status.cloudkite.dev','learn.mathbridge.edu','m.citybikes.co','assets.bluefinmedia.tv','go.fernandpine.com','app.ledgerly.finance','www.riverbendvet.com','docs.tinyhttp.dev','images.harvestmarket.store','vpn.acme-corp.net','beta.storyloom.ai','www.oakhillchurch.org','grafana.internal-ops.cloud'];
const REPLAY_CATCH = { domain: 'ntta.com-tollpay-x7q.win', score: 0.96, stage: 1, signature_verified: true,
  reasons: ['Toll agency name in front of a fake site', 'cheap_tld', 'Matches campaign brand.com-*.win'], __demo: true };

// =================================================================
// FIREHOSE: blurred live domains; a catch freezes it and de-cloaks
// =================================================================
const fh = {
  queue: [], seen: new Set(), x: 0, last: 0, pausedUntil: 0, catchQueue: [],
  track: null, strip: null, started: false, demoTimer: null,
};
// A plausible hostname: labels of letters/digits/-/_ (optional leading *.), at least one dot, ≤ 253 chars
const HOSTNAME = /^(\*\.)?[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+$/i;
function feedDomains(list) {
  if (!Array.isArray(list)) return;
  for (const d of list) {
    const raw = typeof d === 'string' ? d : (d?.domain ?? d?.name);
    const name = typeof raw === 'string' ? raw.trim() : '';
    if (!name || name.length > 253 || !HOSTNAME.test(name) || fh.seen.has(name)) continue;   // skip empty/invalid
    fh.seen.add(name);
    fh.queue.push(name);
  }
  if (fh.seen.size > 5000) fh.seen = new Set([...fh.seen].slice(-2000));
  if (fh.queue.length > 400) fh.queue.splice(0, fh.queue.length - 400);
  if (fh.queue.length) $('#fh-wait').hidden = true;
}
function extractDomains(obj) {
  if (!obj) return null;
  return pick(obj, 'recent_names', 'recent_domains', 'sample_domains', 'domains', 'recent', 'stream') ||
         (obj.domain && obj.type !== 'alert' ? [obj.domain] : null);
}
function fhFrame(now) {
  const dt = fh.last ? Math.min(0.05, (now - fh.last) / 1000) : 0;
  fh.last = now;
  const paused = now < fh.pausedUntil;
  $('.firehose').classList.toggle('paused', paused);

  if (!paused) {
    // A catch is waiting: de-cloak the item nearest the middle
    if (fh.catchQueue.length) { triggerCatch(fh.catchQueue.shift(), now); }
    else {
      const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
      fh.x -= (reduce ? 25 : CONFIG.FIREHOSE_PX_PER_S) * dt;
    }
  }
  // drop items that scrolled off the left
  const first = fh.track.firstElementChild;
  if (first) {
    const w = first.offsetWidth + 22;
    if (fh.x + w < 0) { first.remove(); fh.x += w; }
  }
  // append new items on the right
  const stripW = fh.strip.clientWidth;
  if (fh.track.scrollWidth + fh.x < stripW + 300 && fh.queue.length) {
    fh.track.append(el('span', 'fh-item', fh.queue.shift()));
  }
  fh.track.style.transform = `translateX(${fh.x}px)`;
  requestAnimationFrame(fhFrame);
}
function triggerCatch(alert, now) {
  if (!heroWins(alert)) return;   // empty, or worse than the catch already on the card
  // Pick the stream item closest to the middle and turn it into the scam domain
  const items = [...fh.track.children];
  const mid = fh.strip.clientWidth / 2;
  let best = null, bestD = Infinity;
  for (const it of items) {
    const c = it.offsetLeft + fh.x + it.offsetWidth / 2;
    const d = Math.abs(c - mid);
    if (d < bestD) { bestD = d; best = it; }
  }
  let target = best;
  if (!target) { target = el('span', 'fh-item'); fh.track.append(target); }
  target.textContent = alert.domain;
  target.classList.add('caught');
  fh.pausedUntil = now + CONFIG.CATCH_PAUSE_MS;
  showCatchCard(alert, true);
}
function startFirehose() {
  if (fh.started) return;
  fh.started = true;
  fh.track = $('#fh-track'); fh.strip = $('#fh-strip');
  requestAnimationFrame(fhFrame);
  connectWS();
  if (REPLAY) startReplay();
}
function startReplay() {
  $('#fh-demo').hidden = false;
  const loop = () => { fh.seen.clear(); feedDomains([...REPLAY_DOMAINS].sort(() => Math.random() - .5)); };
  loop(); setInterval(loop, 4000);
  setTimeout(function again() {
    const a = normalizeAlert({ ...REPLAY_CATCH, ts: Date.now() / 1000 });
    fh.catchQueue.push(a);
    setTimeout(again, 20000);
  }, 3500);
}

// Live WebSocket (optional): domain names and alerts pushed from the server
function connectWS() {
  let base = CONFIG.API_BASE || location.origin;
  base = base.replace(/^http/, 'ws');
  let ws;
  try { ws = new WebSocket(base + CONFIG.WS_PATH); } catch { return; }
  ws.onmessage = ev => {
    let msg; try { msg = JSON.parse(ev.data); } catch { return; }
    const msgs = Array.isArray(msg) ? msg : [msg];
    for (const m of msgs) {
      const d = (m && typeof m.data === 'object' && m.data) || m;   // server sends {type, source, data}
      if (m.type !== 'alert') feedDomains(extractDomains(d));       // alerts never go into the blurred stream
      if (m.type === 'cpacf' && d.groups && d.available !== false) renderCpacf(d);
      const al = m.type === 'alert' ? d : (m.alert || null);
      if (al && alertsPrimed) handleAlerts([normalizeAlert(al)]);   // before the first poll, the poll covers it
    }
  };
  ws.onclose = () => setTimeout(connectWS, 5000);
  ws.onerror = () => { try { ws.close(); } catch {} };
}

// ---------- Catch card ----------
function showCatchCard(a, animate) {
  if (heroRank(a) < 0) return;    // never render a card with no domain
  heroShown = heroRank(a);
  const card = $('#catch-card');
  card.hidden = false;
  const known = isKnown(a);
  card.classList.toggle('known', known);
  $('#cc-label').textContent = known ? 'Caught, already on a public list' : 'Just caught';
  $('#cc-time').textContent = a.time ? `· ${timeAgo(a.time)}` : '';
  $('#cc-demo').hidden = !a.demo;
  $('#cc-headline').textContent = catchHeadline(a);
  $('#cc-domain').textContent = a.domain;
  const score = Math.round(a.score * 100);
  $('#cc-score').textContent = score;
  $('#cc-score-fill').style.width = score + '%';
  const rs = $('#cc-reasons'); rs.replaceChildren();
  a.reasons.slice(0, 3).forEach(r => rs.append(el('li', null, plainReason(r))));
  const link = $('#cc-crtsh'); link.href = a.crtsh;
  $('#cc-stage').textContent = known ? 'Already on a public scam list' : 'Not on any public blocklist yet';
  $('#cc-seal').hidden = a.sealed !== true;
  if (animate) { card.classList.remove('snap'); void card.offsetWidth; card.classList.add('snap'); }
}

// "A fake DHL site", "A fake toll site", ... in words people use.
const BRAND_NAMES = {
  dhl: 'DHL', usps: 'USPS', ups: 'UPS', fedex: 'FedEx', ezpass: 'E-ZPass', 'e-zpass': 'E-ZPass',
  ntta: 'NTTA', txtag: 'TxTag', sunpass: 'SunPass', fastrak: 'FasTrak', peachpass: 'Peach Pass',
  ipass: 'I-PASS', irs: 'IRS', dmv: 'DMV', txdmv: 'Texas DMV', hctra: 'HCTRA', eztag: 'EZ TAG',
};
const LURE_WORDS = new Set(['toll', 'tolls', 'parcel', 'package', 'redeliver', 'deliver', 'delivery',
  'shipping', 'tracking', 'citation', 'violation', 'ticket', 'fine', 'courtfee', 'paytoll']);
const CATEGORY_WORDS = { toll: 'toll', delivery: 'delivery', gov: 'government' };
function catchHeadline(a) {
  const brand = String(a.brand ?? '').toLowerCase();
  if (brand && !LURE_WORDS.has(brand)) {
    const name = BRAND_NAMES[brand] || (brand.length <= 4 ? brand.toUpperCase() : brand.charAt(0).toUpperCase() + brand.slice(1));
    return `A fake ${name} site`;
  }
  return CATEGORY_WORDS[a.category] ? `A fake ${CATEGORY_WORDS[a.category]} site` : 'A likely scam site';
}
// Turn the model's terse reasons into short sentences.
function plainReason(r) {
  const m = /^name model score\s+([\d.]+)/i.exec(r);
  if (m) return `Our AI scored the name ${Math.round(+m[1] * 100)} out of 100.`;
  const s = r.trim();
  return /[.!?]$/.test(s) ? s : s + '.';
}

// ---------- Alert bookkeeping ----------
// Catch card priority: a NEW toll/delivery/gov catch (stage != 0) > a known-list toll/delivery/gov
// site > anything else ("other"). -1 = no domain, never shown.
const heroRank = a => !String(a?.domain ?? '').trim() ? -1
  : SCAM_CATEGORIES.has(a.category) ? (isKnown(a) ? 2 : 3) : 1;
let heroShown = -1;               // rank of the catch on the card now
// A new scam always takes the card; otherwise only something better, or an equally good scam
const heroWins = a => {
  const r = heroRank(a);
  return r >= 0 && (r === 3 || r > heroShown || (r === heroShown && r >= 2));
};

const seenAlerts = new Set();
let alertsPrimed = false;
let latestAlerts = [];
function handleAlerts(list) {
  if (!alertsPrimed) {
    list.forEach(a => seenAlerts.add(a.id));
    alertsPrimed = true;
    // Show the best catch without the animation: highest rank, newest first among equals
    const best = list.reduce((b, a) => heroRank(a) > heroRank(b) ? a : b, null);
    if (best) showCatchCard(best, false);
    return;
  }
  const fresh = list.filter(a => !seenAlerts.has(a.id));
  fresh.forEach(a => seenAlerts.add(a.id));
  fresh.reverse().filter(a => heroRank(a) >= 0).forEach(a => fh.catchQueue.push(a));   // oldest first
  fresh.slice(0, 3).forEach(() => window.ScamWallpaper?.ping());   // red flash on the live background
}

// ---------- Rendering helpers ----------
function timeAgo(d) {
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${Math.round(s)} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return d.toLocaleDateString();
}
const level = s => s >= .9 ? 'high' : s >= .75 ? 'mid' : 'low';
const CAT = {
  toll: { label: 'Toll' }, delivery: { label: 'Delivery' },
  gov: { label: 'Government' }, other: { label: 'Other' },
};

// =================================================================
// DASHBOARD
// =================================================================
let benchCache = null;
let simTick = 0;
async function loadDashboard() {
  const [statsRaw, alertsRaw, resultsRaw, benchRaw, cpacfRaw, summaryRaw, leadRaw] = await Promise.all([
    getJSON('stats'), getJSON('alerts'), getJSON('results'),
    benchCache ? Promise.resolve(benchCache) : getJSON('bench'),
    getJSON('cpacf'), getJSON('summary'), getJSON('leadtime'),
  ]);
  if (benchRaw?.results) benchCache = benchRaw;

  const apiUp = !!(statsRaw || alertsRaw || cpacfRaw);
  setStatus(apiUp ? 'live' : 'offline', apiUp ? 'Live' : 'Offline');

  // ---- Firehose feed from stats (until the WebSocket is used) ----
  if (statsRaw) feedDomains(extractDomains(statsRaw));

  // ---- Top counters ----
  let stats;
  if (statsRaw) {
    // Of the certificates we could check: ok / (ok + fail). unknown_issuer (mostly precerts with no
    // certificate bytes, or an issuer not cached yet) has nothing to check, so it isn't counted either way.
    const v = statsRaw.verify || {};
    const failed = (v.fail || 0) + (v.failed || 0) + (v.bad || 0);
    const checkable = (v.ok || 0) + failed;
    stats = {
      checked: pick(statsRaw, 'processed_total', 'certs_total'),
      rate: pick(statsRaw, 'certs_per_s'),
      verifiedPct: checkable ? Math.floor(((v.ok || 0) / checkable) * 10000) / 100 : null,
      failed: checkable ? failed : null,
      verifyMs: pick(statsRaw, 'avg_verify_ms'),
      lag: pick(statsRaw, 'lag_s'),
    };
    setSim('stats', false);
  } else {
    simTick++;
    stats = { ...SAMPLE.stats, checked: SAMPLE.stats.checked + simTick * SAMPLE.stats.rate * (CONFIG.POLL_MS / 1000) };
    setSim('stats', true);
  }
  countTo('stat-checked', stats.checked);
  countTo('stat-rate', stats.rate);
  countTo('stat-hw', stats.verifiedPct, stats.verifiedPct === 100 ? 0 : 2, '%');
  $('#stat-rate-sub').textContent = stats.verifyMs != null
    ? `Each one verified in ${(+stats.verifyMs).toFixed(2)} ms · ${(+stats.lag || 0).toFixed(2)} s behind live`
    : 'Live from public certificate logs';
  $('#fh-rate').textContent = stats.rate ? `· showing a sample of ${fmt(stats.rate)} per second` : '';

  const bench = benchCache || SAMPLE.bench;
  const verifyX = bench.results?.['verify (real CT certs)']?.speedup;
  const failedText = stats.failed != null ? `${fmt(stats.failed)} failed · ` : '';
  $('#stat-hw-sub').textContent = failedText + (verifyX
    ? `checked on IBM CPACF, ${(+verifyX).toFixed(1)}× faster than software`
    : 'each checked against its issuer');

  // ---- Alerts: new vs already-known, breakdown, catch moment ----
  const list = alertsRaw ? normalizeAlerts(alertsRaw) : [];
  latestAlerts = list;
  if (alertsRaw) handleAlerts(list);
  const knownCount = pick(summaryRaw, 'known_total') ?? pick(statsRaw, 'alerts_known', 'known_total') ?? list.filter(isKnown).length;
  const newCount = pick(summaryRaw, 'new_total') ?? pick(statsRaw, 'alerts_new', 'new_total') ??
                   Math.max(0, (pick(statsRaw, 'alerts_total') ?? list.length) - knownCount);
  countTo('stat-new', newCount);
  $('#stat-new').classList.toggle('hot', newCount > 0);
  $('#stat-known').textContent = knownCount > 0
    ? `Plus ${fmt(knownCount)} already on known lists`
    : 'Not yet on any public blocklist';

  renderBreakdown(await loadBreakdown(), !!alertsRaw);

  // ---- Accuracy: real results or "Evaluation running…" ----
  renderResults(resultsRaw, leadRaw);

  // ---- IBM panel ----
  renderBench(bench);
  setSim('bench', !benchCache);
  if (cpacfRaw?.groups && cpacfRaw.available !== false) { renderCpacf(cpacfRaw); setSim('cpacf', false); }
  else { renderCpacf(SAMPLE.cpacf); setSim('cpacf', true); }
}

// Scam types in the last 24 h. Its own query (the alerts list above is only the newest 100), each
// site counted once. Only toll / delivery / gov get a row; "other" (generic phishing, almost all
// already on public lists) is one quiet line so it can't drown the three that matter.
const BREAKDOWN_HOURS = 24;
async function loadBreakdown() {
  try {
    const since = Math.floor(Date.now() / 1000) - BREAKDOWN_HOURS * 3600;
    const r = await fetch(`${CONFIG.API_BASE}${CONFIG.ENDPOINTS.alerts}?since=${since}&limit=1000`, { cache: 'no-store' });
    if (!r.ok) return null;
    const data = await r.json();
    return data?.source === 'live' ? normalizeAlerts(data) : null;
  } catch { return null; }
}

function renderBreakdown(list, reached) {
  const box = $('#breakdown');
  box.replaceChildren();
  if (!list) {
    box.append(el('p', 'bd-empty', reached ? 'No scam sites in the last 24 hours yet.' : 'Waiting for the live API…'));
    $('#story-24h').textContent = reached ? '0' : '–';
    return;
  }
  const bySite = new Map();                         // newest first: keep each site's newest alert
  for (const a of list) {
    const site = registeredSite(String(a.domain ?? '').toLowerCase());
    if (site && !bySite.has(site)) bySite.set(site, a);
  }
  const groups = { toll: [], delivery: [], gov: [], other: [] };
  for (const a of bySite.values()) (groups[a.category] || groups.other).push(a);
  const keys = ['toll', 'delivery', 'gov'];
  const total = keys.reduce((n, k) => n + groups[k].length, 0);
  const max = Math.max(1, ...keys.map(k => groups[k].length));
  $('#story-24h').textContent = fmt(total);

  const head = el('div', 'bd-total');
  head.append(el('span', 'bd-total-num', fmt(total)),
              el('span', 'bd-total-label', `toll, delivery & government scam sites caught in the last\u00a0${BREAKDOWN_HOURS}\u00a0hours`));
  box.append(head);

  for (const k of keys) {
    const row = el('div', 'bd-row');
    const top = el('div', 'bd-top');
    top.append(el('span', 'bd-name', CAT[k].label), el('span', 'bd-num', fmt(groups[k].length)));
    const track = el('div', 'bd-track');
    const fill = el('div', 'bd-fill'); fill.style.width = (groups[k].length / max * 100) + '%';
    track.append(fill);
    const ex = groups[k][0];
    row.append(top, track, el('div', 'bd-example', ex ? String(ex.domain) : 'none yet'));   // plain text, never a link
    box.append(row);
  }
  if (groups.other.length) {
    box.append(el('p', 'bd-other', `+ ${fmt(groups.other.length)} other phishing sites, mostly already on public blocklists`));
  }
}

function renderResults(raw, lead) {
  // /api/results: { precision, recall, pr_auc, false_alarms_per_10k, baselines: { unit42_regex, keyword_rule } }
  // /api/leadtime: { median_days, min_days, max_days, share_before_any_feed, n }
  const r = raw?.results && typeof raw.results === 'object' && !Array.isArray(raw.results) ? raw.results : raw;
  const recall = pick(r, 'recall', 'test_recall');
  const prec   = pick(r, 'precision', 'test_precision');
  const prAuc  = pick(r, 'pr_auc');
  const fa10k  = pick(r, 'false_alarms_per_10k', 'fa_per_10k');
  const leadOk = lead && Number(lead.n) > 0;
  const leadDays = leadOk ? pick(lead, 'median_days') : null;
  const leadShare = leadOk ? pick(lead, 'share_before_any_feed') : null;

  const box = $('#metrics');
  const hasAny = [recall, prec, fa10k].some(v => v != null && !isNaN(v)) || leadOk;
  const key = JSON.stringify([recall, prec, prAuc, fa10k, leadDays, leadShare, lead?.n, r?.baselines]);
  if (box.dataset.key === key) return;          // avoid re-rendering every poll
  box.dataset.key = key;
  box.replaceChildren();

  if (!hasAny) {
    const p = el('div', 'eval-pending');
    p.append(el('div', 'spinner'), el('strong', null, 'Evaluation running…'),
      el('span', 'fine', 'Real test-set numbers appear here as soon as the model finishes evaluating. We never show placeholder accuracy.'));
    box.append(p);
    return;
  }
  const pct = v => Math.round(v <= 1 ? v * 100 : v) + '%';
  if (fa10k != null) {
    const h = el('div', 'metric metric-hero');
    h.append(el('div', 'metric-value', (+fa10k).toFixed(2)),
      el('div', 'metric-label', 'False alarms per 10,000 normal sites'),
      el('div', 'metric-tech', 'Real websites wrongly flagged, on the held-out test set'));
    box.append(h);
  }
  const grid = el('div', 'metrics');
  const tiles = [];
  if (recall != null) tiles.push([pct(recall), 'Scams caught', 'Recall on held-out test set']);
  if (prec != null) tiles.push([pct(prec), 'Right when it warns', 'Precision']);
  if (leadDays != null) tiles.push([leadDays < 2 ? `${Math.round(leadDays * 24)} h` : `${(+leadDays).toFixed(1)} days`, 'Head start on public blocklists', `Median over ${fmt(lead.n)} catches`]);
  if (leadShare != null) tiles.push([pct(leadShare), 'Caught before any public feed', 'Share of catches we flagged first']);
  if (prAuc != null && tiles.length < 4) tiles.push([(+prAuc).toFixed(2), 'PR-AUC', 'Overall ranking quality (1.0 is perfect)']);
  tiles.forEach(([val, label, tech]) => {
    const t = el('div', 'metric');
    t.append(el('div', 'metric-value', val), el('div', 'metric-label', label), el('div', 'metric-tech', tech));
    grid.append(t);
  });
  if (tiles.length) box.append(grid);

  // Model vs. simple baselines (only rows that have numbers)
  const rows = [['Scamouflage AI', { recall, precision: prec, false_alarms_per_10k: fa10k }, true]];
  const b = r?.baselines || {};
  if (b.unit42_regex) rows.push(['Unit 42 regex patterns', b.unit42_regex, false]);
  if (b.keyword_rule) rows.push(['Keyword rule', b.keyword_rule, false]);
  const filled = rows.filter(([, v]) => v && ['recall', 'precision', 'false_alarms_per_10k'].some(k => v[k] != null));
  if (filled.length > 1) {
    const table = el('table', 'baseline-table');
    const head = el('tr');
    ['', 'Scams caught', 'Right when it warns', 'False alarms / 10k'].forEach(h => head.append(el('th', null, h)));
    table.append(head);
    filled.forEach(([name, v, ours]) => {
      const tr = el('tr', ours ? 'ours' : '');
      tr.append(el('td', null, name),
        el('td', null, v.recall != null ? pct(v.recall) : '–'),
        el('td', null, v.precision != null ? pct(v.precision) : '–'),
        el('td', null, v.false_alarms_per_10k != null ? (+v.false_alarms_per_10k).toFixed(+v.false_alarms_per_10k < 1 ? 2 : 1) : '–'));
      table.append(tr);
    });
    const wrap = el('div', 'baseline-wrap');
    wrap.append(el('div', 'fine', 'Compared with simple rules on the same test set'), table);
    box.append(wrap);
  }
}

// ---------- IBM CPACF: live counters + chip on vs off ----------
const MACHINES = { '9175': 'IBM z17', '9176': 'IBM z17', '3931': 'IBM z16', '3932': 'IBM z16', '8561': 'IBM z15', '8562': 'IBM z15' };
let benchRendered = false;
function renderBench(hw) {
  const m = MACHINES[String(hw.machine_type)];
  $('#bench-machine').textContent = m
    ? `Measured on our ${m} server (machine type ${hw.machine_type}), with the chip on vs. switched off`
    : 'Measured on our server, with the chip on vs. switched off';
  $('#chip-name').textContent = m ? m.toUpperCase() : 'IBM Z';
  if (benchRendered && hw === renderBench.last) return;
  renderBench.last = hw; benchRendered = true;

  const res = hw.results || {};
  const v = res['verify (real CT certs)'];
  const on = v?.on || 0, off = v?.off || 0, max = Math.max(on, off, 1);
  $('#race-on').style.width = (on / max * 100) + '%';
  $('#race-off').style.width = (off / max * 100) + '%';
  $('#race-on-num').textContent = on ? `${fmt(on)}/s` : '–';
  $('#race-off-num').textContent = off ? `${fmt(off)}/s` : '–';
  $('#race-x').textContent = v?.speedup ? `${(+v.speedup).toFixed(1)}×` : '–';

  const items = [];
  const algo = hw.verify_by_algo || {};
  if (algo['ecdsa-p384']) items.push([algo['ecdsa-p384'].speedup, 'ECDSA P-384 signature checks']);
  if (algo['ecdsa-p256']) items.push([algo['ecdsa-p256'].speedup, 'ECDSA P-256 signature checks']);
  if (res['SHA-256 (bulk)']) items.push([res['SHA-256 (bulk)'].speedup, 'SHA-256 hashing (bulk)']);
  if (res['SHA-256 (cert DER)']) items.push([res['SHA-256 (cert DER)'].speedup, 'Certificate fingerprints']);
  if (res['Ed25519 sign (alerts)']) items.push([res['Ed25519 sign (alerts)'].speedup, 'Signing our alerts (Ed25519)']);
  const rsa = algo['rsa-2048'] || algo['rsa-4096'];
  if (rsa) items.push([rsa.speedup, 'RSA (not accelerated by CPACF)']);
  const box = $('#speed-list'); box.replaceChildren();
  items.forEach(([x, label]) => {
    const it = el('div', `speed-item ${x < 1.5 ? 'flat' : ''}`);
    it.append(el('div', 'sx', `${(+x).toFixed(1)}×`), el('div', 'sl', label));
    box.append(it);
  });
}
function renderCpacf(c) {
  const g = c.groups || {}, t = c.totals || {};
  const ecdsaTotal = Object.entries(t).filter(([k]) => k.startsWith('KDSA ECDSA Verify')).reduce((a, [, v]) => a + v, 0);
  countTo('cpacf-verify', g.ecdsa_verify_per_s);
  countTo('cpacf-sha', g.sha_per_s);
  countTo('cpacf-total', ecdsaTotal);
  chip.rate = g.ecdsa_verify_per_s || 0;
}

// Chip graphic: pins light up in proportion to live CPACF signature checks.
// Capped so it stays calm: at most CHIP_MAX_FLASHES a second, however busy the chip is.
const CHIP_MAX_FLASHES = 12;
const chip = { rate: 0, pins: [], acc: 0, last: 0 };
function buildChip() {
  const svg = $('.chip-svg'), ns = 'http://www.w3.org/2000/svg';
  if (!svg) return;
  const pins = svg.querySelector('.pins'), grid = svg.querySelector('.chip-grid');
  const line = (parent, [x1, y1, x2, y2], cls) => {
    const l = document.createElementNS(ns, 'line');
    l.setAttribute('x1', x1); l.setAttribute('y1', y1); l.setAttribute('x2', x2); l.setAttribute('y2', y2);
    if (cls) l.setAttribute('class', cls);
    parent.append(l);
    return l;
  };
  for (let i = 0; i < 8; i++) {
    const p = 58 + i * 17.7;
    [[p, 40, p, 20], [p, 200, p, 220], [40, p, 20, p], [200, p, 220, p]].forEach(c => chip.pins.push(line(pins, c, 'pin')));
  }
  for (let i = 1; i < 6; i++) {
    const p = 58 + i * (124 / 6);
    line(grid, [p, 58, p, 182]); line(grid, [58, p, 182, p]);
  }
  if (!matchMedia('(prefers-reduced-motion: reduce)').matches) requestAnimationFrame(chipFrame);
}
function chipFrame(now) {
  const dt = chip.last ? Math.min(0.25, (now - chip.last) / 1000) : 0; chip.last = now;
  chip.acc += Math.min(CHIP_MAX_FLASHES, chip.rate / 20) * dt;
  while (chip.acc >= 1) {
    chip.acc -= 1;
    const pin = chip.pins[Math.floor(Math.random() * chip.pins.length)];
    pin.classList.add('lit'); setTimeout(() => pin.classList.remove('lit'), 260);
  }
  requestAnimationFrame(chipFrame);
}

// =================================================================
// LATEST 15 SCAMS tab
// =================================================================
const SCAM_CATEGORIES = new Set(['toll', 'delivery', 'gov']);
const decidedMs = a => toDate(a.decided_at)?.getTime() || 0;   // ISO UTC; missing sorts last
// Only https://crt.sh/ links are ever clickable. Scam domains stay plain text.
const crtshLink = u => (typeof u === 'string' && u.startsWith('https://crt.sh/')) ? u : null;

// ---------- Registered site (eTLD+1), so one site can't fill the list ----------
// Small stand-in for the Public Suffix List: common two-part country suffixes...
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au', 'gov.au', 'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'co.jp', 'ne.jp', 'or.jp', 'go.jp',
  'com.br', 'net.br', 'gov.br', 'com.mx', 'gob.mx', 'com.ar', 'com.co', 'com.pe',
  'co.in', 'net.in', 'org.in', 'gov.in', 'co.za', 'gov.za', 'co.kr', 'or.kr', 'co.id', 'go.id',
  'co.th', 'in.th', 'com.cn', 'gov.cn', 'com.hk', 'com.tw', 'com.sg', 'gov.sg', 'com.my', 'gov.my',
  'com.vn', 'com.pk', 'com.ng', 'com.tr', 'gov.tr', 'com.ua', 'co.il', 'com.eg', 'com.sa',
]);
// ...and shared hosts where every subdomain is a different owner's site.
const SHARED_HOSTS = ['pages.dev', 'mybluehost.me', 'vercel.app', 'netlify.app', 'github.io',
                      'workers.dev', 'web.app', 'firebaseapp.com', 'amplifyapp.com'];

function registeredSite(host) {
  const h = String(host ?? '').toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  if (!h.includes('.') || /^[\d.]+$/.test(h) || h.includes(':')) return h;   // bare name or IP
  const labels = h.split('.');
  for (const s of SHARED_HOSTS) {
    if (h === s) return h;
    if (h.endsWith('.' + s)) return labels.slice(-(s.split('.').length + 1)).join('.');
  }
  const n = MULTI_PART_SUFFIXES.has(labels.slice(-2).join('.')) ? 3 : 2;
  return labels.slice(-n).join('.');
}
// Prefer a registered-domain field if the API/engine ever sends one.
const siteOf = a => String(a.registered_domain ?? a.site ?? a.etld1 ?? registeredSite(a.domain)).toLowerCase();

// /api/alerts?limit=200 -> toll/delivery/gov only, newest decided_at first, newest alert per site, first 15
function latestScams(raw) {
  const rows = (raw?.items || [])
    .filter(a => SCAM_CATEGORIES.has(String(a.category ?? '').toLowerCase()))
    .sort((x, y) => decidedMs(y) - decidedMs(x));   // stable: ties keep the API's newest-first order
  const sites = new Map();                          // site -> { newest alert, all names seen }; newest site first
  for (const a of rows) {
    const site = siteOf(a);
    if (!sites.has(site)) sites.set(site, { a, names: new Set() });
    sites.get(site).names.add(String(a.domain ?? '').toLowerCase());
  }
  return [...sites].slice(0, CONFIG.CATCHES_LIMIT).map(([site, { a, names }]) => ({
    ...normalizeAlert(a),                           // stage null -> undefined, so isKnown() treats it as new
    category: String(a.category).toLowerCase(),
    brand: a.brand, ageDays: a.age_days, registrar: a.registrar,
    decided: toDate(a.decided_at), decidedRaw: a.decided_at,
    crtsh: crtshLink(a.crtsh_url),
    site, moreNames: names.size - 1,
  }));
}

function fmtAge(days) {
  const d = Number(days);
  if (days == null || isNaN(d)) return null;
  if (d < 1) return `${Math.max(1, Math.round(d * 24))} h`;
  return `${d < 10 ? d.toFixed(1) : Math.round(d)} days`;
}

async function loadCatches() {
  const btn = $('#refresh-btn');
  btn.disabled = true; btn.textContent = 'Loading…';
  const raw = await getJSON('catches');
  renderCatches(raw ? latestScams(raw) : [], !!raw);
  btn.disabled = false; btn.textContent = '↻ Refresh';
}
function renderCatches(list, reached) {
  const fresh = list.filter(a => !isKnown(a)), known = list.filter(isKnown);
  [['new', fresh], ['known', known]].forEach(([key, rows]) => {
    $(`#group-${key}`).hidden = rows.length === 0;
    $(`#count-${key}`).textContent = rows.length;
    $(`#list-${key}`).replaceChildren(...rows.map(scamRow));
  });
  const empty = $('#catch-empty');
  empty.hidden = list.length > 0;
  empty.textContent = reached
    ? 'No toll, delivery or government scams yet. New ones show up here as soon as they\'re found.'
    : 'Can\'t reach the server right now. Try Refresh in a moment.';
}
function scamRow(a) {
  const lv = level(a.score);
  const li = el('li', 'catch open');
  const main = el('div', 'catch-main static');
  const pill = el('div', `score-pill ${lv}`, Math.round(a.score * 100));
  pill.title = `Score ${a.score.toFixed(3)}`;
  main.append(pill);

  const info = el('div');
  info.append(el('div', 'catch-domain', a.domain));   // plain text, never a link
  const meta = el('div', 'catch-meta');
  meta.append(el('span', 'cat-chip', (CAT[a.category] || CAT.other).label));
  if (isKnown(a)) meta.append(el('span', 'stage-chip known', 'Known · already on a scam list'));
  if (a.brand) meta.append(el('span', null, `Brand: ${a.brand}`));
  if (a.moreNames > 0) {
    meta.append(el('span', 'more-names', `+${a.moreNames} more name${a.moreNames === 1 ? '' : 's'} on this site`));
  }
  if (a.decided) {
    const t = el('span', null, `Flagged ${timeAgo(a.decided)}`);
    t.title = a.decidedRaw;
    meta.append(t);
  }
  info.append(meta);
  main.append(info);

  const detail = el('div', 'catch-detail');
  if (a.reasons.length) {
    const rs = el('div', 'reasons');
    a.reasons.forEach(r => rs.append(el('span', 'reason', r)));
    detail.append(rs);
  }
  const facts = el('div', 'detail-links');
  const age = fmtAge(a.ageDays);
  facts.append(el('span', null, `Domain age: ${age ?? 'unknown'}`),
               el('span', null, `Registrar: ${a.registrar || 'unknown'}`));
  if (a.crtsh) {
    const crt = el('a', null, '↗ Public certificate record (crt.sh)');
    crt.href = a.crtsh; crt.target = '_blank'; crt.rel = 'noopener noreferrer';
    facts.append(crt);
  }
  detail.append(facts);
  li.append(main, detail);
  return li;
}

// =================================================================
// Tabs
// =================================================================
let pollTimer = null;
function showTab(name) {
  if (!['dashboard', 'catches', 'extension'].includes(name)) name = 'dashboard';
  document.querySelectorAll('.tab-btn').forEach(b => {
    const on = b.dataset.tab === name;
    b.classList.toggle('active', on); b.setAttribute('aria-selected', String(on));
  });
  document.querySelectorAll('.tab-panel').forEach(p => p.hidden = p.id !== `panel-${name}`);
  clearInterval(pollTimer);
  if (name === 'dashboard') {
    startFirehose();
    loadDashboard();
    pollTimer = setInterval(loadDashboard, CONFIG.POLL_MS);
  } else if (name === 'catches') {
    loadCatches();
  }
  window.scrollTo({ top: 0 });
}
document.querySelectorAll('.tab-btn').forEach(b => b.addEventListener('click', () => { location.hash = b.dataset.tab; }));
window.addEventListener('hashchange', () => showTab(location.hash.slice(1)));
$('#refresh-btn').addEventListener('click', loadCatches);
if (CONFIG.EXTENSION_URL && CONFIG.EXTENSION_URL !== '#') {
  $('#install-btn').href = CONFIG.EXTENSION_URL;
  $('#install-btn').hidden = false;
}
$('#howto-btn').addEventListener('click', () => $('#install-steps').scrollIntoView({ behavior: 'smooth', block: 'start' }));

buildChip();
showTab(location.hash.slice(1) || 'dashboard');
if (location.hash.slice(1) !== 'catches') loadCatches();   // fill "Latest 15 scams" on every page load
