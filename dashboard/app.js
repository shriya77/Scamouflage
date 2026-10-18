/* Scamouflage website
 * Every live number comes from the LinuxONE API. If a value isn't available it shows "–" or the
 * element is hidden; nothing is ever filled in with sample numbers.
 * Static copy (the 26-minute replay funnel, 11,485/s, 432,589 sites) is recorded results, not live.
 */

// ===================== CONFIG: edit these =====================
const CONFIG = {
  // If the API serves this page (http://localhost:8000/), leave '' (same origin).
  // Otherwise (Live Server / python http.server) it uses localhost:8000 through your SSH tunnel.
  API_BASE: location.port === '8000' ? '' : 'http://localhost:8000',

  ENDPOINTS: {
    stats:   '/api/stats',       // live pipeline counters + recent domain names for the stream
    alerts:  '/api/alerts',      // { items: [...] }
    catches: '/api/alerts?limit=200', // "Latest catches" tab: filtered and deduped on the client
    summary: '/api/alerts/summary', // { known_total, new_total, total }
    results: '/api/results',     // model evaluation: precision, recall, false_alarms_per_10k, baselines
    leadtime: '/api/leadtime',   // median_days, share_before_any_feed, n
    bench:   '/api/hardware',    // CPACF on/off benchmark (static, fetched once)
    cpacf:   '/api/cpacf/live',  // live CPACF activity counters
  },
  WS_PATH: '/ws/live',           // live stream (domain names + alerts), optional

  EXTENSION_URL: '#',            // optional: a download link for the extension folder (shows a Download button)
  POLL_MS: 2000,
  CATCHES_LIMIT: 15,
};
// Add ?replay to the URL to run a clearly-labelled demo replay (sample domains + a sample catch).
const REPLAY = new URLSearchParams(location.search).has('replay');
// ===============================================================

const $ = (s, el = document) => el.querySelector(s);
const fmt = n => (n == null || isNaN(n)) ? '–' : Math.round(n).toLocaleString('en-US');
const pick = (o, ...keys) => { for (const k of keys) if (o && o[k] != null) return o[k]; return undefined; };
const num = v => (v == null || v === '' || isNaN(+v)) ? null : +v;
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;

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
function setStatus(state, text) {
  const s = $('#status');
  s.classList.toggle('offline', state === 'offline');
  $('#status-text').textContent = text;
}
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;     // textContent only: domain names are untrusted
  return e;
}

// ---------- Count numbers up smoothly ----------
const shown = {};
function countTo(id, target, decimals = 0) {
  const node = document.getElementById(id);
  if (!node) return;
  if (target == null || isNaN(target)) { node.textContent = '–'; delete shown[id]; return; }
  const start = shown[id] ?? 0;
  const t0 = performance.now(), dur = reduce ? 0 : (shown[id] == null ? 1200 : 900);
  const step = now => {
    const p = dur ? Math.min(1, (now - t0) / dur) : 1;
    const v = start + (target - start) * (1 - Math.pow(1 - p, 3));
    node.textContent = decimals ? v.toFixed(decimals) : fmt(v);
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
  shown[id] = target;
}

// ---------- Alerts: tolerant of field names ----------
const SCAM_CATEGORIES = new Set(['toll', 'delivery', 'gov']);
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
  return {
    id: String(pick(a, 'cert_id', 'id', 'alert_id', 'uid') ?? `${domain}|${time?.getTime() ?? ''}`),
    domain,
    score: toScore(pick(a, 'score', 'risk', 'risk_score', 'prob', 'probability')),
    reasons: reasons.map(humanReason),
    category: String(pick(a, 'category', 'brand_type', 'type') ?? guessCategory(domain)).toLowerCase(),
    time,
    stage: pick(a, 'stage'),
    crtsh: pick(a, 'crtsh_url', 'crtsh') || null,
    demo: !!a.__demo,
  };
}
function normalizeAlerts(raw) {
  const arr = Array.isArray(raw) ? raw : (raw?.items || raw?.alerts || raw?.data || raw?.results || []);
  return arr.map(normalizeAlert).sort((x, y) => (y.time?.getTime() || 0) - (x.time?.getTime() || 0));
}
const isKnown = a => Number(a.stage) === 0;   // stage 0 = already on a known public list

const REPLAY_DOMAINS = ['shop-autumn-sale.com','mail.northwind-co.net','api.trailcam.io','blog.greenleafgardens.org','cdn.pixelforge.app','portal.lakeside-dental.com','www.quietharbor.inn','status.cloudkite.dev','learn.mathbridge.edu','m.citybikes.co','assets.bluefinmedia.tv','go.fernandpine.com','app.ledgerly.finance','www.riverbendvet.com','docs.tinyhttp.dev','images.harvestmarket.store','vpn.acme-corp.net','beta.storyloom.ai','www.oakhillchurch.org','grafana.internal-ops.cloud'];
const REPLAY_CATCH = { domain: 'ntta.com-tollpay-x7q.win', score: 0.96, stage: 1, signature_verified: true,
  reasons: ['Toll agency name in front of a fake site', 'cheap_tld', 'Matches campaign brand.com-*.win'], __demo: true };

const CAT = {
  toll: { label: 'Toll', sign: 'Toll scam' }, delivery: { label: 'Delivery', sign: 'Delivery scam' },
  gov: { label: 'Government', sign: 'Government scam' }, other: { label: 'Other', sign: 'Phishing site' },
};
function timeAgo(d) {
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${Math.round(s)} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return d.toLocaleDateString();
}
function shortAgo(d) {
  if (!d) return '';
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} d`;
}

// =================================================================
// STREAM: real recent names drift past, blurred; real catches glow in rust
// =================================================================
// A plausible hostname: labels of letters/digits/-/_ (optional leading *.), at least one dot, ≤ 253 chars
const HOSTNAME = /^(\*\.)?[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+$/i;
const ROW_NAMES = 16;
const stream = { names: [], seen: new Set(), hot: [], built: false, started: false };
const rows = ['r1', 'r2', 'r3'].map(id => document.getElementById(id));

function feedDomains(list) {
  if (!Array.isArray(list)) return;
  for (const d of list) {
    const raw = typeof d === 'string' ? d : (d?.domain ?? d?.name);
    const name = typeof raw === 'string' ? raw.trim() : '';
    if (!name || name.length > 253 || !HOSTNAME.test(name) || stream.seen.has(name)) continue;   // skip empty/invalid
    stream.seen.add(name);
    stream.names.push(name);
  }
  if (stream.seen.size > 5000) stream.seen = new Set([...stream.seen].slice(-2000));
  if (stream.names.length > 160) stream.names.splice(0, stream.names.length - 160);
  if (!stream.built && stream.names.length >= 8) buildRows();
}
function extractDomains(obj) {
  if (!obj) return null;
  return pick(obj, 'recent_names', 'recent_domains', 'sample_domains', 'domains', 'recent', 'stream') ||
         (obj.domain && obj.type !== 'alert' ? [obj.domain] : null);
}
function rowParts(i) {
  const pool = stream.names, len = pool.length;
  if (!len) return null;
  const parts = [];
  for (let j = 0; j < ROW_NAMES; j++) {
    const k = len - 1 - (i * ROW_NAMES + j);
    parts.push(el('span', null, pool[((k % len) + len) % len]));   // long names are cut by CSS; a copy gets the full name
    // every 5th name is a real catch, shown sharp in rust
    if (j % 5 === 3 && stream.hot.length) parts.push(el('span', 'hot', stream.hot[(i * 4 + (j >> 2)) % stream.hot.length]));
  }
  return parts;
}
function fillRow(row, i) {
  const parts = rowParts(i);
  if (!parts) return;
  row.replaceChildren(...parts, ...parts.map(p => p.cloneNode(true)));   // doubled so the loop is seamless
}
function buildRows() {
  stream.built = true;
  rows.forEach(fillRow);
  $('#stream-wait').hidden = true;
}
// New names swap in at the end of each loop, so the drift never jumps
// (only the row's own drift: the rust names' glow pulse also fires animationiteration and bubbles up)
rows.forEach((r, i) => r.addEventListener('animationiteration', e => { if (e.target === r) fillRow(r, i); }));
if (reduce) setInterval(() => stream.built && rows.forEach(fillRow), 15000);

// ---------- Catch sign ----------
// Priority: a NEW toll/delivery/gov catch (stage != 0) > a known-list toll/delivery/gov site >
// anything else. -1 = no domain, never shown.
const heroRank = a => !String(a?.domain ?? '').trim() ? -1
  : SCAM_CATEGORIES.has(a.category) ? (isKnown(a) ? 2 : 3) : 1;
const sign = { cycle: [], queue: [], i: 0, hideTimer: null, held: false };

function setCycle(list) {
  const ranked = list.filter(a => heroRank(a) >= 0)
    .sort((x, y) => heroRank(y) - heroRank(x) || (y.time?.getTime() || 0) - (x.time?.getTime() || 0));
  sign.cycle = ranked.slice(0, 8);
  const hot = [];
  for (const a of ranked) { if (!hot.includes(a.domain)) hot.push(a.domain); if (hot.length >= 12) break; }
  if (!hot.length) return;
  const first = !stream.hot.length;
  stream.hot = hot;
  if (first && stream.built) rows.forEach(fillRow);   // show the catches now, not after the first loop
}
function addHot(domain) {
  const first = !stream.hot.length;
  stream.hot = [domain, ...stream.hot.filter(d => d !== domain)].slice(0, 12);
  if (first && stream.built) rows.forEach(fillRow);
}
function showSign(a) {
  const c = CAT[a.category] || CAT.other;
  const where = isKnown(a) ? 'already on a known scam list' : 'not on any blocklist';
  const when = a.time ? `caught ${timeAgo(a.time)}` : 'caught';
  $('#catchWhen').textContent = `${a.demo ? 'Demo replay: ' : ''}${c.sign}, ${when}, ${where}`;
  $('#catchDomain').textContent = a.domain;                   // plain text, never a link
  const why = $('#catchWhy');
  why.textContent = a.reasons[0] || '';
  why.hidden = !a.reasons.length;
  $('#catchScore').textContent = Math.round(a.score * 100);
  const box = $('#catch');
  box.classList.add('show');
  clearTimeout(sign.hideTimer);
  sign.hideTimer = setTimeout(hideSign, reduce ? 6000 : 3800);
}
function hideSign() { if (!sign.held) $('#catch').classList.remove('show'); }
function selectingInSign() {
  const sel = getSelection();
  return !!sel && !sel.isCollapsed && $('#catch').contains(sel.anchorNode);
}
// Hold the sign while the pointer is on it or its text is selected, so the domain can be copied
$('#catch').addEventListener('pointerenter', () => { sign.held = true; });
$('#catch').addEventListener('pointerleave', () => {
  sign.held = selectingInSign();
  clearTimeout(sign.hideTimer);
  if (!sign.held) sign.hideTimer = setTimeout(hideSign, 1500);
});
document.addEventListener('selectionchange', () => {
  if (sign.held && !selectingInSign() && !$('#catch').matches(':hover')) { sign.held = false; hideSign(); }
});
// One click selects a whole name (full text, even when CSS cuts it off), ready to copy
$('.stream').addEventListener('click', e => {
  const name = e.target.closest('.stream .row span, #catchDomain');
  if (!name || !getSelection().isCollapsed) return;           // a drag already made its own selection
  const range = document.createRange();
  range.selectNodeContents(name);
  getSelection().removeAllRanges();
  getSelection().addRange(range);
});
function nextCatch() {
  if (sign.held || $('.stream').matches(':hover')) return;   // no new sign while someone is selecting names
  const a = sign.queue.shift() || (sign.cycle.length ? sign.cycle[sign.i++ % sign.cycle.length] : null);
  if (a) showSign(a);
}

const seenAlerts = new Set();
let alertsPrimed = false;
function handleAlerts(list) {
  if (!alertsPrimed) {
    list.forEach(a => seenAlerts.add(a.id));
    alertsPrimed = true;
    nextCatch();
    return;
  }
  const fresh = list.filter(a => !seenAlerts.has(a.id));
  fresh.forEach(a => seenAlerts.add(a.id));
  fresh.reverse().filter(a => heroRank(a) >= 0).forEach(a => {   // oldest first
    sign.queue.push(a);
    if (SCAM_CATEGORIES.has(a.category)) addHot(a.domain);
  });
  if (sign.queue.length > 10) sign.queue.splice(0, sign.queue.length - 10);
}

function startStream() {
  if (stream.started) return;
  stream.started = true;
  setInterval(nextCatch, reduce ? 7000 : 5200);
  connectWS();
  if (REPLAY) startReplay();
}
function startReplay() {
  $('#stream-demo').hidden = false;
  const loop = () => { stream.seen.clear(); feedDomains([...REPLAY_DOMAINS].sort(() => Math.random() - .5)); };
  loop(); setInterval(loop, 4000);
  setTimeout(function again() {
    const a = normalizeAlert({ ...REPLAY_CATCH, ts: Date.now() / 1000 });
    addHot(a.domain);
    sign.queue.push(a);
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
      if (m.type !== 'alert') feedDomains(extractDomains(d));       // alerts never go into the blurred names
      if (m.type === 'cpacf' && d.groups && d.available !== false) renderCpacf(d);
      const al = m.type === 'alert' ? d : (m.alert || null);
      if (al && alertsPrimed) handleAlerts([normalizeAlert(al)]);   // before the first poll, the poll covers it
    }
  };
  ws.onclose = () => setTimeout(connectWS, 5000);
  ws.onerror = () => { try { ws.close(); } catch {} };
}

// =================================================================
// LIVE page
// =================================================================
let benchCache = null;
async function loadDashboard() {
  const [statsRaw, alertsRaw, resultsRaw, benchRaw, cpacfRaw, summaryRaw, leadRaw] = await Promise.all([
    getJSON('stats'), getJSON('alerts'), getJSON('results'),
    benchCache ? Promise.resolve(benchCache) : getJSON('bench'),
    getJSON('cpacf'), getJSON('summary'), getJSON('leadtime'),
  ]);
  if (benchRaw?.results) benchCache = benchRaw;

  const apiUp = !!(statsRaw || alertsRaw || cpacfRaw);
  setStatus(apiUp ? 'live' : 'offline', apiUp ? 'Live' : 'Offline');

  if (statsRaw) feedDomains(extractDomains(statsRaw));
  renderStats(statsRaw, summaryRaw);

  if (alertsRaw) {
    const list = normalizeAlerts(alertsRaw);
    setCycle(list);
    handleAlerts(list);
  }
  renderResults(resultsRaw, leadRaw);
  if (benchCache) renderBench(benchCache);
  renderCpacf(cpacfRaw?.groups && cpacfRaw.available !== false ? cpacfRaw : null);
}

// Stat line under the stream: each item is hidden until it has a real value
function statItem(id, value, decimals = 0, animate = true) {
  const node = document.getElementById(id);
  const wrap = node.closest('[data-stat]');
  const v = num(value);
  wrap.hidden = v == null;
  if (v == null) { delete shown[id]; return; }
  if (animate) countTo(id, v, decimals);
  else node.textContent = decimals ? v.toFixed(decimals) : fmt(v);
}
function renderStats(s, summary) {
  statItem('cps', pick(s, 'certs_per_s'));
  statItem('verifyMs', pick(s, 'avg_verify_ms'), 2, false);
  statItem('certTotal', pick(s, 'processed_total', 'certs_total'));
  statItem('newTotal', pick(summary, 'new_total') ?? pick(s, 'alerts_new'));
}

// ---------- Accuracy bento: values from /api/results, count up once when scrolled to ----------
const report = { visible: false };
function countUp(node) {
  if (reduce || node.dataset.animated || node.dataset.count == null) return;
  node.dataset.animated = '1';
  const end = parseFloat(node.dataset.count), dec = +(node.dataset.dec || 0), t0 = performance.now(), dur = 1600;
  const tick = t => {
    const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 4);
    node.textContent = dec ? (end * e).toFixed(dec) : fmt(end * e);
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}
function setCount(id, value, dec = 0) {
  const node = document.getElementById(id);
  node.dataset.count = value; node.dataset.dec = dec;
  node.textContent = dec ? (+value).toFixed(dec) : fmt(value);   // final value shows at rest
  if (report.visible) countUp(node);
}
function setText(id, text) {
  const node = document.getElementById(id);
  node.hidden = !text;
  node.textContent = text || '';
}
function renderResults(raw, lead) {
  const r = raw?.results && typeof raw.results === 'object' && !Array.isArray(raw.results) ? raw.results : raw;
  const key = JSON.stringify([r, lead?.n, lead?.median_days, lead?.share_before_any_feed]);
  const box = $('#report');
  if (box.dataset.key === key) return;          // avoid re-rendering every poll
  box.dataset.key = key;

  const pct = v => v <= 1 ? v * 100 : v;
  const recallIncl = num(pick(r, 'recall_incl_stage3_review'));
  const recall = recallIncl ?? num(pick(r, 'recall', 'test_recall'));
  const prec = num(pick(r, 'precision', 'test_precision'));
  const fa = num(pick(r, 'false_alarms_per_10k', 'fa_per_10k'));
  const d = r?.detail || {};
  const nScams = num(d.n_scams), tp = num(d.tp), fp = num(d.fp);
  const kwFa = num(r?.baselines?.keyword_rule?.false_alarms_per_10k);
  const nTest = num(pick(r, 'n_test_rows'));

  setText('acc-lead', nTest != null ? `Tested on ${fmt(nTest)} websites the model never saw during training.` : '');
  $('#acc-pending').hidden = [recall, prec, fa].some(v => v != null);

  $('#tile-recall').hidden = recall == null;
  if (recall != null) {
    setCount('recallN', pct(recall), 1);
    let sub = '';
    if (nScams) {
      const caught = Math.round(pct(recall) / 100 * nScams);
      sub = `${fmt(caught)} of ${fmt(nScams)} test scams.`;
      if (recallIncl != null && tp != null && caught > tp) {
        sub += ` ${fmt(tp)} from the web address alone, ${fmt(caught - tp)} more on a second check of how new the site is.`;
      }
    }
    setText('recallSub', sub);
  }

  $('#tile-prec').hidden = prec == null;
  if (prec != null) {
    setCount('precN', pct(prec), 1);
    setText('precSub', tp != null && fp != null ? `${fmt(tp)} of ${fmt(tp + fp)} alarms were real scams` : '');
  }

  $('#tile-fa').hidden = fa == null;
  if (fa != null) {
    setCount('faN', fa, 1);
    setText('faSub', kwFa != null ? `a brand-word filter makes ${kwFa.toFixed(1)}` : '');
  }

  // Lead time: only when at least one of our catches was later listed by a feed
  const leadOk = lead && num(lead.n) > 0;
  const days = leadOk ? num(lead.median_days) : null;
  const share = leadOk ? num(lead.share_before_any_feed) : null;
  $('#lead-tiles').hidden = days == null && share == null;
  $('#tile-lead-days').hidden = days == null;
  if (days != null) {
    const hours = days < 2;
    setCount('leadDaysN', hours ? Math.round(days * 24) : days, hours ? 0 : 1);
    $('#leadDaysUnit').textContent = hours ? ' h' : ' days';
    $('#leadDaysSub').textContent = `median over ${fmt(lead.n)} catches`;
  }
  $('#tile-lead-share').hidden = share == null;
  if (share != null) setCount('leadShareN', pct(share));
}

// ---------- IBM chip + race ----------
const MACHINES = { '9175': 'IBM z17', '9176': 'IBM z17', '3931': 'IBM z16', '3932': 'IBM z16', '8561': 'IBM z15', '8562': 'IBM z15' };
function renderBench(hw) {
  if (renderBench.last === hw) return;
  renderBench.last = hw;
  const m = MACHINES[String(hw.machine_type)];
  $('#chipName').textContent = m || 'IBM Z';
  $('#ibm-machine').textContent = m ? `our ${m}` : 'our IBM Z server';

  const res = hw.results || {};
  const v = res['verify (real CT certs)'];
  const on = num(v?.on), off = num(v?.off);
  const raceOk = on > 0 && off > 0;
  $('#race').hidden = !raceOk;
  $('#raceX').hidden = !raceOk;
  if (raceOk) {
    const max = Math.max(on, off);
    $('#raceOnN').textContent = `${fmt(on)} / s`;
    $('#raceOffN').textContent = `${fmt(off)} / s`;
    [['#raceOn', on], ['#raceOff', off]].forEach(([sel, n]) => {
      const bar = $(sel);
      bar.style.width = (n / max * 100) + '%';
      bar.classList.remove('grow'); void bar.offsetWidth; bar.classList.add('grow');
    });
    $('#raceX').textContent = `${(on / off).toFixed(1)}× faster checking real certificates`;
  }

  const algo = hw.verify_by_algo || {};
  const items = [];
  if (res['SHA-256 (bulk)']) items.push([res['SHA-256 (bulk)'].speedup, 'SHA-256 hashing']);
  if (algo['ecdsa-p384']) items.push([algo['ecdsa-p384'].speedup, 'ECDSA P-384 checks']);
  if (res['SHA-256 (cert DER)']) items.push([res['SHA-256 (cert DER)'].speedup, 'certificate fingerprints']);
  if (algo['ecdsa-p256']) items.push([algo['ecdsa-p256'].speedup, 'ECDSA P-256 checks']);
  if (res['Ed25519 sign (alerts)']) items.push([res['Ed25519 sign (alerts)'].speedup, 'signing our alerts']);
  const rsa = algo['rsa-2048'] || algo['rsa-4096'];
  if (rsa) items.push([rsa.speedup, 'RSA, not accelerated']);
  const box = $('#speedups');
  const valid = items.filter(([x]) => num(x) != null);
  box.replaceChildren(...valid.map(([x, label]) => {
    const it = el('div', +x < 1.5 ? 'muted' : null);
    it.append(el('strong', null, `${(+x).toFixed(1)}×`), document.createTextNode(label));
    return it;
  }));
  box.hidden = !valid.length;
}
function renderCpacf(c) {
  const rate = num(c?.groups?.ecdsa_verify_per_s);
  $('#chipRate').textContent = rate == null ? '–' : fmt(rate);
}
function buildPins() {
  let svg = '';
  [90, 125, 160, 195, 230].forEach((p, i) => {
    const d = ` style="animation-delay:${i * 0.17}s"`;
    svg += `<line class="chip-pin"${d} x1="${p}" y1="20" x2="${p}" y2="56"/><line class="chip-pin"${d} x1="${p}" y1="264" x2="${p}" y2="300"/>`;
    svg += `<line class="chip-pin"${d} x1="20" y1="${p}" x2="56" y2="${p}"/><line class="chip-pin"${d} x1="264" y1="${p}" x2="300" y2="${p}"/>`;
  });
  $('#pins').innerHTML = svg;   // static markup only, no data
}

// ---------- Scroll-in animations: funnel bars + count-ups, results count-ups ----------
function watchScroll() {
  if (reduce || !('IntersectionObserver' in window)) { report.visible = true; return; }
  const funnel = $('#funnel');
  const io = new IntersectionObserver(es => {
    if (!es[0].isIntersecting) return;
    io.disconnect();
    funnel.querySelectorAll('.fbar').forEach((r, i) => { r.style.animationDelay = (i * 0.25) + 's'; r.classList.add('grow'); });
    funnel.querySelectorAll('[data-count]').forEach(node => {
      const end = +node.dataset.count, t0 = performance.now(), dur = 1300;
      const tick = t => { const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 3); node.textContent = fmt(end * e); if (p < 1) requestAnimationFrame(tick); };
      requestAnimationFrame(tick);
    });
  }, { threshold: .35 });
  io.observe(funnel);

  const rep = $('#report');
  const io2 = new IntersectionObserver(es => {
    if (!es[0].isIntersecting) return;
    io2.disconnect();
    report.visible = true;
    rep.classList.add('go');
    rep.querySelectorAll('[data-count]').forEach(countUp);
  }, { threshold: .4 });
  io2.observe(rep);
}

// =================================================================
// LATEST CATCHES tab
// =================================================================
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

const roll = { openId: null, seen: null };
async function loadCatches() {
  const btn = $('#refresh-btn');
  btn.disabled = true; btn.textContent = 'Checking…';
  const raw = await getJSON('catches');
  if (location.hash.slice(1) === 'catches') setStatus(raw ? 'live' : 'offline', raw ? 'Live' : 'Offline');
  renderCatches(raw ? latestScams(raw) : [], !!raw);
  btn.disabled = false; btn.textContent = 'Check for new ones';
}
function renderCatches(list, reached) {
  const fresh = list.filter(a => !isKnown(a)), known = list.filter(isKnown);
  if (roll.openId === null && fresh[0]) roll.openId = fresh[0].id;   // newest opens by default
  const prev = roll.seen;
  if (reached) roll.seen = new Set(list.map(a => a.id));
  $('#list').replaceChildren(...fresh.map(a => receiptRow(a, !!prev && !prev.has(a.id))));
  $('#known').replaceChildren(...known.map(knownRow));
  $('#group-new').hidden = !fresh.length;
  $('#group-known').hidden = !known.length;
  const empty = $('#catch-empty');
  empty.hidden = list.length > 0;
  empty.textContent = reached
    ? 'No toll, delivery or government scams yet. New ones show up here as soon as they\'re found.'
    : 'Can\'t reach the server right now. Try again in a moment.';
}
function receiptRow(a, isFresh) {
  const open = a.id === roll.openId;
  const item = el('div', `item${open ? ' open' : ''}${isFresh ? ' fresh' : ''}`);
  item.dataset.id = a.id;
  const b = el('div', 'row-head');                           // not a <button>, so the domain can be selected
  b.setAttribute('role', 'button');
  b.tabIndex = 0;
  b.setAttribute('aria-expanded', String(open));
  const when = el('span', 'when', shortAgo(a.decided || a.time));
  if (a.decidedRaw) when.title = a.decidedRaw;
  const s = Math.round(a.score * 100);
  const score = el('span', `score-n num${s >= 90 ? ' hi' : s >= 75 ? ' mid' : ''}`, s);
  score.title = `Score ${a.score.toFixed(3)}`;
  b.append(when, el('span', 'domain', a.domain),               // plain text, never a link
           el('span', `stamp ${a.category}`, (CAT[a.category] || CAT.other).label.toUpperCase()), score);

  const inner = el('div');
  if (a.reasons.length) {
    const ul = el('ul');
    a.reasons.forEach(r => ul.append(el('li', null, r)));
    inner.append(ul);
  }
  const facts = el('p', 'why-facts');
  if (a.brand) facts.append(el('span', null, `Brand: ${a.brand}`));
  const age = fmtAge(a.ageDays);
  if (age) facts.append(el('span', null, `Domain age: ${age}`));
  if (a.registrar) facts.append(el('span', null, `Registrar: ${a.registrar}`));
  if (a.moreNames > 0) facts.append(el('span', null, `+${a.moreNames} more name${a.moreNames === 1 ? '' : 's'} on this site`));
  if (a.crtsh) {
    const crt = el('a', null, 'Public certificate record (crt.sh)');
    crt.href = a.crtsh; crt.target = '_blank'; crt.rel = 'noopener noreferrer';
    facts.append(crt);
  }
  if (facts.childElementCount) inner.append(facts);
  const why = el('div', 'why');
  why.append(inner);
  item.append(b, why);
  return item;
}
function knownRow(a) {
  const row = el('div', 'known-row');
  const d = el('span', 'domain', a.domain);                     // plain text, never a link
  d.style.fontWeight = '500';
  row.append(el('span', null, shortAgo(a.decided || a.time)), d, el('span', null, (CAT[a.category] || CAT.other).label));
  return row;
}
function toggleRow(item) {
  roll.openId = roll.openId === item.dataset.id ? '' : item.dataset.id;
  $('#list').querySelectorAll('.item').forEach(it => {
    const on = it.dataset.id === roll.openId;
    it.classList.toggle('open', on);
    it.querySelector('.row-head').setAttribute('aria-expanded', String(on));
  });
}
$('#list').addEventListener('click', e => {
  const head = e.target.closest('.row-head');
  if (!head || !getSelection().isCollapsed) return;           // selecting a domain doesn't toggle the row
  toggleRow(head.closest('.item'));
});
$('#list').addEventListener('keydown', e => {
  const head = e.target.closest('.row-head');
  if (!head || (e.key !== 'Enter' && e.key !== ' ')) return;
  e.preventDefault();
  toggleRow(head.closest('.item'));
});

// =================================================================
// Tabs (routes: #dashboard, #catches, #extension)
// =================================================================
const TABS = ['dashboard', 'catches', 'extension'];
let pollTimer = null;
function showTab(name) {
  if (!TABS.includes(name)) name = 'dashboard';
  document.querySelectorAll('[data-page]').forEach(p => p.hidden = p.dataset.page !== name);
  document.querySelectorAll('[data-tab]').forEach(t => t.dataset.tab === name
    ? t.setAttribute('aria-current', 'page') : t.removeAttribute('aria-current'));
  clearInterval(pollTimer);
  if (name === 'dashboard') {
    startStream();
    loadDashboard();
    pollTimer = setInterval(loadDashboard, CONFIG.POLL_MS);
  } else if (name === 'catches') {
    loadCatches();
  }
  window.scrollTo({ top: 0 });
}
window.addEventListener('hashchange', () => showTab(location.hash.slice(1)));
$('#refresh-btn').addEventListener('click', loadCatches);
if (CONFIG.EXTENSION_URL && CONFIG.EXTENSION_URL !== '#') {
  $('#install-btn').href = CONFIG.EXTENSION_URL;
  $('#install-btn').hidden = false;
}

buildPins();
watchScroll();
showTab(location.hash.slice(1) || 'dashboard');
if (location.hash.slice(1) !== 'catches') loadCatches();   // fill "Latest catches" on every page load
