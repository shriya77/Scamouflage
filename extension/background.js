/*
 * background.js: the Scamouflage service worker.
 *
 * Two jobs:
 *   A. SYNC   Download the signed blocklist every 30 minutes, verify it, save it.
 *   B. CHECK  For every page the user opens, hash the hostname locally and look
 *             it up in the saved list. On a match, show the red warning page.
 *
 * Privacy: the only network request this file makes is GET /api/blocklist,
 * which is identical for every user. The sites you visit never leave the browser.
 *
 * Note for beginners: Chrome stops this service worker when it's idle and
 * starts it again on the next event. So in-memory variables (like the Map of
 * entries) can disappear at any time. That's why everything important is saved
 * in chrome.storage and reloaded on demand by ensureLoaded().
 */
importScripts('config.js', 'lib/nacl-fast.min.js', 'matcher.js');

const CONFIG = self.SCAMOUFLAGE_CONFIG;
const M = self.ScamMatcher;

const SYNC_ALARM = 'scamouflage-sync';
const RETRY_ALARM = 'scamouflage-retry';
const WARNING_PAGE = chrome.runtime.getURL('warning.html');
const EXTENSION_ORIGIN = chrome.runtime.getURL('');

// chrome.storage.local keys (kept across browser restarts)
const K_SETTINGS = 'settings';      // { backendUrl, dashboardUrl, demoMode }
const K_LIVE_LIST = 'list_live';    // { envelope, generatedAt, savedAt }
const K_SYNC_STATUS = 'sync_status'; // { lastAttemptAt, lastSuccessAt, lastError }
// chrome.storage.session keys (cleared when the browser closes)
const K_ALLOWED = 'allowed_hosts';  // [hostname, ...] the user chose "Continue anyway"
const K_SAFE_PREFIX = 'safe_url_';  // safe_url_<tabId>: last page in that tab that wasn't flagged

const DEFAULT_SETTINGS = {
  backendUrl: CONFIG.DEFAULT_BACKEND_URL,
  dashboardUrl: CONFIG.DEFAULT_DASHBOARD_URL,
  demoMode: false,
};

// ---------------------------------------------------------------------------
// In-memory state (rebuilt from storage whenever the worker restarts)
// ---------------------------------------------------------------------------
const state = {
  loaded: false,          // true once a verified list is in memory
  source: null,           // "live", "replay", "demo", ...
  generatedAt: null,
  entries: new Map(),     // hash -> entry, for fast lookups
  allowlist: new Set(),   // hashes of official domains
  loadError: null,
};
let loadPromise = null;     // the in-progress (or finished) load of the active list
let syncPromise = null;     // the in-progress sync, so two syncs never overlap
let settingsCache = null;
// hostname -> match result. Cleared whenever the list changes. Hashing is
// cheap, so losing this when the worker sleeps is fine.
const resultCache = new Map();

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
async function getSettings() {
  if (!settingsCache) {
    const stored = (await chrome.storage.local.get(K_SETTINGS))[K_SETTINGS] || {};
    settingsCache = { ...DEFAULT_SETTINGS, ...stored };
  }
  return settingsCache;
}

// ---------------------------------------------------------------------------
// Loading the active list into memory
// ---------------------------------------------------------------------------
function activate(payload, source) {
  state.entries = new Map(payload.entries.map((e) => [e.h, e]));
  state.allowlist = new Set(payload.allowlist);
  state.generatedAt = payload.generated_at;
  state.source = source;
  state.loaded = true;
  state.loadError = null;
  resultCache.clear();
}

function deactivate(error) {
  state.entries = new Map();
  state.allowlist = new Set();
  state.generatedAt = null;
  state.source = null;
  state.loaded = false;
  state.loadError = error || null;
  resultCache.clear();
}

/** Demo mode: the bundled demo list. Otherwise: the last good live list. */
async function loadActiveList() {
  const settings = await getSettings();

  if (settings.demoMode) {
    try {
      const res = await fetch(chrome.runtime.getURL(CONFIG.DEMO_LIST_PATH));
      const envelope = await res.json();
      // Demo keys only. A demo-signed list can never be used as the live list.
      const result = M.verifyEnvelope(envelope, CONFIG.DEMO_KEYS, self.nacl);
      if (!result.ok) throw new Error(result.error);
      activate(result.payload, 'demo');
    } catch (err) {
      deactivate('Demo list rejected: ' + err.message);
    }
    return;
  }

  const saved = (await chrome.storage.local.get(K_LIVE_LIST))[K_LIVE_LIST];
  if (!saved) {
    deactivate(null); // nothing downloaded yet
    return;
  }
  // Re-verify what we saved. It's cheap and guards against a corrupted store.
  // It also catches lists signed by a key we've since retired from config.js:
  // those are deleted so the next sync starts fresh.
  const result = M.verifyEnvelope(saved.envelope, CONFIG.LIVE_KEYS, self.nacl);
  if (!result.ok) {
    await chrome.storage.local.remove(K_LIVE_LIST);
    deactivate('Saved list rejected: ' + result.error);
    return;
  }
  activate(result.payload, M.describeSource(result.payload.entries, 'live'));
}

/** Make sure the active list is in memory (loads it at most once). */
function ensureLoaded() {
  if (!loadPromise) loadPromise = loadActiveList();
  return loadPromise;
}

function reloadList() {
  loadPromise = loadActiveList();
  return loadPromise;
}

// ---------------------------------------------------------------------------
// A. SYNC
// ---------------------------------------------------------------------------
function blocklistUrl(backendUrl) {
  return backendUrl.replace(/\/+$/, '') + '/api/blocklist';
}

/** Run one sync. If a sync is already running, wait for that one instead. */
function syncNow(trigger) {
  if (!syncPromise) {
    syncPromise = doSync(trigger).finally(() => { syncPromise = null; });
  }
  return syncPromise;
}

async function doSync(trigger) {
  const settings = await getSettings();

  // Demo mode never talks to the backend. Just (re)load the bundled list.
  if (settings.demoMode) {
    await reloadList();
    return { ok: state.loaded, demo: true, error: state.loadError };
  }

  const status = (await chrome.storage.local.get(K_SYNC_STATUS))[K_SYNC_STATUS] || {};
  status.lastAttemptAt = new Date().toISOString();

  try {
    // Step 1: download. credentials: 'omit' means no cookies are sent.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    let res;
    try {
      res = await fetch(blocklistUrl(settings.backendUrl), {
        cache: 'no-store',
        credentials: 'omit',
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) throw new Error('backend answered HTTP ' + res.status);

    // Step 2: parse only the outer envelope. "payload" stays a raw string.
    const envelope = await res.json();

    // Step 3: verify the signature over the raw payload string, THEN parse it.
    // Rejects unknown key_ids and bad signatures.
    const result = M.verifyEnvelope(envelope, CONFIG.LIVE_KEYS, self.nacl);
    if (!result.ok) throw new Error('list rejected: ' + result.error);

    // Step 4: refuse to go backwards in time (stops replay of an old list).
    // Only a saved list that still verifies counts; one signed by a retired
    // key must not block the new key's lists.
    const saved = (await chrome.storage.local.get(K_LIVE_LIST))[K_LIVE_LIST];
    const savedStillValid = saved && M.verifyEnvelope(saved.envelope, CONFIG.LIVE_KEYS, self.nacl).ok;
    if (savedStillValid && M.isOlder(result.payload.generated_at, saved.generatedAt)) {
      throw new Error('list rejected: older than the saved list (' +
        result.payload.generated_at + ' < ' + saved.generatedAt + ')');
    }

    // Step 5: save it, then load it into memory.
    await chrome.storage.local.set({
      [K_LIVE_LIST]: {
        envelope: { payload: envelope.payload, signature: envelope.signature, key_id: envelope.key_id },
        generatedAt: result.payload.generated_at,
        savedAt: new Date().toISOString(),
      },
    });
    status.lastSuccessAt = new Date().toISOString();
    status.lastError = null;
    await chrome.storage.local.set({ [K_SYNC_STATUS]: status });
    await reloadList();
    await chrome.alarms.clear(RETRY_ALARM);
    console.log('[Scamouflage] sync ok (' + trigger + '): ' + result.payload.entries.length + ' entries');
    return { ok: true };
  } catch (err) {
    // Keep using the last good list. Never fall back to "safe".
    status.lastError = String((err && err.message) || err);
    await chrome.storage.local.set({ [K_SYNC_STATUS]: status });
    console.warn('[Scamouflage] sync failed (' + trigger + '): ' + status.lastError);

    await ensureLoaded();
    if (!state.loaded) {
      // No list at all yet: try again soon instead of waiting 30 minutes.
      chrome.alarms.create(RETRY_ALARM, { delayInMinutes: CONFIG.RETRY_WHEN_EMPTY_MINUTES });
    }
    return { ok: false, error: status.lastError };
  }
}

async function ensureSyncAlarm() {
  const existing = await chrome.alarms.get(SYNC_ALARM);
  if (!existing) {
    chrome.alarms.create(SYNC_ALARM, {
      delayInMinutes: CONFIG.SYNC_PERIOD_MINUTES,
      periodInMinutes: CONFIG.SYNC_PERIOD_MINUTES,
    });
  }
}

// ---------------------------------------------------------------------------
// B. CHECK
// ---------------------------------------------------------------------------
async function getAllowedHosts() {
  return (await chrome.storage.session.get(K_ALLOWED))[K_ALLOWED] || [];
}

/**
 * Check one URL against the list. Used for navigation AND by the popup.
 * Returns { status, hostname, ... } where status is one of:
 *   skipped      not a web page, our own page, or localhost (outside demo mode)
 *   unavailable  no verified list has loaded yet (NOT "safe")
 *   allowlisted  an official domain on the allowlist
 *   not_listed   not on Scamouflage's list (which doesn't prove it's safe)
 *   flagged      on the list; `userAllowed` is true if they chose to continue
 */
async function checkUrl(url) {
  const settings = await getSettings();
  const c = M.classifyUrl(url, { demoMode: settings.demoMode, extensionOrigin: EXTENSION_ORIGIN });
  if (!c.checkable) return { status: 'skipped', reason: c.reason, hostname: c.hostname || null };

  await ensureLoaded();
  if (!state.loaded) return { status: 'unavailable', hostname: c.hostname };

  let result = resultCache.get(c.hostname);
  if (!result) {
    result = await M.checkHostname(c.hostname, state.entries, state.allowlist, crypto.subtle);
    resultCache.set(c.hostname, result);
  }

  const userAllowed = result.status === 'flagged' && (await getAllowedHosts()).includes(c.hostname);
  return { ...result, hostname: c.hostname, userAllowed, source: state.source };
}

const BADGES = {
  flagged: { text: '!', color: '#d93025' },
  clear: { text: '\u2713', color: '#188038' },  // check mark: "not on the list"
  unknown: { text: '?', color: '#80868b' },     // no list loaded
  none: { text: '', color: '#80868b' },
};

function setBadge(tabId, kind) {
  const badge = BADGES[kind];
  // Errors happen if the tab closed meanwhile; ignore them.
  chrome.action.setBadgeText({ tabId, text: badge.text }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color }).catch(() => {});
  if (chrome.action.setBadgeTextColor) {
    chrome.action.setBadgeTextColor({ tabId, color: '#ffffff' }).catch(() => {});
  }
}

function badgeFor(result) {
  if (result.status === 'flagged') return 'flagged';
  if (result.status === 'unavailable') return 'unknown';
  if (result.status === 'skipped') return 'none';
  return 'clear';
}

/** Send the tab to warning.html, carrying the match details in the URL. */
async function showWarning(tabId, url, result) {
  const entry = result.entry || {};
  const safeKey = K_SAFE_PREFIX + tabId;
  const back = (await chrome.storage.session.get(safeKey))[safeKey] || '';
  const params = new URLSearchParams({
    url,                                   // the original page, for "Continue anyway"
    host: result.hostname,
    matched: result.matched || '',         // which candidate matched (hostname or parent)
    score: entry.score == null ? '' : String(entry.score),
    reasons: JSON.stringify(entry.reasons || []),
    observed: entry.observed_at || '',
    source: entry.source || result.source || '',
    // Where "Go back" goes: the last page in this tab that wasn't flagged.
    // We use this instead of history.back(), because if the flagged page
    // loaded before the warning did, one step back would land on it again.
    back,
  });
  chrome.tabs.update(tabId, { url: WARNING_PAGE + '?' + params.toString() }).catch((err) => {
    console.warn('[Scamouflage] could not show warning:', err);
  });
}

async function onMainFrameNavigation(tabId, url, committed) {
  if (tabId < 0) return;
  if (url.startsWith(WARNING_PAGE)) {
    setBadge(tabId, 'flagged'); // keep the red "!" while the warning is showing
    return;
  }
  const result = await checkUrl(url);
  setBadge(tabId, badgeFor(result));
  if (result.status === 'flagged') {
    if (!result.userAllowed) await showWarning(tabId, url, result);
    return;
  }
  // Remember the last web page that loaded in this tab and wasn't flagged.
  if (committed && /^https?:/i.test(url)) {
    await chrome.storage.session.set({ [K_SAFE_PREFIX + tabId]: url });
  }
}

// ---------------------------------------------------------------------------
// Event listeners. They must be registered at the top level, synchronously,
// so Chrome can wake the worker up for them.
// ---------------------------------------------------------------------------

// Main check: fires before the request is sent, so the warning usually
// appears before the flagged site even starts loading.
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return; // main frame only
  onMainFrameNavigation(details.tabId, details.url, false).catch(console.error);
});

// Second chance: if the page committed anyway (e.g. the worker was asleep and
// slow to wake), catch it here. Also re-applies the badge, which Chrome resets
// when a tab navigates.
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  onMainFrameNavigation(details.tabId, details.url, true).catch(console.error);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(K_SAFE_PREFIX + tabId);
});

chrome.runtime.onInstalled.addListener(() => {
  ensureSyncAlarm();
  syncNow('install');
});

chrome.runtime.onStartup.addListener(() => {
  ensureSyncAlarm();
  syncNow('startup');
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === SYNC_ALARM || alarm.name === RETRY_ALARM) syncNow('alarm');
});

// Options page saved new settings: reload the right list and sync.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes[K_SETTINGS]) {
    settingsCache = null;
    resultCache.clear();
    reloadList().then(() => syncNow('settings-changed'));
  }
  if (area === 'session' && changes[K_ALLOWED]) {
    resultCache.clear();
  }
});

// Messages from our own pages (popup, options, warning). Nothing here talks
// to the backend except "syncNow", which only downloads the list.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !msg || typeof msg.type !== 'string') return false;
  handleMessage(msg)
    .then(sendResponse)
    .catch((err) => sendResponse({ error: String((err && err.message) || err) }));
  return true; // we will call sendResponse asynchronously
});

async function getListInfo() {
  await ensureLoaded();
  const settings = await getSettings();
  const sync = (await chrome.storage.local.get(K_SYNC_STATUS))[K_SYNC_STATUS] || {};
  return {
    loaded: state.loaded,
    source: state.source,
    entryCount: state.entries.size,
    generatedAt: state.generatedAt,
    loadError: state.loadError,
    demoMode: settings.demoMode,
    lastSuccessAt: sync.lastSuccessAt || null,
    lastAttemptAt: sync.lastAttemptAt || null,
    lastError: sync.lastError || null,
  };
}

async function handleMessage(msg) {
  switch (msg.type) {
    case 'checkUrl':
      // From the popup. Checked locally; nothing is sent anywhere.
      return { check: await checkUrl(String(msg.url || '')), list: await getListInfo() };

    case 'getListInfo':
      return { list: await getListInfo() };

    case 'syncNow':
      // Re-read settings first: the options page may have just saved them.
      settingsCache = null;
      await reloadList();
      return { sync: await syncNow('manual'), list: await getListInfo() };

    case 'allowHost': {
      // From the warning page's "Continue anyway". Session only.
      const hostname = M.normalizeHostname(String(msg.hostname || ''));
      if (!hostname) return { ok: false };
      const allowed = await getAllowedHosts();
      if (!allowed.includes(hostname)) allowed.push(hostname);
      await chrome.storage.session.set({ [K_ALLOWED]: allowed });
      return { ok: true };
    }

    case 'getAllowedHosts':
      return { hosts: await getAllowedHosts() };

    case 'clearAllowedHosts':
      await chrome.storage.session.remove(K_ALLOWED);
      return { ok: true };

    default:
      return { error: 'unknown message type' };
  }
}

// Every time the worker starts: make sure the 30-minute alarm exists.
ensureSyncAlarm();
