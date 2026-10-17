/*
 * popup.js: the toolbar popup.
 *
 * Shows the current site's status, using only the list already saved in the
 * browser. The current site is sent to background.js (inside the extension),
 * never to the server. "Sync now" only downloads the list.
 */
(function () {
  'use strict';

  const M = self.ScamMatcher;
  const CONFIG = self.SCAMOUFLAGE_CONFIG;
  const WARNING_PAGE = chrome.runtime.getURL('warning.html');
  const $ = (id) => document.getElementById(id);

  // ---- Helpers ---------------------------------------------------------------
  function timeAgo(iso) {
    if (!iso) return 'never';
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return 'never';
    const minutes = Math.round((Date.now() - date.getTime()) / 60000);
    let ago;
    if (minutes < 1) ago = 'just now';
    else if (minutes < 60) ago = minutes + ' min ago';
    else if (minutes < 48 * 60) ago = Math.round(minutes / 60) + ' h ago';
    else ago = Math.round(minutes / 1440) + ' days ago';
    return date.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' }) + ' (' + ago + ')';
  }

  const SKIP_TEXT = {
    'not-web': 'Not checked: this isn\'t a website.',
    'extension-page': 'Not checked: this is a Scamouflage page.',
    localhost: 'Not checked: local address (turn on demo mode to check it).',
    'invalid-url': 'Not checked.',
  };

  // ---- Step 1: figure out which URL the user is looking at -------------------
  // "activeTab" lets us read the current tab's URL only while the popup is open.
  async function currentUrl() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = (tab && tab.url) || '';
    // On our own warning page, report on the site it's warning about.
    if (url.startsWith(WARNING_PAGE)) {
      return new URL(url).searchParams.get('url') || '';
    }
    return url;
  }

  // ---- Step 2: render the site status ---------------------------------------
  function renderStatus(check, list) {
    const box = $('status');
    const title = $('status-title');
    const detail = $('status-detail');
    const reasonsEl = $('status-reasons');
    box.className = 'status status-' + check.status;
    $('status-host').textContent = check.hostname || '';
    detail.textContent = '';
    reasonsEl.textContent = '';
    reasonsEl.hidden = true;

    switch (check.status) {
      case 'flagged': {
        const entry = check.entry || {};
        title.textContent = 'Flagged as a likely scam (score ' + M.formatScore(entry.score) + ')';
        if (check.matched && check.matched !== check.hostname) {
          detail.textContent = 'Matched through ' + check.matched + '.';
        }
        if (check.userAllowed) {
          detail.textContent += ' You chose to continue to this site for this session.';
        }
        for (const code of entry.reasons || []) {
          const li = document.createElement('li');
          li.textContent = M.explainReason(code);
          reasonsEl.appendChild(li);
        }
        reasonsEl.hidden = !(entry.reasons && entry.reasons.length);
        break;
      }
      case 'not_listed':
        // Never "safe": absence from the list doesn't prove a site is legitimate.
        title.textContent = 'Not on Scamouflage\'s list';
        detail.textContent = 'That doesn\'t prove the site is legitimate. Stay careful with payment links.';
        break;
      case 'allowlisted':
        title.textContent = 'Not on Scamouflage\'s list';
        detail.textContent = 'This domain is on the list of known official sites.';
        break;
      case 'unavailable':
        title.textContent = 'List unavailable';
        detail.textContent = 'No verified list has loaded yet, so this site can\'t be checked. Try "Sync now".';
        break;
      default:
        title.textContent = SKIP_TEXT[check.reason] || 'Not checked.';
    }
    renderList(list);
  }

  // ---- Step 3: render list info ----------------------------------------------
  function renderList(list) {
    $('demo-pill').hidden = !list.demoMode;
    $('entry-count').textContent = list.loaded ? String(list.entryCount) : '–';
    $('last-sync').textContent = list.demoMode ? 'bundled demo list' : timeAgo(list.lastSuccessAt);
    $('list-source').textContent = list.loaded ? (list.source || 'live') : 'none';

    const errorText = list.loadError || (!list.demoMode && list.lastError
      ? 'Last sync failed: ' + list.lastError + (list.loaded ? ' (still using the last good list)' : '')
      : '');
    $('sync-error').textContent = errorText;
    $('sync-error').hidden = !errorText;
  }

  async function refresh() {
    const url = await currentUrl();
    const res = await chrome.runtime.sendMessage({ type: 'checkUrl', url });
    if (res && res.check) renderStatus(res.check, res.list);
  }

  // ---- Buttons ---------------------------------------------------------------
  $('sync-now').addEventListener('click', async () => {
    const button = $('sync-now');
    button.disabled = true;
    button.textContent = 'Syncing…';
    try {
      await chrome.runtime.sendMessage({ type: 'syncNow' });
      await refresh();
    } finally {
      button.disabled = false;
      button.textContent = 'Sync now';
    }
  });

  $('dashboard').addEventListener('click', async (event) => {
    event.preventDefault();
    const { settings } = await chrome.storage.local.get('settings');
    const url = (settings && settings.dashboardUrl) || CONFIG.DEFAULT_DASHBOARD_URL;
    // Plain link to the dashboard: no current-site info in the URL.
    if (/^https?:\/\//i.test(url)) chrome.tabs.create({ url });
  });

  $('options').addEventListener('click', (event) => {
    event.preventDefault();
    chrome.runtime.openOptionsPage();
  });

  refresh();
})();
