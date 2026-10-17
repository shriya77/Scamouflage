/*
 * warning.js: fills in the red warning page and handles its two buttons.
 *
 * background.js opens this page as:
 *   warning.html?url=...&host=...&matched=...&score=...&reasons=[...]&observed=...&source=...&back=...
 *
 * Everything is inserted with textContent (never innerHTML), so nothing in the
 * list can inject HTML into this page.
 */
(function () {
  'use strict';

  const M = self.ScamMatcher;
  const params = new URLSearchParams(location.search);

  const originalUrl = params.get('url') || '';
  const host = params.get('host') || '';
  const matched = params.get('matched') || '';
  const scoreText = params.get('score');
  const score = scoreText === null || scoreText === '' ? null : Number(scoreText);
  const observed = params.get('observed') || '';
  const source = params.get('source') || '';
  const backUrl = params.get('back') || '';

  let reasons = [];
  try {
    const parsed = JSON.parse(params.get('reasons') || '[]');
    if (Array.isArray(parsed)) reasons = parsed.filter((r) => typeof r === 'string');
  } catch (_) {
    reasons = [];
  }

  // ---- Step 1: fill in the text -------------------------------------------
  const headline = document.getElementById('headline');
  headline.textContent = score === null
    ? 'Scamouflage flagged this site as a likely toll scam.'
    : 'Scamouflage flagged this site as a likely toll scam (score ' + M.formatScore(score) + ').';

  document.getElementById('domain').textContent = host || '(unknown site)';

  // If a parent domain matched, say so: "pay.ezpass.com-xk2.win" is flagged
  // because "com-xk2.win" (the whole site) is on the list.
  if (matched && host && matched !== host) {
    const note = document.getElementById('matched-note');
    note.textContent = 'Flagged because it belongs to ' + matched + ', which is on the list.';
    note.hidden = false;
  }

  const list = document.getElementById('reasons');
  if (reasons.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'No specific reason was recorded.';
    list.appendChild(li);
  } else {
    for (const code of reasons) {
      const li = document.createElement('li');
      li.textContent = M.explainReason(code);
      list.appendChild(li);
    }
  }

  const observedEl = document.getElementById('observed');
  const observedDate = observed ? new Date(observed) : null;
  if (observedDate && !Number.isNaN(observedDate.getTime())) {
    observedEl.textContent = 'Its HTTPS certificate was first seen on ' +
      observedDate.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) + '.';
  } else {
    observedEl.textContent = 'We don\'t know when its certificate was first seen.';
  }

  if (source) {
    document.getElementById('source').textContent = 'List source: ' + source + '.';
  }

  // ---- Step 2: "Go back" ----------------------------------------------------
  // background.js tells us the last page in this tab that wasn't flagged.
  // Going there is more reliable than history.back(): if the flagged page
  // loaded before the warning did, one step back would land on it again.
  document.getElementById('go-back').addEventListener('click', async () => {
    let back = null;
    try {
      back = backUrl ? new URL(backUrl) : null;
    } catch (_) {
      back = null;
    }
    if (back && (back.protocol === 'http:' || back.protocol === 'https:')) {
      location.replace(back.href); // replace: the warning page leaves history
      return;
    }
    // Nothing safe to go back to (e.g. the link opened in a new tab): close
    // this tab. If it's the last tab in the window, open a new tab first so
    // the window doesn't close.
    try {
      const tab = await chrome.tabs.getCurrent();
      const tabsInWindow = await chrome.tabs.query({ windowId: tab.windowId });
      if (tabsInWindow.length <= 1) await chrome.tabs.create({ windowId: tab.windowId });
      await chrome.tabs.remove(tab.id);
    } catch (_) {
      window.close();
    }
  });

  // ---- Step 3: "Continue anyway" -------------------------------------------
  // Allow this hostname for the rest of the browser session, then load the
  // original URL. Only http(s) URLs are accepted.
  document.getElementById('continue').addEventListener('click', async () => {
    let target;
    try {
      target = new URL(originalUrl);
    } catch (_) {
      return;
    }
    if (target.protocol !== 'http:' && target.protocol !== 'https:') return;

    await chrome.runtime.sendMessage({ type: 'allowHost', hostname: host || target.hostname });
    location.replace(target.href); // replace: so "back" from the site skips this page
  });
})();
