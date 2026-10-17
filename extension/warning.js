/*
 * warning.js: fills in the red warning page and handles its two buttons.
 *
 * background.js opens this page as:
 *   warning.html?url=...&host=...&matched=...&score=...&reasons=[...]&observed=...&committed=0|1
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
  const committed = params.get('committed') === '1';

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
  // If the flagged page itself made it into history (committed), going back
  // one step would land on it again, so we go back two steps.
  document.getElementById('go-back').addEventListener('click', async () => {
    const steps = committed ? 2 : 1;
    if (history.length > steps) {
      history.go(-steps);
      return;
    }
    // No safe page to go back to: open a fresh new tab and close this one.
    try {
      const tab = await chrome.tabs.getCurrent();
      await chrome.tabs.create({});
      if (tab && tab.id !== undefined) await chrome.tabs.remove(tab.id);
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
