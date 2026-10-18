/*
 * warning.js: fills in the red warning page and handles its three buttons
 * (Go back, Report this site, Continue anyway).
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

  if (score !== null && Number.isFinite(score)) {
    const pct = Math.round(Math.min(1, Math.max(0, score)) * 100);
    document.getElementById('score-fill').style.width = pct + '%';
    document.getElementById('score-text').textContent = 'Risk score ' + M.formatScore(score);
    document.getElementById('score-meter').hidden = false;
  }

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

  // ---- Step 3: "Report this site" ------------------------------------------
  // Asks background.js for a drafted abuse e-mail to the site's registrar.
  // This is the only action that tells the server which site the user was on,
  // and the panel says so. The user sends the mail from their own mail app.
  const reportBtn = document.getElementById('report');
  const backdrop = document.getElementById('report-backdrop');
  const panel = document.getElementById('report-panel');
  const statusEl = document.getElementById('report-status');
  const ready = document.getElementById('report-ready');
  const copyBtn = document.getElementById('report-copy');
  const mailto = document.getElementById('report-mailto');
  const note = document.getElementById('report-note');
  document.getElementById('report-site').textContent = host || matched || '';

  // The dialog sits on top of the page. While it is open, Tab stays inside it
  // and Escape, the × button, "Close" or a click on the dimmed page close it.
  let lastFocus = null;
  function openDialog() {
    lastFocus = document.activeElement;
    backdrop.hidden = false;
    document.body.classList.add('dialog-open');
    document.getElementById('report-close').focus();
  }
  function closeDialog() {
    backdrop.hidden = true;
    document.body.classList.remove('dialog-open');
    if (lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus();
  }
  document.getElementById('report-close').addEventListener('click', closeDialog);
  document.getElementById('report-done').addEventListener('click', closeDialog);
  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) closeDialog(); });
  document.addEventListener('keydown', (e) => {
    if (backdrop.hidden) return;
    if (e.key === 'Escape') { e.preventDefault(); closeDialog(); return; }
    if (e.key !== 'Tab') return;
    const focusable = Array.from(panel.querySelectorAll('button, a[href], textarea'))
      .filter((n) => !n.hidden && n.offsetParent !== null);
    if (focusable.length === 0) return;
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });
  const ERRORS = {
    demo: null, // server text is used
    offline: 'Could not reach the Scamouflage server. Check your connection and try again.',
    not_flagged: 'This site is not in the live alert database, so there is no record to report yet. ' +
      'Your warning came from a list entry that has since been retired, or from a broader match.',
    not_eligible: 'This alert is below the bar Scamouflage sets for a takedown request (a very high score and a ' +
      'verified registration), so it is not reported automatically. You can still warn friends and report the ' +
      'text message to your carrier (forward it to 7726).',
    rate_limited: 'Too many reports from this connection in a short time. Please try again in a minute.',
    off: 'Reporting is switched off on the Scamouflage server right now.',
    no_route: 'The Scamouflage server you are connected to is running an older version without reporting. ' +
      'It needs to be updated (the API must include backend/abuse_report.py) and restarted.',
    server_error: 'The Scamouflage server hit an error while drafting the report. Please try again in a minute.',
  };
  let draft = null;

  function setStatus(text, isError) {
    statusEl.textContent = text;
    statusEl.classList.toggle('err', !!isError);
    statusEl.hidden = !text;
  }

  reportBtn.addEventListener('click', async () => {
    openDialog();
    if (draft) return; // already drafted: just show it again
    reportBtn.disabled = true;
    ready.hidden = true;
    copyBtn.hidden = true;
    mailto.hidden = true;
    note.textContent = '';
    setStatus('Looking up who registered this site…', false);
    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: 'draftReport', hostname: host || matched });
    } catch (_) {
      res = { error: 'The extension could not process the request.', code: 'internal' };
    }
    reportBtn.disabled = false;
    if (!res || res.error) {
      const code = res && res.code;
      setStatus((code && ERRORS[code]) || (res && res.error) || 'Something went wrong.', true);
      return;
    }
    draft = res;
    document.getElementById('report-registrar').textContent =
      res.registrar || 'unknown (no registrar name in the public record)';
    document.getElementById('report-subject').textContent = res.subject;
    document.getElementById('report-body').value = res.body;
    copyBtn.hidden = false;
    if (res.to.length && res.mailto) {
      document.getElementById('report-to').textContent = res.to.join(', ') + (res.phone ? ' · ' + res.phone : '');
      mailto.href = res.mailto;
      mailto.hidden = false;
      note.textContent = '';
      setStatus('Here is the report. Read it, then send it from your mail app.', false);
    } else {
      document.getElementById('report-to').textContent = 'no abuse contact published';
      mailto.hidden = true;
      const why = {
        not_found: 'The public registration record for this domain is already gone (deleted or suspended).',
        no_abuse_contact: 'The registrar does not publish an abuse mailbox in the public record. ' +
          'Search for "' + (res.registrar || 'the registrar') + ' report abuse" and paste the text into their form.',
        no_registered_domain: 'This site lives on shared hosting; report it to the hosting provider instead.',
        timeout: 'The registry did not answer in time. Try again in a moment.',
        rate_limited: 'The registry is rate-limiting lookups right now. Try again in a minute.',
      }[res.contactError] || 'No abuse contact could be found automatically; copy the text and send it yourself.';
      note.textContent = '';
      setStatus(why, true);
    }
    ready.hidden = false;
    if (!backdrop.hidden) (mailto.hidden ? copyBtn : mailto).focus();
  });

  copyBtn.addEventListener('click', async () => {
    if (!draft) return;
    const text = 'To: ' + draft.to.join(', ') + '\nSubject: ' + draft.subject + '\n\n' + draft.body;
    try {
      await navigator.clipboard.writeText(text);
      note.textContent = 'Copied.';
    } catch (_) {
      const ta = document.getElementById('report-body');
      ta.focus(); ta.select();
      note.textContent = 'Select the text and copy it.';
    }
  });

  // ---- Step 4: "Continue anyway" -------------------------------------------
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
