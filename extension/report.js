/*
 * report.js: the "Report to the registrar" window.
 *
 * warning.js opens this page in its own window as report.html?host=...
 * It asks background.js ("draftReport") for a drafted abuse e-mail to the
 * site's registrar and shows it with "Open in my mail app" (mailto:) and
 * "Copy text". The person sends it from their own mail program.
 *
 * Everything is inserted with textContent / value (never innerHTML).
 */
(function () {
  'use strict';

  const params = new URLSearchParams(location.search);
  const host = (params.get('host') || '').trim().toLowerCase();

  const statusEl = document.getElementById('status');
  const ready = document.getElementById('ready');
  const note = document.getElementById('note');
  const copyBtn = document.getElementById('copy');
  const retryBtn = document.getElementById('retry');
  const mailto = document.getElementById('mailto');

  document.getElementById('site').textContent = host || '(no site given)';
  document.title = 'Report ' + (host || 'site') + ': Scamouflage';

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
  const CONTACT_ERRORS = {
    not_found: 'The public registration record for this domain is already gone (deleted or suspended).',
    no_registered_domain: 'This site lives on shared hosting; report it to the hosting provider instead.',
    timeout: 'The registry did not answer in time. Try again in a moment.',
    rate_limited: 'The registry is rate-limiting lookups right now. Try again in a minute.',
  };

  let draft = null;

  function setStatus(text, isError) {
    statusEl.textContent = text;
    statusEl.classList.toggle('err', !!isError);
  }

  async function load() {
    draft = null;
    ready.hidden = true;
    copyBtn.hidden = true;
    mailto.hidden = true;
    retryBtn.hidden = true;
    note.textContent = '';
    if (!host) {
      setStatus('No site to report.', true);
      return;
    }
    setStatus('Looking up who registered this site…', false);
    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: 'draftReport', hostname: host });
    } catch (_) {
      res = { error: 'The extension could not process the request.', code: 'internal' };
    }
    if (!res || res.error) {
      const code = res && res.code;
      setStatus((code && ERRORS[code]) || (res && res.error) || 'Something went wrong.', true);
      retryBtn.hidden = !(code === 'offline' || code === 'rate_limited' || code === 'server_error');
      return;
    }
    draft = res;
    document.getElementById('registrar').textContent =
      res.registrar || 'unknown (no registrar name in the public record)';
    document.getElementById('subject').textContent = res.subject;
    document.getElementById('text').value = res.body;
    copyBtn.hidden = false;
    if (res.to.length && res.mailto) {
      document.getElementById('to').textContent = res.to.join(', ') + (res.phone ? ' · ' + res.phone : '');
      mailto.href = res.mailto;
      mailto.hidden = false;
      setStatus('Here is the report. Read it, then send it from your mail app.', false);
    } else {
      document.getElementById('to').textContent = 'no abuse contact published';
      const why = CONTACT_ERRORS[res.contactError] || (res.contactError === 'no_abuse_contact'
        ? 'The registrar does not publish an abuse mailbox in the public record. Search for "' +
          (res.registrar || 'the registrar') + ' report abuse" and paste the text into their form.'
        : 'No abuse contact could be found automatically; copy the text and send it yourself.');
      setStatus(why, true);
      retryBtn.hidden = !(res.contactError === 'timeout' || res.contactError === 'rate_limited');
    }
    ready.hidden = false;
    (mailto.hidden ? copyBtn : mailto).focus();
  }

  copyBtn.addEventListener('click', async () => {
    if (!draft) return;
    const text = 'To: ' + draft.to.join(', ') + '\nSubject: ' + draft.subject + '\n\n' + draft.body;
    try {
      await navigator.clipboard.writeText(text);
      note.textContent = 'Copied.';
    } catch (_) {
      const ta = document.getElementById('text');
      ta.focus(); ta.select();
      note.textContent = 'Select the text and copy it.';
    }
  });
  retryBtn.addEventListener('click', load);
  document.getElementById('close').addEventListener('click', () => window.close());
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') window.close(); });

  load();
})();
