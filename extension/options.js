/*
 * options.js: settings page.
 *
 * Saves { backendUrl, dashboardUrl, demoMode } to chrome.storage.local.
 * background.js notices the change (storage.onChanged), reloads the right
 * list, and syncs.
 */
(function () {
  'use strict';

  const CONFIG = self.SCAMOUFLAGE_CONFIG;
  const $ = (id) => document.getElementById(id);

  function showStatus(text, ok) {
    const el = $('status');
    el.textContent = text;
    el.className = ok ? 'ok' : 'err';
  }

  /** Accept only http(s) URLs. Returns the cleaned URL or null. */
  function cleanUrl(value) {
    try {
      const url = new URL(value.trim());
      if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
      return url.href;
    } catch (_) {
      return null;
    }
  }

  // ---- Load current settings into the form ----------------------------------
  async function load() {
    const { settings } = await chrome.storage.local.get('settings');
    const s = settings || {};
    $('backend-url').value = s.backendUrl || CONFIG.DEFAULT_BACKEND_URL;
    $('dashboard-url').value = s.dashboardUrl || CONFIG.DEFAULT_DASHBOARD_URL;
    $('demo-mode').checked = !!s.demoMode;
    await loadAllowed();
  }

  async function loadAllowed() {
    const res = await chrome.runtime.sendMessage({ type: 'getAllowedHosts' });
    const list = $('allowed');
    list.textContent = '';
    const hosts = (res && res.hosts) || [];
    if (!hosts.length) {
      const li = document.createElement('li');
      li.textContent = '(none)';
      list.appendChild(li);
    }
    for (const host of hosts) {
      const li = document.createElement('li');
      li.textContent = host;
      list.appendChild(li);
    }
  }

  // ---- Save -------------------------------------------------------------------
  $('form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const backendUrl = cleanUrl($('backend-url').value);
    const dashboardUrl = cleanUrl($('dashboard-url').value);
    if (!backendUrl) return showStatus('Backend URL must start with http:// or https://', false);
    if (!dashboardUrl) return showStatus('Dashboard URL must start with http:// or https://', false);

    // The service worker needs host permission to fetch the backend.
    // http://localhost:8000 is granted at install; anything else is asked for
    // here. permissions.request must run straight from the click, before any
    // other await, or Chrome refuses it.
    const origin = new URL(backendUrl).origin + '/*';
    let granted = true;
    try {
      granted = await chrome.permissions.request({ origins: [origin] });
    } catch (err) {
      return showStatus('Could not request permission: ' + err.message, false);
    }
    if (!granted) return showStatus('Not saved: Chrome permission for ' + origin + ' was denied.', false);

    await chrome.storage.local.set({
      settings: {
        backendUrl: backendUrl.replace(/\/+$/, ''),
        dashboardUrl,
        demoMode: $('demo-mode').checked,
      },
    });
    showStatus('Saved. Syncing the list…', true);
    const res = await chrome.runtime.sendMessage({ type: 'syncNow' });
    if (res && res.sync && res.sync.ok) {
      showStatus('Saved. List loaded (' + res.list.entryCount + ' entries, source: ' + res.list.source + ').', true);
    } else {
      showStatus('Saved, but the list could not be loaded: ' +
        ((res && res.sync && res.sync.error) || 'unknown error'), false);
    }
  });

  $('clear-allowed').addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'clearAllowedHosts' });
    await loadAllowed();
  });

  // ---- Demo links (all served from this computer by demo/index.html) ---------
  const DEMO_SITES = [
    ['http://ezpass.com-demo.localhost:5500/', true, 'exact match'],
    ['http://pay.ezpass.com-demo.localhost:5500/', true, 'parent com-demo.localhost'],
    ['http://usps.com-demo.localhost:5500/', true, 'parent com-demo.localhost'],
    ['http://parent-only.localhost:5500/', true, 'exact match'],
    ['http://sub.parent-only.localhost:5500/', false, 'parent has no match_subdomains'],
    ['http://localhost:5500/', false, 'not on the list'],
  ];

  function renderDemoLinks() {
    const list = $('demo-list');
    for (const [url, warns, why] of DEMO_SITES) {
      const li = document.createElement('li');
      const tag = document.createElement('span');
      tag.className = 'tag ' + (warns ? 'tag-warn' : 'tag-ok');
      tag.textContent = warns ? 'Warning' : 'No warning';
      const link = document.createElement('a');
      link.href = url;
      link.target = '_blank';
      link.rel = 'noopener';
      link.textContent = url;
      const note = document.createElement('span');
      note.className = 'demo-why';
      note.textContent = why;
      li.append(tag, link, note);
      list.appendChild(li);
    }
  }

  function renderAbout() {
    const version = chrome.runtime.getManifest().version;
    const keys = Object.keys(CONFIG.LIVE_KEYS).join(', ');
    $('about-meta').textContent = 'Version ' + version + ' · trusted list key: ' + keys;
  }

  renderDemoLinks();
  renderAbout();
  load();
})();
