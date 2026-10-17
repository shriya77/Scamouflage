/*
 * config.js: settings that ship inside the extension.
 *
 * The public keys below decide which signed lists the extension trusts.
 * Public keys are safe to commit; the matching PRIVATE keys live only in
 * keys/ on the VM (git-ignored).
 *
 *   LIVE_KEYS: keys allowed to sign the list downloaded from the backend.
 *              Print yours with:  python -m backend.make_keys
 *   DEMO_KEYS: keys allowed to sign ONLY the bundled demo_blocklist.json.
 *              A demo-signed list is rejected if it comes from the backend.
 *
 * Loaded with importScripts() in the service worker and with <script> in pages,
 * so it attaches to `self` (which is `window` in pages).
 */
self.SCAMOUFLAGE_CONFIG = Object.freeze({
  // Where the Scamouflage backend is. We reach the VM through an SSH tunnel:
  //   ssh -L 8000:localhost:8000 user@vm
  // Users can change this on the options page.
  DEFAULT_BACKEND_URL: 'http://localhost:8000',

  // The Scamouflage dashboard opened from the popup. Editable on the options page.
  DEFAULT_DASHBOARD_URL: 'http://localhost:8000/',

  // How often to download a fresh list (chrome.alarms, minutes).
  SYNC_PERIOD_MINUTES: 30,

  // If no list has ever loaded, retry sooner than the normal 30 minutes.
  RETRY_WHEN_EMPTY_MINUTES: 2,

  // key_id -> base64 raw 32-byte Ed25519 public key.
  LIVE_KEYS: Object.freeze({
    // keys/blocklist_ed25519.pem, generated on the VM on 2026-10-17.
    'scamouflage-vm-1': 'eugJKnIzUa+nVMw0SCTIGIpPGUvlNfWGYkYutLzV3gM=',
  }),
  DEMO_KEYS: Object.freeze({
    'tolltrap-demo-1': '6uiw89e2W4xa99Ckt4vOJfxD7YVo0rhX+5GvpaEIsjM=',
  }),

  // The bundled demo list (built by: python -m backend.sign_demo_list).
  DEMO_LIST_PATH: 'demo_blocklist.json',
});
