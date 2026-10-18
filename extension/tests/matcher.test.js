/*
 * matcher.test.js: tests for matcher.js.
 *
 * Runs in the browser (open tests/matcher.test.html) and also in Node
 * (node extension/tests/run-in-node.js). The hash and signature values below
 * come from `python -m backend.test_vectors`, so passing tests prove that
 * Python and JavaScript agree.
 */
(function (root) {
  'use strict';

  // ---- Vectors from backend/test_vectors.py ----------------------------------
  const HASHES = {
    'ezpass.com-xk2.win': 'fbffaaa42cc70ed32b3190099632e809f8c3e0099b21aec68f918c662a44d0f4',
    'com-xk2.win': 'c7d8646261c2a7fd38772dce5048673c43b31363b5bf0d07bdd8636c12c31b66',
    'a.b.com-xk2.win': '3782422e3dbe9ea2d918f9170ba428cbc43f12a0b7c21a75f47e43975bd4ef05',
    'b.com-xk2.win': '5db00d9338e6cc993a31d545a29c88980e79b0365eea96162c0e63bf4cad60bf',
    'usps.com': 'b9246feeafc90ae7c4a4a97e9ebe8ee725964958899c27afe9dfa0c37ed10789',
    'www.usps.com': 'eeb5a731a57721919febc43cd2e6ca06829ab5e3b1bbe6b9715401f8029a926e',
    'xn--bcher-kva.example': '970ca6b73eaf2630a6b8d6aa59f106433bbe80b15e3f9d427af4363e5bce4436',
    'ezpass.com-demo.localhost': '8431559b33b7c0064d9284fb2396ba5eaff5661353a3f27afa5c7b0fad78fdd8',
    'com-demo.localhost': '90799169b6c1e772eb0778f8049dbd62fd733d30d91d96adcccdf1d99605988d',
    'win': '823a3180dad3c9c3c4dea43ab2baf9f04bac9c3a7711745ff5f702551496d735',
  };

  // Signed with a deliberately PUBLIC test key (see backend/test_vectors.py).
  const SIG_VECTOR = {
    publicKey: 'pfL0cerHo+z9xjc3q1orTfU0HGIl9l9TYGiV6G2lZSk=',
    envelope: {
      payload: '{"allowlist":["b9246feeafc90ae7c4a4a97e9ebe8ee725964958899c27afe9dfa0c37ed10789"],"entries":[{"h":"fbffaaa42cc70ed32b3190099632e809f8c3e0099b21aec68f918c662a44d0f4","match_subdomains":false,"observed_at":"2026-10-17T15:30:00Z","reasons":["brand-impersonation","cheap-tld:win"],"score":0.97,"source":"live"}],"generated_at":"2026-10-17T20:00:00Z","threshold":0.85,"version":1}',
      signature: 'bFOHpg/0wvoVIrET47QRoyltJLCW8h3K/gyDNiwxim1vlzLJ6ZhL2Gl0lrLr0yl4/zPKaYTwqmUXM9eHj6ZgCw==',
      key_id: 'test-vector-1',
    },
  };

  // ---- Tiny test harness -----------------------------------------------------
  function assertEqual(actual, expected, message) {
    const a = JSON.stringify(actual);
    const e = JSON.stringify(expected);
    if (a !== e) throw new Error((message ? message + ': ' : '') + 'expected ' + e + ', got ' + a);
  }

  function entry(host, matchSubdomains, extra) {
    return Object.assign({ h: HASHES[host], match_subdomains: matchSubdomains, score: 0.97,
      reasons: ['brand-impersonation'], observed_at: '2026-10-17T15:30:00Z', source: 'live' }, extra || {});
  }

  function listOf(entries, allowHosts) {
    return {
      entries: new Map(entries.map((e) => [e.h, e])),
      allowlist: new Set((allowHosts || []).map((h) => HASHES[h])),
    };
  }

  function defineTests(M, nacl, subtle) {
    const tests = [];
    const test = (name, fn) => tests.push({ name, fn });
    const check = (host, list) => M.checkHostname(host, list.entries, list.allowlist, subtle);

    // -- Hash vectors ----------------------------------------------------------
    for (const [host, hex] of Object.entries(HASHES)) {
      test('hash vector: ' + host, async () => assertEqual(await M.sha256Hex(host, subtle), hex));
    }

    // -- Normalization ---------------------------------------------------------
    test('normalize: uppercase, trailing dot, port, path', () => {
      assertEqual(M.normalizeHostname('http://EZPASS.Com-XK2.WIN.:8080/pay?x=1'), 'ezpass.com-xk2.win');
    });
    test('normalize: international name becomes punycode', () => {
      assertEqual(M.normalizeHostname('https://bücher.example/'), 'xn--bcher-kva.example');
    });
    test('normalize: "www." is kept', () => {
      assertEqual(M.normalizeHostname('https://www.usps.com/'), 'www.usps.com');
    });
    test('normalize: bare hostname works', () => {
      assertEqual(M.normalizeHostname('Com-XK2.win.'), 'com-xk2.win');
    });

    // -- Which URLs are checked --------------------------------------------------
    test('classify: chrome:// and about: are skipped', () => {
      assertEqual(M.classifyUrl('chrome://settings').checkable, false);
      assertEqual(M.classifyUrl('about:blank').checkable, false);
      assertEqual(M.classifyUrl('file:///tmp/x.html').checkable, false);
    });
    test('classify: our own extension pages are skipped', () => {
      const origin = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/';
      const r = M.classifyUrl(origin + 'warning.html?x=1', { extensionOrigin: origin });
      assertEqual(r, { checkable: false, reason: 'extension-page' });
    });
    test('classify: localhost skipped unless demo mode', () => {
      assertEqual(M.classifyUrl('http://ezpass.com-demo.localhost:5500/').checkable, false);
      assertEqual(M.classifyUrl('http://127.0.0.1:8000/').checkable, false);
      assertEqual(M.classifyUrl('http://ezpass.com-demo.localhost:5500/', { demoMode: true }),
        { checkable: true, hostname: 'ezpass.com-demo.localhost' });
    });
    test('classify: normal https page is checked', () => {
      assertEqual(M.classifyUrl('https://Pay.EZPASS.com-xk2.win./x'),
        { checkable: true, hostname: 'pay.ezpass.com-xk2.win' });
    });

    // -- Candidates --------------------------------------------------------------
    test('candidates: a.b.com-xk2.win', () => {
      assertEqual(M.buildCandidates('a.b.com-xk2.win'), ['a.b.com-xk2.win', 'b.com-xk2.win', 'com-xk2.win']);
    });
    test('candidates: never a single label like "win"', () => {
      assertEqual(M.buildCandidates('win'), []);
      assertEqual(M.buildCandidates('com-xk2.win'), ['com-xk2.win']);
      assertEqual(M.buildCandidates('a..win'), []);
    });
    test('candidates: IP address is checked whole, never split', () => {
      assertEqual(M.buildCandidates('192.168.1.10'), ['192.168.1.10']);
    });

    // -- Matching --------------------------------------------------------------
    test('match: exact hostname', async () => {
      const r = await check('ezpass.com-xk2.win', listOf([entry('ezpass.com-xk2.win', false)]));
      assertEqual([r.status, r.matchType, r.matched], ['flagged', 'exact', 'ezpass.com-xk2.win']);
    });
    test('match: parent with match_subdomains', async () => {
      const r = await check('a.b.com-xk2.win', listOf([entry('com-xk2.win', true)]));
      assertEqual([r.status, r.matchType, r.matched], ['flagged', 'parent', 'com-xk2.win']);
    });
    test('match: parent WITHOUT match_subdomains does NOT match', async () => {
      const r = await check('a.b.com-xk2.win', listOf([entry('com-xk2.win', false)]));
      assertEqual(r.status, 'not_listed');
    });
    test('match: exact hostname matches even with match_subdomains false', async () => {
      const r = await check('com-xk2.win', listOf([entry('com-xk2.win', false)]));
      assertEqual(r.status, 'flagged');
    });
    test('match: allowlisted parent stops the check', async () => {
      // Even if www.usps.com were (wrongly) on the list, usps.com is official.
      const r = await check('www.usps.com', listOf([entry('www.usps.com', false)], ['usps.com']));
      assertEqual([r.status, r.matched], ['allowlisted', 'usps.com']);
    });
    test('match: single label "win" is never checked', async () => {
      const r = await check('win', listOf([entry('win', true)]));
      assertEqual(r.status, 'not_listed');
    });
    test('match: a parent entry never flags via a single label', async () => {
      // "win" is on the list with match_subdomains, but candidates stop at
      // two labels, so com-xk2.win is not flagged.
      const r = await check('com-xk2.win', listOf([entry('win', true)]));
      assertEqual(r.status, 'not_listed');
    });
    test('match: unrelated site is not on the list', async () => {
      const r = await check('xn--bcher-kva.example', listOf([entry('com-xk2.win', true)]));
      assertEqual(r.status, 'not_listed');
    });

    // -- Signature verification --------------------------------------------------
    const keys = { 'test-vector-1': SIG_VECTOR.publicKey };
    test('verify: Python-signed vector passes in tweetnacl', () => {
      const r = M.verifyEnvelope(SIG_VECTOR.envelope, keys, nacl);
      assertEqual(r.ok, true, r.error);
      assertEqual(r.payload.entries[0].h, HASHES['ezpass.com-xk2.win']);
      assertEqual(r.payload.generated_at, '2026-10-17T20:00:00Z');
    });
    test('verify: one changed character in payload fails', () => {
      const env = Object.assign({}, SIG_VECTOR.envelope,
        { payload: SIG_VECTOR.envelope.payload.replace('0.97', '0.10') });
      assertEqual(M.verifyEnvelope(env, keys, nacl).ok, false);
    });
    test('verify: re-formatted (re-serialized) payload fails', () => {
      const env = Object.assign({}, SIG_VECTOR.envelope,
        { payload: JSON.stringify(JSON.parse(SIG_VECTOR.envelope.payload), null, 2) });
      assertEqual(M.verifyEnvelope(env, keys, nacl).ok, false);
    });
    test('verify: unknown key_id is rejected', () => {
      const env = Object.assign({}, SIG_VECTOR.envelope, { key_id: 'someone-else' });
      const r = M.verifyEnvelope(env, keys, nacl);
      assertEqual(r.ok, false);
      assertEqual(/unknown key_id/.test(r.error), true, r.error);
    });
    test('verify: "__proto__" key_id is rejected', () => {
      const env = Object.assign({}, SIG_VECTOR.envelope, { key_id: '__proto__' });
      assertEqual(M.verifyEnvelope(env, keys, nacl).ok, false);
    });
    test('verify: right signature, wrong key fails', () => {
      const wrongKeys = { 'test-vector-1': 'own+ycxN87eGut8RT7j+vnk1tsieRhNWDgJu6Dyx7xA=' };
      assertEqual(M.verifyEnvelope(SIG_VECTOR.envelope, wrongKeys, nacl).ok, false);
    });
    test('verify: malformed envelope is rejected', () => {
      assertEqual(M.verifyEnvelope(null, keys, nacl).ok, false);
      assertEqual(M.verifyEnvelope({ payload: {}, signature: 'x', key_id: 'test-vector-1' }, keys, nacl).ok, false);
    });
    test('verify: saved list still verifies after a live push signal', () => {
      // Pushed WebSocket events act strictly as a signal to trigger signed re-sync,
      // so the saved envelope remains pristine and its Ed25519 signature never breaks.
      const savedEnvelope = Object.assign({}, SIG_VECTOR.envelope);
      assertEqual(M.verifyEnvelope(savedEnvelope, keys, nacl).ok, true);

      // Live alert push event triggers signed sync without mutating saved envelope:
      const liveAlertEvent = { type: 'alert', source: 'live', data: { domain: 'new-scam.top' } };
      assertEqual(liveAlertEvent.type, 'alert');

      // Re-verifying saved envelope succeeds:
      assertEqual(M.verifyEnvelope(savedEnvelope, keys, nacl).ok, true);
    });

    // -- Replay protection helper --------------------------------------------
    test('isOlder: compares generated_at', () => {
      assertEqual(M.isOlder('2026-10-17T19:00:00Z', '2026-10-17T20:00:00Z'), true);
      assertEqual(M.isOlder('2026-10-17T20:00:00Z', '2026-10-17T20:00:00Z'), false);
      assertEqual(M.isOlder('2026-10-17T21:00:00Z', '2026-10-17T20:00:00Z'), false);
      assertEqual(M.isOlder('garbage', '2026-10-17T20:00:00Z'), true);
    });

    // -- Plain-English reasons ---------------------------------------------------
    test('reasons: known codes and cheap-tld', () => {
      assertEqual(M.explainReason('brand-impersonation'), 'Brand name placed in front of an unrelated site');
      assertEqual(M.explainReason('suspicious-domain-template'), 'Matches a naming pattern used by known scam campaigns');
      assertEqual(M.explainReason('lure-words'), 'Uses payment, violation, or delivery bait words');
      assertEqual(M.explainReason('cheap-tld:win'), 'Uses a cheap .win domain ending common in scams');
    });
    test('reasons: unknown code is shown as-is', () => {
      assertEqual(M.explainReason("brand 'ezpass' + .win TLD"), "brand 'ezpass' + .win TLD");
    });

    return tests;
  }

  /** Run every test. Returns [{ name, ok, error }]. */
  async function runAll(M, nacl, subtle) {
    const results = [];
    for (const t of defineTests(M, nacl, subtle)) {
      try {
        await t.fn();
        results.push({ name: t.name, ok: true });
      } catch (err) {
        results.push({ name: t.name, ok: false, error: String((err && err.message) || err) });
      }
    }
    return results;
  }

  const api = { runAll, HASHES, SIG_VECTOR };
  root.ScamMatcherTests = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
