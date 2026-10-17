/*
 * matcher.js: the pure helper functions behind Scamouflage.
 *
 * "Pure" means: no chrome.* APIs, no storage, no network. Every function only
 * looks at its inputs, which makes them easy to test (tests/matcher.test.html).
 *
 * Used by:
 *   background.js  (importScripts) to check pages and verify downloaded lists
 *   popup / warning pages (<script>) for reason text and small helpers
 *   tests          (<script> in the browser, or require() in Node)
 *
 * Everything is exposed as one object: ScamMatcher.
 */
(function (root) {
  'use strict';

  const HEX64 = /^[0-9a-f]{64}$/;
  const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

  // ---------------------------------------------------------------------------
  // 1. Normalizing hostnames
  //
  // Must match backend/blocklist_route.py normalize_hostname() exactly, or the
  // hashes won't line up. new URL().hostname already gives us lowercase ASCII
  // with punycode for international names and no port; we only strip a
  // trailing dot ("example.com." is the same site as "example.com").
  // ---------------------------------------------------------------------------
  function stripTrailingDots(hostname) {
    let h = hostname;
    while (h.endsWith('.')) h = h.slice(0, -1);
    return h;
  }

  /** Hostname from a full URL or a bare hostname. Returns null if invalid. */
  function normalizeHostname(input) {
    if (typeof input !== 'string' || !input.trim()) return null;
    const text = input.trim();
    try {
      const url = new URL(text.includes('://') ? text : 'http://' + text);
      const h = stripTrailingDots(url.hostname);
      return h || null;
    } catch (_) {
      return null;
    }
  }

  /** True for this computer: localhost, *.localhost, 127.x.x.x, ::1, 0.0.0.0. */
  function isLocalHostname(hostname) {
    return hostname === 'localhost' ||
      hostname.endsWith('.localhost') ||
      /^127\./.test(hostname) ||
      hostname === '[::1]' ||
      hostname === '0.0.0.0';
  }

  /**
   * Decide whether a URL should be checked at all.
   *   opts.demoMode         check localhost too (the demo page runs there)
   *   opts.extensionOrigin  "chrome-extension://<id>/" so we skip our own pages
   * Returns { checkable: true, hostname } or { checkable: false, reason, hostname? }.
   */
  function classifyUrl(url, opts) {
    const options = opts || {};
    let parsed;
    try {
      parsed = new URL(url);
    } catch (_) {
      return { checkable: false, reason: 'invalid-url' };
    }
    if (options.extensionOrigin && url.startsWith(options.extensionOrigin)) {
      return { checkable: false, reason: 'extension-page' };
    }
    // Skips chrome://, about:, file:, data:, chrome-extension://, etc.
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { checkable: false, reason: 'not-web' };
    }
    const hostname = stripTrailingDots(parsed.hostname);
    if (!hostname) return { checkable: false, reason: 'invalid-url' };
    if (isLocalHostname(hostname) && !options.demoMode) {
      return { checkable: false, reason: 'localhost', hostname };
    }
    return { checkable: true, hostname };
  }

  // ---------------------------------------------------------------------------
  // 2. Building candidates: the hostname, then each parent, stopping at two
  //    labels. We never check a single label like "win" or "com".
  //    a.b.com-xk2.win -> [a.b.com-xk2.win, b.com-xk2.win, com-xk2.win]
  // ---------------------------------------------------------------------------
  function buildCandidates(hostname) {
    if (typeof hostname !== 'string' || !hostname) return [];
    if (hostname.startsWith('[')) return []; // IPv6 literal, never on the list
    const labels = hostname.split('.');
    if (labels.length < 2 || labels.some((label) => label === '')) return [];
    if (IPV4.test(hostname)) return [hostname]; // "2.3.4" is not a parent of an IP
    const out = [];
    for (let i = 0; labels.length - i >= 2; i++) {
      out.push(labels.slice(i).join('.'));
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // 3. Hashing: SHA-256 of the hostname's UTF-8 bytes, as lowercase hex.
  //    The list only contains hashes, so this is how we compare.
  // ---------------------------------------------------------------------------
  async function sha256Hex(text, subtle) {
    const s = subtle || root.crypto.subtle;
    const digest = await s.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
  }

  /** [{ name, hash }] for each candidate, in the same order. */
  async function hashCandidates(candidates, subtle) {
    return Promise.all(candidates.map(async (name) => ({ name, hash: await sha256Hex(name, subtle) })));
  }

  // ---------------------------------------------------------------------------
  // 4. Matching
  //   entries:   Map(hash -> entry)   (entry has match_subdomains, score, ...)
  //   allowlist: Set(hash)
  //
  //   1) Any candidate on the allowlist  -> stop, not flagged.
  //   2) Full hostname matches any entry -> flagged.
  //   3) A parent matches an entry with match_subdomains: true -> flagged.
  //   Otherwise                          -> not on the list.
  // ---------------------------------------------------------------------------
  function matchHashed(hashed, entries, allowlist) {
    if (!hashed.length) return { status: 'not_listed' };

    for (const c of hashed) {
      if (allowlist.has(c.hash)) return { status: 'allowlisted', matched: c.name };
    }

    const [full, ...parents] = hashed;
    const exact = entries.get(full.hash);
    if (exact) return { status: 'flagged', matchType: 'exact', matched: full.name, entry: exact };

    for (const parent of parents) {
      const entry = entries.get(parent.hash);
      if (entry && entry.match_subdomains === true) {
        return { status: 'flagged', matchType: 'parent', matched: parent.name, entry };
      }
    }
    return { status: 'not_listed' };
  }

  /** For an already-normalized hostname: candidates -> hashes -> match. */
  async function checkHostname(hostname, entries, allowlist, subtle) {
    const hashed = await hashCandidates(buildCandidates(hostname), subtle);
    return matchHashed(hashed, entries, allowlist);
  }

  // ---------------------------------------------------------------------------
  // 5. Verifying a signed list
  //
  // We verify the RAW payload string BEFORE JSON.parse, so a tampered list is
  // rejected before any of its contents are trusted.
  //   trustedKeys: { key_id: base64PublicKey }
  //   naclLib:     tweetnacl (self.nacl)
  // Returns { ok: true, payload } or { ok: false, error }.
  // ---------------------------------------------------------------------------
  function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function verifyEnvelope(envelope, trustedKeys, naclLib) {
    if (!envelope || typeof envelope !== 'object' ||
        typeof envelope.payload !== 'string' ||
        typeof envelope.signature !== 'string' ||
        typeof envelope.key_id !== 'string') {
      return { ok: false, error: 'malformed envelope' };
    }

    // Only keys we ship in config.js count. hasOwnProperty stops tricks like
    // key_id "__proto__" or "toString".
    if (!Object.prototype.hasOwnProperty.call(trustedKeys, envelope.key_id)) {
      return { ok: false, error: 'unknown key_id "' + envelope.key_id + '"' };
    }

    let publicKey, signature;
    try {
      publicKey = base64ToBytes(trustedKeys[envelope.key_id]);
      signature = base64ToBytes(envelope.signature);
    } catch (_) {
      return { ok: false, error: 'bad base64 in key or signature' };
    }
    if (publicKey.length !== 32) return { ok: false, error: 'public key must be 32 bytes' };
    if (signature.length !== 64) return { ok: false, error: 'signature must be 64 bytes' };

    const message = new TextEncoder().encode(envelope.payload); // exact UTF-8 bytes
    if (!naclLib.sign.detached.verify(message, signature, publicKey)) {
      return { ok: false, error: 'signature check failed' };
    }

    // Signature is good: now it's safe to parse.
    let payload;
    try {
      payload = JSON.parse(envelope.payload);
    } catch (_) {
      return { ok: false, error: 'payload is not valid JSON' };
    }
    return validatePayload(payload);
  }

  /** Check the payload's shape and drop any malformed entries. */
  function validatePayload(payload) {
    if (!payload || typeof payload !== 'object') return { ok: false, error: 'payload is not an object' };
    if (payload.version !== 1) return { ok: false, error: 'unsupported list version ' + payload.version };
    if (typeof payload.generated_at !== 'string' || Number.isNaN(Date.parse(payload.generated_at))) {
      return { ok: false, error: 'missing or invalid generated_at' };
    }
    if (!Array.isArray(payload.entries)) return { ok: false, error: 'entries must be a list' };

    const entries = payload.entries
      .filter((e) => e && typeof e === 'object' && typeof e.h === 'string' && HEX64.test(e.h))
      .map((e) => ({
        h: e.h,
        match_subdomains: e.match_subdomains === true,
        score: typeof e.score === 'number' ? e.score : null,
        reasons: Array.isArray(e.reasons) ? e.reasons.filter((r) => typeof r === 'string') : [],
        observed_at: typeof e.observed_at === 'string' ? e.observed_at : null,
        source: typeof e.source === 'string' ? e.source : null,
      }));
    const allowlist = Array.isArray(payload.allowlist)
      ? payload.allowlist.filter((h) => typeof h === 'string' && HEX64.test(h))
      : [];

    return {
      ok: true,
      payload: {
        version: 1,
        generated_at: payload.generated_at,
        threshold: typeof payload.threshold === 'number' ? payload.threshold : null,
        entries,
        allowlist,
      },
    };
  }

  /** True if timestamp a is strictly older than b (both ISO strings). */
  function isOlder(a, b) {
    const ta = Date.parse(a);
    const tb = Date.parse(b);
    if (Number.isNaN(tb)) return false; // nothing valid saved yet
    if (Number.isNaN(ta)) return true;  // unreadable new date: treat as old
    return ta < tb;
  }

  /** "live", "replay", "live + replay", ... from the entries' source fields. */
  function describeSource(entries, fallback) {
    const sources = new Set(entries.map((e) => e.source).filter(Boolean));
    return sources.size ? Array.from(sources).sort().join(' + ') : (fallback || 'live');
  }

  // ---------------------------------------------------------------------------
  // 6. Plain-English reasons
  // ---------------------------------------------------------------------------
  const REASON_TEXT = {
    'brand-impersonation': 'Brand name placed in front of an unrelated site',
    'suspicious-domain-template': 'Matches a naming pattern used by known scam campaigns',
    'lure-words': 'Uses payment, violation, or delivery bait words',
  };

  function explainReason(code) {
    if (typeof code !== 'string') return String(code);
    if (Object.prototype.hasOwnProperty.call(REASON_TEXT, code)) return REASON_TEXT[code];
    if (code.startsWith('cheap-tld:')) {
      const tld = code.slice('cheap-tld:'.length).replace(/^\.+/, '');
      return 'Uses a cheap .' + tld + ' domain ending common in scams';
    }
    return code; // unknown codes are shown as-is
  }

  /** 0.97 -> "0.97" (two decimals), or "unknown". */
  function formatScore(score) {
    return typeof score === 'number' && Number.isFinite(score) ? score.toFixed(2) : 'unknown';
  }

  const api = {
    stripTrailingDots,
    normalizeHostname,
    isLocalHostname,
    classifyUrl,
    buildCandidates,
    sha256Hex,
    hashCandidates,
    matchHashed,
    checkHostname,
    base64ToBytes,
    verifyEnvelope,
    validatePayload,
    isOlder,
    describeSource,
    explainReason,
    formatScore,
  };

  root.ScamMatcher = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
