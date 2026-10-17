/*
 * Optional: run the same matcher tests from a terminal (Node 18+).
 *   node extension/tests/run-in-node.js
 * Chrome doesn't load this file; it's only for quick checks and CI.
 */
'use strict';
const path = require('path');

const nacl = require(path.join(__dirname, '..', 'lib', 'nacl-fast.min.js'));
const M = require(path.join(__dirname, '..', 'matcher.js'));
const { runAll } = require(path.join(__dirname, 'matcher.test.js'));

runAll(M, nacl, globalThis.crypto.subtle).then((results) => {
  for (const r of results) {
    console.log((r.ok ? 'PASS  ' : 'FAIL  ') + r.name + (r.ok ? '' : '\n      ' + r.error));
  }
  const failed = results.filter((r) => !r.ok).length;
  console.log(failed ? `\n${failed} of ${results.length} tests FAILED` : `\nAll ${results.length} tests passed`);
  process.exit(failed ? 1 : 0);
});
