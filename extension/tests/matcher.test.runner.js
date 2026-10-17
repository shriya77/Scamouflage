/*
 * Runs the tests and shows the results on matcher.test.html.
 * (A separate file because extension pages can't run inline <script> code.)
 */
(async function () {
  'use strict';
  const results = await self.ScamMatcherTests.runAll(self.ScamMatcher, self.nacl, crypto.subtle);
  const list = document.getElementById('results');

  for (const r of results) {
    const li = document.createElement('li');
    li.className = r.ok ? 'pass' : 'fail';
    li.textContent = (r.ok ? 'PASS  ' : 'FAIL  ') + r.name;
    if (!r.ok) {
      const err = document.createElement('span');
      err.className = 'error';
      err.textContent = r.error;
      li.appendChild(err);
    }
    list.appendChild(li);
  }

  const failed = results.filter((r) => !r.ok).length;
  const summary = document.getElementById('summary');
  summary.className = failed ? 'fail' : 'pass';
  summary.textContent = failed
    ? failed + ' of ' + results.length + ' tests FAILED'
    : 'All ' + results.length + ' tests passed';
  document.title = (failed ? 'FAIL' : 'PASS') + ' - Scamouflage matcher tests';
})();
