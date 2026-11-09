// Guard for /ng/: the Red Hat ipcalc port must match the reference build.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ipcalcRh } from '../src/ipcalc-rh.js';
import { matchesRh } from './rh/match.mjs';

const golden = JSON.parse(readFileSync(new URL('./rh/golden.json', import.meta.url), 'latin1'));

test(`rh golden: ${golden.cases.length} cases match Red Hat ipcalc 1.0.3`, () => {
  const bad = golden.cases.filter((c) => !matchesRh(c, ipcalcRh(c.argv)));
  if (bad.length) {
    const c = bad[0], got = ipcalcRh(c.argv);
    assert.fail(`${bad.length} mismatches. First: ${JSON.stringify(c.argv)} status ${got.status} vs ${c.status}\n--- expected\n${c.stdout}--- got\n${got.stdout}`);
  }
});

test('random-private follows the real tool\'s shapes', () => {
  for (let k = 0; k < 200; k++) {
    const v4 = ipcalcRh(['-r', '24']).stdout;
    assert.match(v4, /^Network:\t(10\.\d+|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d+\.0\/24\nNetmask:\t255\.255\.255\.0 = 24\n/);
    assert.match(ipcalcRh(['-r', '8']).stdout, /^Network:\t10\.0\.0\.0\/8\n/);
    assert.match(ipcalcRh(['-r', '64']).stdout, /^Full Network:\tfd[0-9a-f]{2}:[0-9a-f]{4}:[0-9a-f]{4}:[0-9a-f]{4}:0000:0000:0000:0000\/64\nNetwork:\tfd/);
  }
  assert.deepEqual(ipcalcRh(['-r', '24', '1.2.3.4']), { stdout: "ipcalc: provided superfluous parameter '1.2.3.4'\n", status: 1 });
});

test('DNS options are refused, not faked', () => {
  assert.equal(ipcalcRh(['-h', '8.8.8.8']).status, 1);
  assert.match(ipcalcRh(['-o', 'example.com']).stdout, /not available on ipcalc\.sh/);
});

test('endless output is capped', () => {
  const r = ipcalcRh(['-S', '32', '0.0.0.0/0']);
  assert.equal(r.status, 'truncated');
  assert.ok(r.stdout.length <= (1 << 20) + 64);
});
