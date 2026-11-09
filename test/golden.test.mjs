// Baseline guard: the port must reproduce the real ipcalc byte-for-byte.
// Run: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { ipcalc } from '../src/ipcalc.js';

const golden = JSON.parse(readFileSync(new URL('./golden.json', import.meta.url), 'latin1'));

// Large outputs are stored as a hash of their bytes (see gen-golden.mjs).
const matches = (o, out) => typeof o === 'string' ? o === out
  : o.bytes === out.length && o.sha256 === createHash('sha256').update(out, 'latin1').digest('hex');

test(`golden: ${golden.cases.length} cases match real ipcalc 0.51`, () => {
  const failures = [];
  for (const c of golden.cases) {
    const got = ipcalc(c.argv);
    if (c.status === 'hang') {
      if (got.status !== 'hang') failures.push({ argv: c.argv, reason: 'real tool hangs, port returned' });
      continue;
    }
    if (got.status !== c.status) failures.push({ argv: c.argv, reason: `status ${got.status} != ${c.status}` });
    else if (!c.outputs.some((o) => matches(o, got.stdout))) {
      failures.push({ argv: c.argv, expected: c.outputs[0].head ?? c.outputs[0], got: got.stdout });
    }
  }
  if (failures.length) {
    const f = failures[0];
    assert.fail(`${failures.length} mismatches. First: ${JSON.stringify(f.argv)} ${f.reason ?? ''}\n` +
      (f.expected !== undefined ? `--- expected\n${f.expected}--- got\n${f.got}` : ''));
  }
});
