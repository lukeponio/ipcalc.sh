// Regenerates test/golden.json from the real ipcalc. Only needed when adding
// cases; the committed golden.json lets the suite run without Perl.
//   node test/gen-golden.mjs [randomCount=3000]
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { cpus } from 'node:os';
import { CURATED, generateCases } from './cases.mjs';
import { realVariants, pool } from './real.mjs';

const count = Number(process.argv[2] ?? 3000);
const seen = new Set();
const cases = [...CURATED, ...generateCases(20261106, count)].filter((a) => {
  const k = JSON.stringify(a);
  return !seen.has(k) && seen.add(k);
});

// Keep the file small: big listings (up to 1000 subnets) are stored as a hash.
const shrink = (o) => o.length <= 16384 ? o
  : { sha256: createHash('sha256').update(o, 'latin1').digest('hex'), bytes: o.length, head: o.slice(0, 2000) };

const results = await pool(cases, cpus().length * 2, async (argv, i) => {
  if (i % 250 === 0) process.stderr.write(`${i}/${cases.length}\n`);
  const { status, outputs } = await realVariants(argv);
  return { argv, status, outputs: outputs.map(shrink) };
});
writeFileSync(new URL('./golden.json', import.meta.url), JSON.stringify({
  tool: 'ipcalc 0.51 (Debian/Ubuntu package ipcalc_0.51-1, Krischan Jodies)',
  note: 'stdout through a pipe (no tty), TERM=xterm. outputs lists every variant seen across Perl hash seeds. Outputs over 16 KiB are stored as sha256 of the bytes plus the first 2000 chars. status: exit code, or "hang" if the real tool never terminates.',
  cases: results,
}, null, 1) + '\n');
console.log(`wrote ${results.length} cases`);
