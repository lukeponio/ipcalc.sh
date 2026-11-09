// Regenerates test/rh/golden.json from the reference Red Hat ipcalc.
//   node test/rh/gen-golden.mjs [randomCount=3000]
import { writeFileSync } from 'node:fs';
import { cpus } from 'node:os';
import { CURATED, generateCases } from './cases.mjs';
import { runRealRh } from './real.mjs';
import { pool } from '../real.mjs';

const count = Number(process.argv[2] ?? 3000);
const seen = new Set();
const cases = [...CURATED, ...generateCases(20261106, count)].filter((a) => {
  const k = JSON.stringify(a);
  return !seen.has(k) && seen.add(k);
});
const results = await pool(cases, cpus().length * 2, async (argv) => ({ argv, ...(await runRealRh(argv)) }));
writeFileSync(new URL('./golden.json', import.meta.url), JSON.stringify({
  tool: 'Red Hat ipcalc 1.0.3 (upstream build, GeoIP compiled in, no GeoLite2 databases)',
  note: 'stdout (line-buffered) and stderr merged, as a terminal shows them. status: exit code, 134/139 for abort/segfault, or "hang".',
  cases: results,
}, null, 1) + '\n');
console.log(`wrote ${results.length} cases`);
