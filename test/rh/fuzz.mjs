// Live differential fuzz against the reference Red Hat ipcalc.
//   node test/rh/fuzz.mjs [count=3000] [seed=random]
import { cpus } from 'node:os';
import { generateCases } from './cases.mjs';
import { runRealRh } from './real.mjs';
import { pool } from '../real.mjs';
import { ipcalcRh } from '../../src/ipcalc-rh.js';
import { matchesRh } from './match.mjs';

const count = Number(process.argv[2] ?? 3000);
const seed = Number(process.argv[3] ?? Math.floor(Math.random() * 2 ** 31));
console.log(`fuzz seed ${seed}, ${count} cases`);
let bad = 0;
await pool(generateCases(seed, count), cpus().length * 2, async (argv) => {
  const real = await runRealRh(argv);
  const got = ipcalcRh(argv);
  if (!matchesRh(real, got) && bad++ < 8) {
    const a = real.stdout.split('\n'), b = got.stdout.split('\n');
    let i = 0; while (i < a.length && a[i] === b[i]) i++;
    console.log(`MISMATCH ${JSON.stringify(argv)} real=${real.status} port=${got.status} line ${i + 1}\n  real: ${JSON.stringify(a.slice(i, i + 3))}\n  port: ${JSON.stringify(b.slice(i, i + 3))}`);
  }
});
console.log(bad ? `${bad} mismatches` : 'all match');
process.exit(bad ? 1 : 0);
