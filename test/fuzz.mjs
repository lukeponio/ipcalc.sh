// Live differential fuzz against the real ipcalc with fresh random inputs.
//   node test/fuzz.mjs [count=2000] [seed=random]
import { cpus } from 'node:os';
import { generateCases } from './cases.mjs';
import { realVariants, pool } from './real.mjs';
import { ipcalc } from '../src/ipcalc.js';

const count = Number(process.argv[2] ?? 2000);
const seed = Number(process.argv[3] ?? Math.floor(Math.random() * 2 ** 31));
console.log(`fuzz seed ${seed}, ${count} cases`);
let bad = 0;
await pool(generateCases(seed, count), cpus().length, async (argv) => {
  const real = await realVariants(argv);
  const got = ipcalc(argv);
  const ok = real.status === 'hang' ? got.status === 'hang'
    : got.status === real.status && real.outputs.includes(got.stdout);
  if (!ok && bad++ < 5) {
    const a = real.outputs[0].split('\n'), b = got.stdout.split('\n');
    let i = 0; while (i < a.length && a[i] === b[i]) i++;
    console.log(`MISMATCH ${JSON.stringify(argv)} real=${real.status} port=${got.status} line ${i + 1}\n  real: ${JSON.stringify(a.slice(i, i + 3))}\n  port: ${JSON.stringify(b.slice(i, i + 3))}`);
  }
});
console.log(bad ? `${bad} mismatches` : 'all match');
process.exit(bad ? 1 : 0);
