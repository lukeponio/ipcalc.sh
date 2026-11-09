// Runs the real Perl ipcalc 0.51 (needs `apt-get install ipcalc` or IPCALC=path).
// Output is captured through a pipe, exactly like `curl` users get it.
import { execFile } from 'node:child_process';

export const IPCALC = process.env.IPCALC || '/usr/bin/ipcalc';
const TIMEOUT_MS = 120000; // 1000-subnet listings take ~10s under bignum

export function runReal(argv, hashSeed) {
  const env = { PATH: process.env.PATH, TERM: 'xterm' };
  if (hashSeed !== undefined) Object.assign(env, { PERL_HASH_SEED: hashSeed, PERL_PERTURB_KEYS: '0' });
  return new Promise((resolve) => {
    execFile('perl', [IPCALC, ...argv], { env, encoding: 'latin1', timeout: TIMEOUT_MS, maxBuffer: 64 << 20 },
      (err, stdout) => {
        if (err && err.killed) return resolve({ stdout: '', status: 'hang' });
        resolve({ stdout, status: err ? err.code : 0 });
      });
  });
}

// Perl randomises hash order per process, which changes the "In Part ..."
// label for networks that contain several special blocks. Collect every
// variant seen across many seeds; any of them is a correct answer.
const SEEDS = Array.from({ length: 16 }, (_, i) => ((i * 2654435761) >>> 0).toString(16).padStart(8, '0'));

export async function realVariants(argv) {
  const first = await runReal(argv, SEEDS[0]);
  if (!first.stdout.includes('In Part')) return { status: first.status, outputs: [first.stdout] };
  const outs = new Set([first.stdout]);
  for (const s of SEEDS.slice(1)) outs.add((await runReal(argv, s)).stdout);
  return { status: first.status, outputs: [...outs].sort() };
}

export async function pool(items, n, fn) {
  const res = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: n }, async () => {
    while (next < items.length) { const i = next++; res[i] = await fn(items[i], i); }
  }));
  return res;
}
