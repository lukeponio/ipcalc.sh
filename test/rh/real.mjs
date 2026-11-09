// Runs the reference Red Hat ipcalc (build it with ./build-reference.sh).
// stdout is line-buffered and merged with stderr, which is what a terminal shows.
import { execFile } from 'node:child_process';

const DIR = process.env.IPCALC_RH_DIR || '/opt/ipcalc-rh';
const SIGNALS = { SIGABRT: 134, SIGSEGV: 139 };

export function runRealRh(argv) {
  // Run via PATH so argv[0] is "ipcalc", as in getopt's error messages on Fedora.
  const env = { PATH: `${DIR}:${process.env.PATH}`, LC_ALL: 'C' };
  return new Promise((resolve) => {
    execFile('sh', ['-c', 'exec stdbuf -oL ipcalc "$@" 2>&1', 'sh', ...argv],
      { env, encoding: 'latin1', timeout: 5000, maxBuffer: 4 << 20 },
      (err, stdout) => {
        if (err && (err.killed || err.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER')) return resolve({ stdout: '', status: 'hang' });
        resolve({ stdout, status: !err ? 0 : SIGNALS[err.signal] ?? err.code });
      });
  });
}
