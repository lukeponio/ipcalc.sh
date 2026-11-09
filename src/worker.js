// Cloudflare Worker for ipcalc.sh.
//
//   curl ipcalc.sh/192.168.0.1/24        == ipcalc 192.168.0.1/24 | cat
//   curl ipcalc.sh/10.0.0.0/20/24        == ipcalc 10.0.0.0/20 24
//   curl ipcalc.sh/-b/10.0.0.0/8         == ipcalc -b 10.0.0.0/8
//   curl ipcalc.sh/10.0.0.1-10.0.0.77    == ipcalc 10.0.0.1-10.0.0.77
//   curl "ipcalc.sh/10.0.0.0/24+-s+10+20" (+ or %20 also separate words)
//
// Path segments become argv words. Splitting "a/b" into two words is exactly
// what ipcalc itself does with its arguments, so this mapping is lossless.
//   curl ipcalc.sh/ng/192.168.0.1/24     == Red Hat/Fedora ipcalc 192.168.0.1/24
//   curl ipcalc.sh/help                  extras (src/extras.js), only for input ipcalc rejects
import { ipcalc } from './ipcalc.js';
import { ipcalcRh } from './ipcalc-rh.js';
import { extras } from './extras.js';

const BROWSER = /Mozilla\//;
const CLI = /^(curl|Wget|HTTPie|xh|aria2|PowerShell|libcurl|Go-http-client|python-requests|Lynx|Links|w3m)\b/i;

// Percent-decode to raw bytes (one char per byte), like argv on Linux.
const bytes = (s) => s.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));

// Every valid ipcalc input is printable ASCII. Anything else can only end up
// echoed in an "INVALID ..." line, so replace it to stop terminal escape
// injection via a crafted link (deliberate deviation from the CLI).
export function pathToArgv(pathname) {
  return bytes(pathname.replace(/\+/g, ' ')).split(/[\/\s]+/).filter(Boolean)
    .map((w) => w.replace(/[^\x20-\x7e]/g, '?'));
}

// Red Hat ipcalc needs "addr/prefix" as one word (an IPv6 "addr prefix" pair is
// an error there), so glue a prefix back onto the address it followed.
const ARG_LONG = ['split', 'random-private', 'deaggregate', 'lookup-host'];
const takesArg = (w) => /^-[^-]*[Srdo]$/.test(w) || (/^--[a-z-]+$/.test(w) && ARG_LONG.some((n) => n.startsWith(w.slice(2))));
export function pathToArgvRh(pathname) {
  const argv = [];
  for (const w of pathToArgv(pathname)) {
    const p = argv[argv.length - 1];
    const isValue = argv.length > 1 && takesArg(argv[argv.length - 2]);
    if (p && !w.startsWith('-') && !p.startsWith('-') && !p.includes('/') && /[.:]/.test(p) && !isValue) argv[argv.length - 1] = `${p}/${w}`;
    else argv.push(w);
  }
  return argv;
}

// Real inputs are under 100 bytes; this bounds CPU (e.g. thousands of -s sizes).
export const MAX_PATH = 1024;

export function textResponse(pathname, method = 'GET') {
  const rh = pathname === '/ng' || pathname.startsWith('/ng/');
  const argv = rh ? pathToArgvRh(pathname.slice(3)) : pathToArgv(pathname);
  let { stdout, status } = rh ? ipcalcRh(argv) : extras(argv) ?? ipcalc(argv);
  if (status === 'truncated') stdout += '\n[ipcalc.sh: output truncated at 1 MiB]\n';
  const random = rh && argv.some((a) => /^-[^-]*r|^--r/.test(a)); // --random-private
  const body = Uint8Array.from(stdout, (c) => c.charCodeAt(0));
  return new Response(method === 'HEAD' ? null : body, {
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': random ? 'no-store' : 'public, max-age=86400',
      'x-ipcalc-exit': String(status),
      'x-content-type-options': 'nosniff',
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method Not Allowed\n', { status: 405, headers: { allow: 'GET, HEAD' } });
    }
    if (url.pathname.length > MAX_PATH) {
      return new Response('Request too long\n', { status: 414, headers: { 'content-type': 'text/plain; charset=utf-8' } });
    }
    const ua = request.headers.get('user-agent') || '';
    if (BROWSER.test(ua) && !CLI.test(ua) && url.pathname !== '/robots.txt') {
      const raw = url.pathname.slice(1).replace(/\+/g, ' ');
      let q;
      try { q = decodeURIComponent(raw); } catch { q = raw; }
      const target = new URL(env.BROWSER_REDIRECT || 'https://subnetting.io/');
      if (q) target.searchParams.set('q', q);
      return Response.redirect(target.toString(), 302);
    }
    return textResponse(url.pathname, request.method);
  },
};
