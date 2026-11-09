// ipcalc.sh extras: URL forms that ipcalc 0.51 rejects today (it prints
// INVALID ...), so they never change baseline output. Each takes any mix of
// IPv4/IPv6 addresses, CIDRs, address+mask pairs and ranges.
//
//   /10.1.5.7/in/10.1.0.0/22        yes | no
//   /24/in/20  /24/in/10.0.0.0/20   how many /24s fit
//   /short/10.0.0.0/20              short summary with a Contains: line
//   /merge/... /exclude/... /overlap/... /expand/... /split/<cidr>/<n>
//   /acl/... /prefix-list/[NAME]/... /help
import { inet_pton4, inet_pton6, inet_ntop6 } from './ipcalc-rh.js';

const B = (n) => BigInt(n);
const toBig = (bytes) => bytes.reduce((n, b) => (n << 8n) | B(b), 0n);
const ones = (bits) => (1n << B(bits)) - 1n;

function addr(s) {
  let b = inet_pton4(s);
  if (b) return { v: 4, bits: 32, n: toBig(b) };
  b = s.includes(':') && inet_pton6(s);
  return b ? { v: 6, bits: 128, n: toBig(b) } : null;
}
const fmt = (v, n) => v === 4 ? [24n, 16n, 8n, 0n].map((s) => (n >> s) & 255n).join('.')
  : inet_ntop6(Uint8Array.from({ length: 16 }, (_, i) => Number((n >> B(8 * (15 - i))) & 255n)));

// Prefix length from "24", a dotted netmask or a dotted wildcard (IPv4).
// A dotted word after an address is read as its mask when it is one.
function prefix(a, w) {
  if (w == null) return null;
  if (/^\d{1,3}$/.test(w)) return +w <= a.bits ? +w : null;
  const m = a.v === 4 && addr(w);
  if (!m || m.v !== 4 || m.n === 0n) return null; // 0.0.0.0 stays an address
  for (const x of [m.n, ~m.n & ones(32)]) {
    const host = ~x & ones(32);
    if ((host & (host + 1n)) === 0n) return 32 - host.toString(2).replace(/^0$/, '').length;
  }
  return null;
}

const fail = (msg) => { throw new Error(msg); };

// Words to items { v, bits, lo, hi, n (address as typed), p (when a CIDR) }.
function items(words) {
  const out = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    const r = w.match(/^([^-]+)-([^-]+)$/);
    let a = addr(w), b;
    if (r && (a = addr(r[1])) && (b = addr(r[2]))) { /* a-b */ }
    else if (a && words[i + 1] === '-' && (b = addr(words[i + 2] || ''))) i += 2;
    if (b) {
      if (a.v !== b.v) fail(`mixed IPv4 and IPv6 range: ${fmt(a.v, a.n)} - ${fmt(b.v, b.n)}`);
      out.push({ v: a.v, bits: a.bits, lo: a.n < b.n ? a.n : b.n, hi: a.n < b.n ? b.n : a.n, n: a.n });
      continue;
    }
    if (!a) fail(`not an address, CIDR or range: ${w}`);
    let p = prefix(a, words[i + 1]);
    if (p == null) p = a.bits; else i++;
    const host = ones(a.bits - p), lo = a.n & ~host;
    out.push({ v: a.v, bits: a.bits, lo, hi: lo | host, n: a.n, p });
  }
  return out;
}

// Smallest exact CIDR cover of lo..hi.
function cidrs(v, lo, hi) {
  const bits = v === 4 ? 32 : 128, out = [];
  while (lo <= hi) {
    let s = 0;
    while (s < bits && (lo & ones(s + 1)) === 0n && lo + ones(s + 1) <= hi) s++;
    out.push({ v, lo, p: bits - s });
    lo += 1n << B(s);
  }
  return out;
}
const cidr = (c) => `${fmt(c.v, c.lo)}/${c.p}`;
const label = (x) => { const c = cidrs(x.v, x.lo, x.hi); return c.length === 1 ? cidr(c[0]) : `${fmt(x.v, x.lo)}-${fmt(x.v, x.hi)}`; };

// Union of intervals, per family, IPv4 first.
function union(list) {
  const out = [];
  for (const x of [...list].sort((a, b) => a.v - b.v || (a.lo < b.lo ? -1 : a.lo > b.lo ? 1 : 0))) {
    const t = out[out.length - 1];
    if (t && t.v === x.v && x.lo <= t.hi + 1n) { if (x.hi > t.hi) t.hi = x.hi; } else out.push({ ...x });
  }
  return out;
}
const toCidrs = (list) => list.flatMap((x) => cidrs(x.v, x.lo, x.hi));

function exclude(base, cut) {
  let rest = union(base);
  for (const c of union(cut)) {
    rest = rest.flatMap((x) => {
      if (x.v !== c.v || c.hi < x.lo || c.lo > x.hi) return [x];
      return [c.lo > x.lo && { ...x, hi: c.lo - 1n }, c.hi < x.hi && { ...x, lo: c.hi + 1n }].filter(Boolean);
    });
  }
  return rest;
}

const pow2 = (e) => 1n << B(e);
const plural = (n, w, pl = w + 's') => `${n} ${n === 1n ? w : pl}`;
const usable = (v, q) => v === 6 ? null : q >= 31 ? pow2(32 - q) : pow2(32 - q) - 2n;

// "how many /q in /p" with the backwards-question catch.
function howMany(q, p, v, where) {
  if (q < p) return `No /${q}s fit in a /${p}, because a /${q} is bigger. A /${q} holds ${plural(pow2(p - q), '/' + p)}.\n`;
  const u = usable(v, q), n = pow2(q - p);
  return `${where || 'A /' + p} holds ${plural(n, '/' + q)}, each with ${u == null ? plural(pow2(128 - q), 'address', 'addresses') : plural(u, 'usable host')}.\n`;
}

function inCheck(left, right) {
  const len = (w) => (/^\d{1,3}$/.test(w) && +w <= 128 ? +w : null);
  if (left.length === 1 && len(left[0]) != null) {
    const q = len(left[0]);
    if (right.length === 1 && len(right[0]) != null) {
      const p = len(right[0]), v = q > 32 || p > 32 ? 6 : 4;
      return { stdout: howMany(q, p, v), status: 0 };
    }
    const [y, ...more] = items(right);
    if (!y || more.length || y.p == null) fail('use /<prefix>/in/<prefix> or /<prefix>/in/<cidr>');
    if (q > y.bits) fail(`/${q} is longer than ${y.bits} bits`);
    return { stdout: howMany(q, y.p, y.v, cidr(y)), status: 0 };
  }
  const xs = items(left), ys = items(right);
  if (xs.length !== 1 || !ys.length) fail('use /<address or cidr>/in/<cidr>[/<cidr>...]');
  const x = xs[0], yes = ys.some((y) => y.v === x.v && y.lo <= x.lo && x.hi <= y.hi);
  return { stdout: yes ? 'yes\n' : 'no\n', status: yes ? 0 : 1 };
}

function short(x) {
  if (x.p == null) fail(`not a CIDR: ${label(x)}`);
  const { v, bits, p, lo, hi } = x, mask = ones(bits) & ~ones(bits - p);
  const pad = (k) => (k + ':').padEnd(11);
  const lines = [];
  if (x.n !== lo) lines.push(pad('Address') + fmt(v, x.n));
  lines.push(pad('Network') + `${fmt(v, lo)}/${p}`, pad('Netmask') + `${fmt(v, mask)} = ${p}`);
  if (v === 4) lines.push(pad('Wildcard') + fmt(4, ones(32 - p)));
  if (v === 4 && p < 31) lines.push(pad('Broadcast') + fmt(4, hi));
  const edge = v === 4 && p < 31 ? 1n : 0n;
  lines.push(pad('HostMin') + fmt(v, lo + edge), pad('HostMax') + fmt(v, hi - edge),
    pad('Hosts') + (usable(v, p) ?? pow2(128 - p)));
  const c = (v === 4 ? [16, 24, 26, 30] : [48, 56, 64]).filter((q) => q > p).slice(0, 3);
  if (c.length) lines.push(pad('Contains') + c.map((q) => `${pow2(q - p)} x /${q}`).join(', '));
  return lines.join('\n') + '\n';
}

const MAX_LINES = 65536;

const UTM = (where) => `?utm_source=ipcalc.sh&utm_medium=referral&utm_campaign=crosslink&utm_content=${where}`;
export const HELP = `ipcalc.sh extras (everything else is plain ipcalc 0.51; /ng/ is Red Hat ipcalc)

  curl ipcalc.sh/10.1.5.7/in/10.1.0.0/22        yes or no (exit header 0 or 1)
  curl ipcalc.sh/24/in/20                       how many /24s in a /20
  curl ipcalc.sh/24/in/10.0.0.0/20              ...in a given network
  curl ipcalc.sh/short/10.0.0.0/20              short summary with a Contains: line
  curl ipcalc.sh/merge/10.0.0.0/24/10.0.1.0/24  merge or summarize into fewest CIDRs
  curl ipcalc.sh/merge/10.0.0.5-10.0.0.200      range to CIDRs
  curl ipcalc.sh/exclude/10.0.0.0/16/10.0.5.0/24  first block minus the rest
  curl ipcalc.sh/overlap/10.0.0.0/23/10.0.1.0/24  list overlapping pairs
  curl ipcalc.sh/expand/192.168.1.0/29          every address, one per line
  curl ipcalc.sh/split/10.0.0.0/16/12           split into 12 equal subnets
  curl ipcalc.sh/acl/10.0.0.0/24/10.0.9.1       Cisco ACL wildcard lines
  curl ipcalc.sh/prefix-list/BRANCH/10.0.0.0/8  ip prefix-list lines

Every list takes IPv4 or IPv6 addresses, CIDRs, "address mask" pairs and
ranges (a-b). Separate words with /, + or commas.

Plan subnets and VLANs in a browser: https://subnetting.io/
Network diagrams: https://netdiagrams.com/${UTM('help')}
Segmentation audits: https://segaudit.com/${UTM('help')}
`;

const VERBS = {
  merge: (w) => toCidrs(union(items(w))).map(cidr),
  exclude: (w) => { const [base, ...cut] = items(w); if (!base) fail('use /exclude/<block>/<block to remove>...'); return toCidrs(exclude([base], cut)).map(cidr); },
  overlap: (w) => {
    const xs = items(w), out = [];
    xs.forEach((a, i) => xs.slice(i + 1).forEach((b) => {
      if (a.v === b.v && a.lo <= b.hi && b.lo <= a.hi) out.push(`${label(a)} overlaps ${label(b)}`);
    }));
    return { lines: out.length ? out : ['no overlap'], status: out.length ? 0 : 1 };
  },
  expand: (w) => {
    const xs = union(items(w)), total = xs.reduce((s, x) => s + x.hi - x.lo + 1n, 0n);
    if (total > B(MAX_LINES)) fail(`${total} addresses; expand stops at ${MAX_LINES}`);
    return xs.flatMap((x) => Array.from({ length: Number(x.hi - x.lo + 1n) }, (_, i) => fmt(x.v, x.lo + B(i))));
  },
  split: (w) => {
    const n = /^\d+$/.test(w[w.length - 1] ?? '') ? +w[w.length - 1] : 0, xs = items(w.slice(0, -1));
    if (xs.length !== 1 || xs[0].p == null || n < 1) fail('use /split/<cidr>/<number of subnets>');
    if (n > MAX_LINES) fail(`split stops at ${MAX_LINES} subnets`);
    const { v, bits, lo, p } = xs[0], q = p + Math.ceil(Math.log2(n));
    if (q > bits) fail(`a /${p} can't be split into ${n}: the subnets would be smaller than /${bits}`);
    return Array.from({ length: n }, (_, i) => cidr({ v, lo: lo + B(i) * pow2(bits - q), p: q }));
  },
  short: (w) => [items(w).map(short).join('\n').replace(/\n$/, '')],
  acl: (w) => toCidrs(union(items(w))).map((c) => {
    if (c.v !== 4) fail(`ACL wildcards are IPv4 only: ${cidr(c)}`);
    return c.p === 32 ? `permit host ${fmt(4, c.lo)}` : c.p === 0 ? 'permit any' : `permit ${fmt(4, c.lo)} ${fmt(4, ones(32 - c.p))}`;
  }),
  'prefix-list': (w) => {
    const name = w[0] && !addr(w[0]) && /^[A-Za-z][\w-]{0,62}$/.test(w[0]) ? w.shift() : 'SUBNETS';
    return toCidrs(items(w)).map((c, i) => `${c.v === 4 ? 'ip' : 'ipv6'} prefix-list ${name} seq ${5 * (i + 1)} permit ${cidr(c)}`);
  },
  help: () => [HELP.replace(/\n$/, '')],
};
const ALIAS = { aggregate: 'merge', summarize: 'merge', summarise: 'merge', subtract: 'exclude', overlaps: 'overlap', prefixlist: 'prefix-list' };

// Returns { stdout, status } for an extras URL, or null to let ipcalc handle it.
export function extras(argv) {
  const words = argv.flatMap((w) => w.split(',')).filter(Boolean);
  const verb = ALIAS[words[0]?.toLowerCase()] || words[0]?.toLowerCase();
  const at = words.findIndex((w, i) => i > 0 && w.toLowerCase() === 'in');
  if (!Object.hasOwn(VERBS, verb) && (at < 1 || words[0].startsWith('-'))) return null;
  try {
    if (!Object.hasOwn(VERBS, verb)) return inCheck(words.slice(0, at), words.slice(at + 1));
    const rest = words.slice(1);
    if (!rest.length && verb !== 'help') fail(`/${verb}/ needs at least one address; see curl ipcalc.sh/help`);
    const r = VERBS[verb](rest);
    const { lines, status = 0 } = Array.isArray(r) ? { lines: r } : r;
    return { stdout: lines.map((l) => l + '\n').join(''), status };
  } catch (e) {
    if (!(e instanceof Error) || e instanceof RangeError || e instanceof TypeError) throw e;
    return { stdout: `ipcalc.sh: ${e.message}\n`, status: 2 };
  }
}
