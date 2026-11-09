// Faithful JavaScript port of Red Hat ipcalc 1.0.3 (gitlab.com/ipcalc/ipcalc,
// the `ipcalc` on Fedora/RHEL/CentOS; Debian renames it ipcalc-ng).
// Copyright (c) 1997-2015 Red Hat, Inc. and contributors, GPL-2.0.
//
// Goal: the bytes a terminal shows for `ipcalc <args>` (stdout line-buffered,
// stderr unbuffered), reference build = upstream 1.0.3 with GeoIP support but
// no GeoLite2 databases installed (a stock Fedora box).
// Web-only differences: DNS options (-h, -o) are refused, output is capped.

import { RH_USAGE_LONG, RH_USAGE_SHORT } from './rh-texts.js';

const VERSION = '1.0.3';
const PROG = 'ipcalc';
const MAX_OUT = 1 << 20; // shortcut: 1 MiB cap on output (e.g. -S 32 0.0.0.0/0 is 4 billion lines)

const F = {
  IPV6: 1 << 1, IPV4: 1 << 2, SHOW_MODERN_INFO: 1 << 3, RESOLVE_IP: 1 << 4, RESOLVE_HOST: 1 << 5,
  SHOW_BROADCAST: 1 << 6, SHOW_NETMASK: 1 << 7, SHOW_NETWORK: 1 << 8, SHOW_PREFIX: 1 << 9,
  SHOW_MINADDR: 1 << 10, SHOW_MAXADDR: 1 << 11, SHOW_ADDRESSES: 1 << 12, SHOW_ADDRSPACE: 1 << 13,
  GET_GEOIP: 1 << 14, SHOW_ALL_INFO: 1 << 16, SHOW_REVERSE: 1 << 17, ASSUME_CLASS_PREFIX: 1 << 18,
  NO_DECORATE: 1 << 20, SHOW_ADDRESS: 1 << 21, JSON: 1 << 22, RANDOM: 1 << 23,
};
F.SHOW_GEOIP = (1 << 15) | F.GET_GEOIP;
const FLAGS_TO_IGNORE = F.IPV6 | F.IPV4 | F.GET_GEOIP | F.NO_DECORATE | F.JSON | F.ASSUME_CLASS_PREFIX | (1 << 16) | F.RANDOM;
const ENV_INFO_FLAGS = F.SHOW_NETMASK | F.SHOW_BROADCAST | F.RESOLVE_IP | F.RESOLVE_HOST | F.SHOW_ADDRESS |
  F.SHOW_REVERSE | F.SHOW_GEOIP | F.SHOW_ADDRSPACE | F.SHOW_ADDRESSES | F.SHOW_MAXADDR | F.SHOW_MINADDR |
  F.SHOW_PREFIX | F.SHOW_NETWORK;
const APP = { VERSION: 1, CHECK: 2, SHOW_INFO: 4, SPLIT: 8, DEAGGREGATE: 16 };
const JSON_FIRST = 0, JSON_NEXT = 1, JSON_ARRAY_FIRST = 2, JSON_ARRAY_NEXT = 3;

const LONG_OPTIONS = [
  ['check', 0, 'c'], ['random-private', 1, 'r'], ['split', 1, 'S'], ['deaggregate', 1, 'd'],
  ['info', 0, 'i'], ['all-info', 0, 'ALLINFO'], ['ipv4', 0, '4'], ['ipv6', 0, '6'], ['address', 0, 'a'],
  ['broadcast', 0, 'b'], ['hostname', 0, 'h'], ['lookup-host', 1, 'o'], ['reverse-dns', 0, 'REVERSE'],
  ['geoinfo', 0, 'g'], ['netmask', 0, 'm'], ['network', 0, 'n'], ['prefix', 0, 'p'],
  ['class-prefix', 0, 'CLASS_PREFIX'], ['minaddr', 0, 'MINADDR'], ['maxaddr', 0, 'MAXADDR'],
  ['addresses', 0, 'ADDRESSES'], ['addrspace', 0, 'ADDRSPACE'], ['silent', 0, 's'],
  ['no-decorate', 0, 'NO_DECORATE'], ['json', 0, 'j'], ['version', 0, 'v'], ['help', 0, '?'], ['usage', 0, 'USAGE'],
];
const SHORT_OPTS = 'S:cr:i46abho:gmnpjsvd:';

class Exit extends Error { constructor(code) { super('exit'); this.code = code; } }
class Crash extends Error { constructor(code) { super('crash'); this.code = code; } }
class Hang extends Error {}
class Truncated extends Error {}

// ---- glibc address parsing/printing ----------------------------------------
export function inet_pton4(s) {
  let saw_digit = 0, octets = 0;
  const tmp = [0, 0, 0, 0];
  let tp = 0;
  for (const ch of s) {
    if (ch >= '0' && ch <= '9') {
      const n = tmp[tp] * 10 + (ch.charCodeAt(0) - 48);
      if (saw_digit && tmp[tp] === 0) return null;
      if (n > 255) return null;
      tmp[tp] = n;
      if (!saw_digit) { if (++octets > 4) return null; saw_digit = 1; }
    } else if (ch === '.' && saw_digit) {
      if (octets === 4) return null;
      tmp[++tp] = 0;
      saw_digit = 0;
    } else return null;
  }
  if (octets < 4) return null;
  return tmp;
}
const pton4u = (s) => { const b = inet_pton4(s); return b ? ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0 : null; };
const ntop4 = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');

export function inet_pton6(src) {
  const tmp = new Uint8Array(16);
  let tp = 0, colonp = -1, i = 0;
  if (src.length === 0) return null;
  if (src[0] === ':') { i++; if (i === src.length || src[i] !== ':') return null; }
  let curtok = i, xdigits = 0, val = 0;
  while (i < src.length) {
    const ch = src[i++];
    const d = /[0-9a-fA-F]/.test(ch) ? parseInt(ch, 16) : -1;
    if (d >= 0) {
      if (xdigits === 4) return null;
      val = (val << 4) | d;
      if (val > 0xffff) return null;
      xdigits++;
      continue;
    }
    if (ch === ':') {
      curtok = i;
      if (xdigits === 0) {
        if (colonp >= 0) return null;
        colonp = tp;
        continue;
      } else if (i === src.length) return null;
      if (tp + 2 > 16) return null;
      tmp[tp++] = (val >> 8) & 255;
      tmp[tp++] = val & 255;
      xdigits = 0; val = 0;
      continue;
    }
    if (ch === '.' && tp + 4 <= 16) {
      const v4 = inet_pton4(src.slice(curtok));
      if (v4) { tmp.set(v4, tp); tp += 4; xdigits = 0; break; }
    }
    return null;
  }
  if (xdigits > 0) {
    if (tp + 2 > 16) return null;
    tmp[tp++] = (val >> 8) & 255;
    tmp[tp++] = val & 255;
  }
  if (colonp >= 0) {
    if (tp === 16) return null;
    const n = tp - colonp;
    const moved = tmp.slice(colonp, tp);
    tmp.fill(0, colonp, 16);
    tmp.set(moved, 16 - n);
    tp = 16;
  }
  if (tp !== 16) return null;
  return tmp;
}

export function inet_ntop6(a) {
  const w = [];
  for (let i = 0; i < 16; i += 2) w.push((a[i] << 8) | a[i + 1]);
  let best = { base: -1, len: 0 }, cur = { base: -1, len: 0 };
  for (let i = 0; i < 8; i++) {
    if (w[i] === 0) {
      if (cur.base === -1) cur = { base: i, len: 1 }; else cur.len++;
    } else if (cur.base !== -1) {
      if (best.base === -1 || cur.len > best.len) best = cur;
      cur = { base: -1, len: 0 };
    }
  }
  if (cur.base !== -1 && (best.base === -1 || cur.len > best.len)) best = cur;
  if (best.base !== -1 && best.len < 2) best = { base: -1, len: 0 };
  let s = '';
  for (let i = 0; i < 8; i++) {
    if (best.base !== -1 && i >= best.base && i < best.base + best.len) {
      if (i === best.base) s += ':';
      continue;
    }
    if (i !== 0) s += ':';
    if (i === 6 && best.base === 0 && (best.len === 6 || (best.len === 5 && w[5] === 0xffff))) {
      s += ntop4(((a[12] << 24) | (a[13] << 16) | (a[14] << 8) | a[15]) >>> 0);
      return s;
    }
    s += w[i].toString(16);
  }
  if (best.base !== -1 && best.base + best.len === 8) s += ':';
  return s;
}

// strtol(s, &end, 0) + int range check, as safe_atoi(). Returns null on error.
function safe_atoi(s) {
  const m = /^[ \t\n\v\f\r]*([+-]?)(0[xX](?=[0-9a-fA-F])[0-9a-fA-F]*|0[0-7]*|[1-9][0-9]*)/.exec(s);
  if (!m || m[0].length !== s.length) return null;
  const neg = m[1] === '-';
  const digits = m[2];
  let v = /^0[xX]/.test(digits) ? BigInt(digits) : digits.length > 1 && digits[0] === '0' ? BigInt('0o' + digits.slice(1)) : BigInt(digits);
  if (neg) v = -v;
  if (v > 2n ** 63n - 1n || v < -(2n ** 63n)) return null; // ERANGE
  if (v > 2147483647n || v < -2147483648n) return null;
  return Number(v);
}

function mask2prefix(mask) {
  let c = 0, seen_one = 0, i = mask >>> 0;
  while (i > 0) {
    if (i & 1) { seen_one = 1; c++; } else if (seen_one) return -1;
    i >>>= 1;
  }
  return c;
}
const ipv4_mask_to_int = (s) => { const n = pton4u(s); return n === null ? -1 : mask2prefix(n); };
const prefix2mask = (p) => (p ? (~((2 ** (32 - p)) - 1)) >>> 0 : 0);
const p2 = (pow) => (pow <= 127 ? String(2n ** BigInt(pow)) : '');

function ipv4_net_to_type(n) {
  const b1 = n >>> 24, b2 = (n >>> 16) & 255, b3 = (n >>> 8) & 255, b4 = n & 255;
  if (b1 === 0) return 'This host on this network';
  if (b1 === 10) return 'Private Use';
  if (b1 === 100 && (b2 & 0xc0) === 64) return 'Shared Address Space';
  if (b1 === 127) return 'Loopback';
  if (b1 === 169 && b2 === 254) return 'Link Local';
  if (b1 === 172 && (b2 & 0xf0) === 16) return 'Private Use';
  if (b1 === 192 && b2 === 0 && b3 === 0 && b4 <= 7) return 'IPv4 Service Continuity Prefix';
  if (b1 === 192 && b2 === 0 && b3 === 0 && b4 === 8) return 'IPv4 dummy address';
  if (b1 === 192 && b2 === 0 && b3 === 0 && b4 === 9) return 'Port Control Protocol Anycast';
  if (b1 === 192 && b2 === 0 && b3 === 0 && b4 === 10) return 'Traversal Using Relays around NAT Anycast';
  if (b1 === 192 && b2 === 0 && b3 === 0 && (b4 === 170 || b4 === 171)) return 'NAT64/DNS64 Discovery';
  if (b1 === 192 && b2 === 0 && b3 === 0) return 'IETF Protocol Assignments';
  if (b1 === 192 && b2 === 0 && b3 === 2) return 'Documentation (TEST-NET-1)';
  if (b1 === 198 && b2 === 51 && b3 === 100) return 'Documentation (TEST-NET-2)';
  if (b1 === 203 && b2 === 0 && b3 === 113) return 'Documentation (TEST-NET-3)';
  if (b1 === 192 && b2 === 88 && b3 === 99) return '6 to 4 Relay Anycast (Deprecated)';
  if (b1 === 192 && b2 === 31 && b3 === 196) return 'AS112-v4';
  if (b1 === 192 && b2 === 52 && b3 === 193) return 'AMT';
  if (b1 === 192 && b2 === 168) return 'Private Use';
  if (b1 === 192 && b2 === 175 && b3 === 48) return 'Direct Delegation AS112 Service';
  if (b1 === 255 && b2 === 255 && b3 === 255 && b4 === 255) return 'Limited Broadcast';
  if (b1 === 198 && (b2 & 0xfe) === 18) return 'Benchmarking';
  if (b1 >= 224 && b1 <= 239) return 'Multicast';
  if ((b1 & 0xf0) === 240) return 'Reserved';
  return 'Internet';
}
function ipv4_net_to_class(n) {
  const b1 = n >>> 24;
  if (b1 < 128) return 'Class A';
  if (b1 < 192) return 'Class B';
  if (b1 < 224) return 'Class C';
  if (b1 < 239) return 'Class D';
  return 'Class E';
}
const default_ipv4_prefix = (n) => { const b1 = n >>> 24; return b1 < 128 ? 8 : b1 < 192 ? 16 : 24; };
// (1 << 32) on x86 is 1 << 0, so /0 reports 4294967295 hosts.
const ipv4_prefix_to_hosts = (p) => (p >= 31 ? p2(32 - p) : String(((p === 0 ? 1 : 2 ** (32 - p)) - 2) >>> 0));

const startsWith = (a, bytes) => bytes.every((b, i) => a[i] === b);
function ipv6_net_to_type(a, prefix) {
  const w1 = (a[0] << 8) | a[1], w2 = (a[2] << 8) | a[3];
  const z = Array(16).fill(0);
  if (prefix === 128 && startsWith(a, [...z.slice(0, 15), 1])) return 'Loopback Address';
  if (prefix === 128 && startsWith(a, z)) return 'Unspecified Address';
  if (prefix >= 96 && startsWith(a, [...z.slice(0, 10), 0xff, 0xff])) return 'IPv4-mapped Address';
  if (prefix >= 96 && startsWith(a, [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0])) return 'IPv4-IPv6 Translat.';
  if (prefix >= 48 && startsWith(a, [0, 0x64, 0xff, 0x9b, 0, 1])) return 'IPv4-IPv6 Translat.';
  if (prefix >= 96 && startsWith(a, [0x10, ...z.slice(0, 11)])) return 'Discard-Only Address Block';
  if (prefix >= 32 && w1 === 0x2001 && w2 === 0) return 'TEREDO';
  if (prefix === 128 && startsWith(a, [0x20, 1, 0, 1, ...z.slice(0, 11), 1])) return 'Port Control Protocol Anycast';
  if (prefix === 128 && startsWith(a, [0x20, 1, 0, 1, ...z.slice(0, 11), 2])) return 'Traversal Using Relays around NAT Anycast';
  if (prefix >= 48 && startsWith(a, [0x20, 1, 0, 2, 0, 0])) return 'Benchmarking';
  if (prefix >= 32 && w1 === 0x2001 && w2 === 0x3) return 'AMT';
  if (prefix >= 48 && startsWith(a, [0x20, 1, 0, 4, 1, 0x12])) return 'AS112-v6';
  if (prefix >= 28 && w1 === 0x2001 && (w2 & 0xfff0) === 0x10) return 'Deprecated (previously ORCHID)';
  if (prefix >= 28 && w1 === 0x2001 && (w2 & 0xfff0) === 0x20) return 'ORCHIDv2';
  if (prefix >= 23 && w1 === 0x2001 && (w2 & 0xff00) <= 0x100) return 'IETF Protocol Assignments';
  if (prefix >= 32 && w1 === 0x2001 && w2 === 0xdb8) return 'Documentation';
  if (w1 === 0x2002) return '6to4';
  if (prefix >= 48 && startsWith(a, [0x26, 0x20, 0, 0x4f, 0x80, 0])) return 'Direct Delegation AS112 Service';
  if ((w1 & 0xe000) === 0x2000) return 'Global Unicast';
  if ((a[0] & 0xfe) === 0xfc) return 'Unique Local Unicast';
  if ((w1 & 0xffc0) === 0xfe80) return 'Link-Scoped Unicast';
  if (a[0] === 0xff) return 'Multicast';
  return 'Reserved';
}

function ipv6_prefix_to_mask(prefix) {
  const m = new Uint8Array(16);
  for (let i = prefix, j = 0; i > 0; i -= 8, j++) m[j] = i >= 8 ? 0xff : (0xff << (8 - i)) & 0xff;
  return m;
}
const expand_ipv6 = (a) => Array.from({ length: 8 }, (_, i) => a[2 * i].toString(16).padStart(2, '0') + a[2 * i + 1].toString(16).padStart(2, '0')).join(':');

function calc_reverse_dns4(ip, prefix, net, bcast) {
  const b1 = ip >>> 24, b2 = (ip >>> 16) & 255, b3 = (ip >>> 8) & 255, b4 = ip & 255;
  if (prefix === 32) return `${b4}.${b3}.${b2}.${b1}.in-addr.arpa.`;
  if (prefix === 24) return `${b3}.${b2}.${b1}.in-addr.arpa.`;
  if (prefix === 16) return `${b2}.${b1}.in-addr.arpa.`;
  if (prefix === 8) return `${b1}.in-addr.arpa.`;
  if (prefix > 24) return `${net & 255}-${bcast & 255}.${b3}.${b2}.${b1}.in-addr.arpa.`;
  if (prefix > 16) return `${(net >>> 8) & 255}-${(bcast >>> 8) & 255}.${b2}.${b1}.in-addr.arpa.`;
  if (prefix > 8) return `${(net >>> 16) & 255}-${(bcast >>> 16) & 255}.${b1}.in-addr.arpa.`;
  return null;
}
function calc_reverse_dns6(a, prefix) {
  if (prefix % 4 !== 0) return null;
  const max = Math.floor(prefix / 8);
  let s = '';
  if (prefix % 8 === 4) s += (a[(prefix + 4) / 8 - 1] >> 4).toString(16) + '.';
  for (let i = 0; i < max; i++) s += (a[max - 1 - i] & 0xf).toString(16) + '.' + (a[max - 1 - i] >> 4).toString(16) + '.';
  return s + 'ip6.arpa.';
}

// ---- IPv6 helpers (ipv6.c) --------------------------------------------------
function ipv6_add(a, b) {
  let cy = 0;
  for (let i = 15; i >= 0; i--) { const r = a[i] + b[i] + cy; a[i] = r & 255; cy = r >> 8; }
}
function ipv6_or1(a, bit) {
  if (!(bit < 128)) throw new AssertFail("ipv6.c:47: ipv6_or1: Assertion `bit < 128' failed.");
  a[15 - Math.floor(bit / 8)] |= 1 << (bit % 8);
}
function ipv6_orm(a, bits) {
  if (!(bits < 128)) throw new AssertFail("ipv6.c:63: ipv6_orm: Assertion `bits < 128' failed.");
  const bytes = Math.floor(bits / 8);
  for (let i = 0; i < bytes; i++) a[15 - i] |= 0xff;
  for (let i = bytes * 8; i < bits; i++) ipv6_or1(a, i);
}
function ipv6_cmp(a, b) {
  for (let i = 0; i < 16; i++) if (a[i] !== b[i]) return a[i] > b[i] ? 1 : -1;
  return 0;
}
class AssertFail extends Error {}

// ---- getopt_long (glibc, permuting) -----------------------------------------
function getopt_long(argv) {
  const opts = [], nonopts = [];
  let i = 0;
  const needArg = (c) => SHORT_OPTS.includes(c + ':');
  while (i < argv.length) {
    const a = argv[i++];
    if (a === '--') { nonopts.push(...argv.slice(i)); break; }
    if (a.startsWith('--')) {
      const body = a.slice(2), eq = body.indexOf('=');
      const name = eq >= 0 ? body.slice(0, eq) : body;
      let found = LONG_OPTIONS.find((o) => o[0] === name);
      if (!found) {
        const cands = LONG_OPTIONS.filter((o) => o[0].startsWith(name));
        if (cands.length > 1) {
          const msg = `${PROG}: option '--${body}' is ambiguous; possibilities:` + cands.map((o) => ` '--${o[0]}'`).join('') + '\n';
          opts.push(['?', undefined, msg]); return { opts, nonopts, stop: true };
        }
        found = cands[0];
      }
      if (!found) { opts.push(['?', undefined, `${PROG}: unrecognized option '--${body}'\n`]); return { opts, nonopts, stop: true }; }
      const [lname, hasArg, val] = found;
      if (eq >= 0) {
        if (!hasArg) { opts.push(['?', undefined, `${PROG}: option '--${lname}' doesn't allow an argument\n`]); return { opts, nonopts, stop: true }; }
        opts.push([val, body.slice(eq + 1)]);
      } else if (hasArg) {
        if (i >= argv.length) { opts.push(['?', undefined, `${PROG}: option '--${lname}' requires an argument\n`]); return { opts, nonopts, stop: true }; }
        opts.push([val, argv[i++]]);
      } else opts.push([val]);
      continue;
    }
    if (a.startsWith('-') && a.length > 1) {
      for (let j = 1; j < a.length; j++) {
        const c = a[j];
        if (c === ':' || c === ';' || !SHORT_OPTS.includes(c)) {
          opts.push(['?', undefined, `${PROG}: invalid option -- '${c}'\n`]); return { opts, nonopts, stop: true };
        }
        if (needArg(c)) {
          if (j + 1 < a.length) opts.push([c, a.slice(j + 1)]);
          else if (i < argv.length) opts.push([c, argv[i++]]);
          else { opts.push(['?', undefined, `${PROG}: option requires an argument -- '${c}'\n`]); return { opts, nonopts, stop: true }; }
          break;
        }
        opts.push([c]);
      }
      continue;
    }
    nonopts.push(a);
  }
  return { opts, nonopts };
}

export function ipcalcRh(argv, { random = (n) => crypto.getRandomValues(new Uint8Array(n)) } = {}) {
  let out = '', pending = '';
  const emit = (s) => {
    out += s;
    if (out.length > MAX_OUT) throw new Truncated();
  };
  const stdout = (s) => {
    pending += s;
    const k = pending.lastIndexOf('\n');
    if (k >= 0) { emit(pending.slice(0, k + 1)); pending = pending.slice(k + 1); }
  };
  const stderr = (s) => emit(s);

  let flags = 0, beSilent = 0;
  const warn = (s) => { if (!beSilent) stderr(s); };
  const usage = (verbose) => stderr(verbose ? RH_USAGE_LONG : RH_USAGE_SHORT);
  const exit = (code) => { throw new Exit(code); };

  // ---- output helpers (ipcalc.c) ----
  const output_start = (jc) => { if (flags & F.JSON) stdout('{\n'); jc.v = JSON_FIRST; };
  const output_separate = () => { if (!(flags & F.JSON)) stdout('\n'); };
  const output_stop = () => { if (flags & F.JSON) stdout('\n}\n'); };
  const array_start = (jc, head, json_head) => {
    if (flags & F.JSON) {
      if (jc.v === JSON_NEXT) stdout(',\n  ');
      stdout(`  "${json_head}":[\n  `);
    } else if (!(flags & F.NO_DECORATE)) stdout(`[${head}]\n`);
    jc.v = JSON_ARRAY_FIRST;
  };
  const array_stop = (jc) => { if (flags & F.JSON) { stdout(']'); jc.v = JSON_NEXT; } };
  const json_printf = (jc, title, str) => {
    if (jc.v === JSON_ARRAY_NEXT) stdout(',\n  ');
    else if (jc.v === JSON_NEXT) stdout(',\n');
    stdout('  ' + (title ? `"${title}":"${str}"` : `"${str}"`));
    if (jc.v === JSON_FIRST) jc.v = JSON_NEXT;
    else if (jc.v === JSON_ARRAY_FIRST) jc.v = JSON_ARRAY_NEXT;
  };
  // colors are only used on a tty; ipcalc.sh never is one.
  const pretty_printf = (jc, title, jtitle, str) => {
    if (flags & F.JSON) json_printf(jc, jtitle, str);
    else stdout(title + str + '\n');
  };
  const default_printf = (jc, title, jtitle, str) => {
    if (flags & F.JSON) json_printf(jc, jtitle, str);
    else if (flags & F.NO_DECORATE) stdout(str + '\n');
    else stdout(title + str + '\n');
  };

  // ---- info ----
  function get_ipv4_info(ipStr, prefix) {
    const info = {};
    const ip = pton4u(ipStr);
    if (ip === null) { warn(`${PROG}: bad IPv4 address: ${ipStr}\n`); return null; }
    if (prefix < 0) prefix = flags & F.ASSUME_CLASS_PREFIX ? default_ipv4_prefix(ip) : 32;
    if (prefix > 32) { warn(`${PROG}: bad IPv4 prefix ${prefix}\n`); return null; }
    info.ip = ntop4(ip);
    const mask = prefix2mask(prefix);
    info.netmask = ntop4(mask);
    info.prefix = prefix;
    const broadcast = prefix === 31 ? 0xffffffff : ((ip & mask) | ~mask) >>> 0;
    info.broadcast = ntop4(broadcast);
    const network = (ip & mask) >>> 0;
    info.reverse_dns = calc_reverse_dns4(network, prefix, network, broadcast);
    info.network = ntop4(network);
    info.type = ipv4_net_to_type(network);
    info.class = ipv4_net_to_class(network);
    if (prefix < 32) {
      info.hostmin = ntop4(prefix <= 30 ? (network | 1) >>> 0 : network);
      let max = (network | ~mask) >>> 0;
      if (prefix <= 30) max = (max - 1) >>> 0;
      info.hostmax = ntop4(max);
    } else info.hostmin = info.hostmax = info.network;
    info.hosts = ipv4_prefix_to_hosts(prefix);
    if (flags & F.RESOLVE_HOST) noDns();
    return info;
  }

  function get_ipv6_info(ipStr, prefix) {
    const info = {};
    const ip6 = inet_pton6(ipStr);
    if (!ip6) { warn(`${PROG}: bad IPv6 address: ${ipStr}\n`); return null; }
    info.expanded_ip = expand_ipv6(ip6);
    info.ip = inet_ntop6(ip6);
    if (prefix > 128) { warn(`${PROG}: bad IPv6 prefix: ${prefix}\n`); return null; }
    if (prefix < 0) prefix = 128;
    info.prefix = prefix;
    const mask = ipv6_prefix_to_mask(prefix);
    info.netmask = inet_ntop6(mask);
    const net = ip6.map((b, i) => b & mask[i]);
    info.network = inet_ntop6(net);
    info.expanded_network = expand_ipv6(net);
    info.type = ipv6_net_to_type(net, prefix);
    info.reverse_dns = calc_reverse_dns6(net, prefix);
    if (prefix < 128) {
      info.hostmin = info.network;
      info.hostmax = inet_ntop6(net.map((b, i) => (b | ~mask[i]) & 255));
    } else info.hostmin = info.hostmax = info.network;
    info.hosts = p2(128 - prefix);
    if (flags & F.RESOLVE_HOST) noDns();
    return info;
  }

  // ipcalc.sh cannot do DNS from here; refuse instead of inventing an answer.
  const noDns = () => { stderr(`${PROG}: DNS lookups (-h, -o) are not available on ipcalc.sh\n`); exit(1); };

  function str_to_prefix(s, fix) {
    let prefix;
    if (!(flags & F.IPV6) && s.includes('.')) prefix = ipv4_mask_to_int(s);
    else { prefix = safe_atoi(s); if (prefix === null) return -1; }
    if (fix && prefix > 32 && !(flags & F.IPV6)) flags |= F.IPV6;
    if (prefix < 0 || ((flags & F.IPV6) && prefix > 128) || (!(flags & F.IPV6) && prefix > 32)) return -1;
    return prefix;
  }

  function generate_ip_network(prefix) {
    if (flags & F.IPV6) {
      const net = new Uint8Array(16);
      net[0] = 0xfd;
      net.set(random(15), 1);
      return `${inet_ntop6(net)}/${prefix}`;
    }
    const bytes = random(5); // bytes[4] stands in for the clock_gettime() nanoseconds
    const c = bytes[4] % 4;
    const b = [...bytes.slice(0, 4)];
    if (prefix >= 16 && c < 2) {
      if (c === 1) { b[0] = 192; b[1] = 168; } else { b[0] = 172; b[1] = 16 | ((bytes[4] >> 4) & 0x0f); }
    } else b[0] = 10;
    return `${b.join('.')}/${prefix}`;
  }

  // ---- split (netsplit.c) ----
  function split_v4(split_prefix, info) {
    const jc = { v: JSON_FIRST };
    const splitmask = prefix2mask(split_prefix), nmask = prefix2mask(info.prefix);
    if (splitmask < nmask) {
      warn(`Cannot subnet to /${split_prefix} with this base network, use a prefix > /${info.prefix}\n`);
      exit(1);
    }
    output_start(jc);
    array_start(jc, 'Split networks', 'SPLITNETWORK');
    const net = pton4u(info.network);
    let broadcast = pton4u(info.broadcast);
    const diff = (0xffffffff - splitmask + 1) >>> 0;
    let start = net, end = (net + diff - 1) >>> 0, count = 0;
    if (info.prefix === 31) broadcast = (start + 1) >>> 0;
    for (;;) {
      if (!(flags & F.NO_DECORATE) || (flags & F.JSON)) default_printf(jc, 'Network:\t', null, `${ntop4(start)}/${split_prefix}`);
      else stdout(`${ntop4(start)}/${split_prefix}\n`);
      count = (count + 1) >>> 0;
      start = (start + diff) >>> 0;
      if (end === 0xffffffff || end >= broadcast) break;
      end = (end + diff) >>> 0;
    }
    array_stop(jc);
    if (!(flags & F.NO_DECORATE) || (flags & F.JSON)) {
      default_printf(jc, '\nTotal:  \t', 'NETS', String(count));
      default_printf(jc, 'Hosts/Net:\t', 'ADDRESSES', ipv4_prefix_to_hosts(split_prefix));
    }
    output_stop(jc);
  }

  function split_v6(split_prefix, info) {
    const jc = { v: JSON_FIRST };
    const net = inet_pton6(info.network);
    if (!net) { warn(`${PROG}: bad IPv6 address: ${info.network}\n`); exit(1); }
    const netlast = inet_pton6(info.hostmax);
    if (!netlast) { warn(`${PROG}: bad IPv6 address: ${info.hostmax}\n`); exit(1); }
    const netmask = inet_pton6(info.netmask);
    if (!netmask) { warn(`${PROG}: bad IPv6 mask: ${info.netmask}\n`); exit(1); }
    const splitmask = ipv6_prefix_to_mask(split_prefix);
    let i = 0, j = 0;
    do {
      if (splitmask[i] > netmask[i]) j = 1;
      if (netmask[i] > splitmask[i]) j = 2;
      i++;
    } while (i < 16 && !j);
    if (j === 2) {
      warn(`Cannot subnet to /${split_prefix} with this base network, use a prefix > /${info.prefix}\n`);
      exit(1);
    }
    const sdiff = new Uint8Array(16), end = new Uint8Array(16);
    for (let k = 0; k < 16; k++) { sdiff[k] = 0xff - splitmask[k]; end[k] = net[k] + sdiff[k]; }
    const start = Uint8Array.from(net), ediff = Uint8Array.from(sdiff);
    const one = new Uint8Array(16); one[15] = 1;
    ipv6_add(sdiff, one);
    output_start(jc);
    array_start(jc, 'Split networks', 'SPLITNETWORK');
    let done = 0, count = 0;
    while (!done) {
      if (!(flags & F.NO_DECORATE) || (flags & F.JSON)) default_printf(jc, 'Network:\t', null, `${inet_ntop6(start)}/${split_prefix}`);
      else stdout(`${inet_ntop6(start)}/${split_prefix}\n`);
      ipv6_add(start, sdiff);
      j = 0;
      for (let k = 0; k < 16; k += 2) if (end[k] !== 0xff && end[k + 1] !== 0xff) j = 1;
      if (!j) done = 1;
      j = 0;
      let k = 0;
      do {
        if (end[k] > netlast[k]) j = 1;
        if (netlast[k] > end[k]) j = 2;
        k++;
      } while (k < 16 && !j);
      if (!j || j === 1) done = 1;
      end.fill(0);
      ipv6_add(end, start);
      ipv6_add(end, ediff);
      count = (count + 1) >>> 0;
    }
    array_stop(jc);
    if (!(flags & F.NO_DECORATE) || (flags & F.JSON)) {
      default_printf(jc, '\nTotal:  \t', 'NETS', String(count));
      // netsplit.c formats into char buf[32], so long counts are cut to 31 digits
      default_printf(jc, 'Hosts/Net:\t', 'ADDRESSES', p2(128 - split_prefix).slice(0, 31));
    }
    output_stop(jc);
  }

  // ---- deaggregate.c ----
  function deaggregate(str) {
    const trim = (s) => s.replace(/^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g, '');
    const m1 = /^-*([^-]+)/.exec(str);
    if (!m1) { warn(`${PROG}: bad deaggregation string: ${str}\n`); exit(1); }
    const rest = str.slice(m1[0].length);
    const m2 = /^-*([^-]+)/.exec(rest.slice(1)); // strtok wrote NUL over the delimiter
    if (!rest.length || !m2) { warn(`${PROG}: bad deaggregation string: ${str.slice(0, m1[0].length)}\n`); exit(1); }
    const d1 = trim(m1[1]), d2 = trim(m2[1]);
    if (flags & F.IPV6) deaggregate_v6(d1, d2); else deaggregate_v4(d1, d2);
  }

  function deaggregate_v4(s1, s2) {
    let base = pton4u(s1);
    if (base === null) { warn(`${PROG}: bad IPv4 address: ${s1}\n`); exit(1); }
    const end = pton4u(s2);
    if (end === null) { warn(`${PROG}: bad IPv4 address: ${s2}\n`); exit(1); }
    if (base > end) { warn(`${PROG}: bad range\n`); exit(1); }
    const jc = { v: 0 };
    output_start(jc);
    array_start(jc, 'Deaggregated networks', 'DEAGGREGATEDNETWORK');
    while (base <= end) {
      let step = 0;
      while (step < 32 && ((base | 2 ** step) >>> 0) !== base) {
        if ((base | (0xffffffff >>> (31 - step))) >>> 0 > end) break;
        step++;
      }
      // Past bit 31 the C code shifts by >= 32 (undefined) and never returns.
      if (step >= 32) throw new Hang();
      default_printf(jc, 'Network:\t', null, `${ntop4(base)}/${32 - step}`);
      base = (base + 2 ** step) >>> 0; // uint32 wrap: a range ending at .255 starts over at 0
    }
    array_stop(jc);
    output_stop(jc);
  }

  function deaggregate_v6(s1, s2) {
    const base = inet_pton6(s1);
    if (!base) { warn(`${PROG}: bad IPv6 address: ${s1}\n`); exit(1); }
    const end = inet_pton6(s2);
    if (!end) { warn(`${PROG}: bad IPv6 address: ${s2}\n`); exit(1); }
    if (ipv6_cmp(base, end) > 0) { warn(`${PROG}: bad IPv6 range\n`); exit(1); }
    const jc = { v: 0 };
    output_start(jc);
    array_start(jc, 'Deaggregated networks', 'DEAGGREGATEDNETWORK');
    while (ipv6_cmp(base, end) <= 0) {
      let step = 0;
      for (;;) {
        const b2 = Uint8Array.from(base);
        ipv6_or1(b2, step);
        if (ipv6_cmp(base, b2) === 0) break;
        const tmp = Uint8Array.from(base);
        ipv6_orm(tmp, step + 1);
        if (ipv6_cmp(tmp, end) > 0) break;
        step++;
      }
      default_printf(jc, 'Network:\t', null, `${inet_ntop6(base)}/${128 - step}`);
      const tmp = new Uint8Array(16);
      ipv6_or1(tmp, step);
      ipv6_add(base, tmp);
    }
    array_stop(jc);
    output_stop(jc);
  }

  // ---- main ----
  function main() {
    let randomStr = null, hostname = null, splitStr = null, ipStr = null, prefixStr = null, chptr = null;
    let prefix = -1, app = 0;
    const { opts, nonopts } = getopt_long(argv);
    for (const [c, arg, msg] of opts) {
      switch (c) {
        case 'c': app |= APP.CHECK; break;
        case 'S': app |= APP.SPLIT; splitStr = arg; break;
        case 'd': app |= APP.DEAGGREGATE; ipStr = arg; break;
        case 'r': app |= APP.SHOW_INFO; flags |= F.RANDOM; randomStr = arg; break;
        case 'i': app |= APP.SHOW_INFO; flags |= F.SHOW_MODERN_INFO; break;
        case 'ALLINFO': app |= APP.SHOW_INFO; flags |= F.SHOW_ALL_INFO | F.SHOW_MODERN_INFO; break;
        case 'CLASS_PREFIX': flags |= F.ASSUME_CLASS_PREFIX; break;
        case 'REVERSE': app |= APP.SHOW_INFO; flags |= F.SHOW_REVERSE; break;
        case '4': flags |= F.IPV4; break;
        case '6': flags |= F.IPV6; break;
        case 'a': app |= APP.SHOW_INFO; flags |= F.SHOW_ADDRESS; break;
        case 'b': app |= APP.SHOW_INFO; flags |= F.SHOW_BROADCAST; break;
        case 'h': app |= APP.SHOW_INFO; flags |= F.RESOLVE_HOST; break;
        case 'o': app |= APP.SHOW_INFO; flags |= F.RESOLVE_IP; hostname = arg; break;
        case 'g': app |= APP.SHOW_INFO; flags |= F.SHOW_GEOIP; break;
        case 'm': app |= APP.SHOW_INFO; flags |= F.SHOW_NETMASK; break;
        case 'n': app |= APP.SHOW_INFO; flags |= F.SHOW_NETWORK; break;
        case 'p': app |= APP.SHOW_INFO; flags |= F.SHOW_PREFIX; break;
        case 'MINADDR': app |= APP.SHOW_INFO; flags |= F.SHOW_MINADDR; break;
        case 'MAXADDR': app |= APP.SHOW_INFO; flags |= F.SHOW_MAXADDR; break;
        case 'ADDRESSES': app |= APP.SHOW_INFO; flags |= F.SHOW_ADDRESSES; break;
        case 'ADDRSPACE': app |= APP.SHOW_INFO; flags |= F.SHOW_ADDRSPACE; break;
        case 'NO_DECORATE': flags |= F.NO_DECORATE; break;
        case 'j': flags |= F.JSON; break;
        case 's': beSilent = 1; break;
        case 'v': app |= APP.VERSION; break;
        case 'USAGE': usage(0); exit(0); break;
        case '?': if (msg) stderr(msg); usage(1); exit(0); break;
      }
    }
    if (nonopts.length) {
      if (ipStr !== null) { warn(`${PROG}: superfluous option given\n`); exit(1); }
      ipStr = nonopts[0];
      if (nonopts.length > 1) chptr = nonopts[1];
    }
    if ((flags & F.JSON) && (flags & F.NO_DECORATE)) flags &= ~F.NO_DECORATE;
    if (!(flags & ~FLAGS_TO_IGNORE)) flags |= F.SHOW_MODERN_INFO;
    if ((flags & ~ENV_INFO_FLAGS) && (flags & F.JSON)) flags |= F.SHOW_MODERN_INFO;
    if (flags & F.SHOW_ALL_INFO) flags |= F.GET_GEOIP;
    let bits = 0;
    for (let a = app; a; a >>= 1) bits += a & 1;
    if (bits > 1) { warn(`${PROG}: you cannot mix these options\n`); exit(1); }
    if ((flags & F.IPV6) && (flags & F.IPV4)) { warn(`${PROG}: you cannot specify both IPv4 and IPv6\n`); exit(1); }
    if (!(flags & F.IPV4) && ipStr !== null && ipStr.includes(':')) flags |= F.IPV6;

    if (app === APP.VERSION) { stdout(`${PROG} ${VERSION}\n`); exit(0); }
    if (app === APP.DEAGGREGATE) { deaggregate(ipStr); exit(0); }

    if (flags & F.RANDOM) {
      if (ipStr !== null) { warn(`${PROG}: provided superfluous parameter '${ipStr}'\n`); exit(1); }
      prefix = str_to_prefix(randomStr, 1);
      if (prefix < 0) { warn(`${PROG}: bad ${flags & F.IPV6 ? 'IPv6' : 'IPv4'} prefix: ${randomStr}\n`); exit(1); }
      ipStr = generate_ip_network(prefix);
    }
    if (hostname === null && ipStr === null) {
      if (!beSilent) { stderr(`${PROG}: ip address expected\n`); usage(1); }
      exit(1);
    }
    if (hostname !== null) noDns();
    if (chptr !== null) {
      if (!(flags & F.IPV6)) prefixStr = chptr;
      else {
        if (!beSilent) { stderr(`${PROG}: unexpected argument: ${chptr}\n`); usage(1); }
        exit(1);
      }
    }
    if (prefixStr === null && ipStr.includes('/')) {
      const k = ipStr.indexOf('/');
      prefixStr = ipStr.slice(k + 1);
      ipStr = ipStr.slice(0, k);
    }
    if (prefixStr !== null) {
      prefix = str_to_prefix(prefixStr, 0);
      if (prefix < 0) { warn(`${PROG}: bad ${flags & F.IPV6 ? 'IPv6' : 'IPv4'} prefix: ${prefixStr}\n`); exit(1); }
    }
    const info = flags & F.IPV6 ? get_ipv6_info(ipStr, prefix) : get_ipv4_info(ipStr, prefix);
    if (!info) exit(1);

    if (app === APP.SPLIT) {
      const sp = str_to_prefix(splitStr, 1);
      if (sp < 0) { warn(`${PROG}: bad ${flags & F.IPV6 ? 'IPv6' : 'IPv4'} prefix: ${splitStr}\n`); exit(1); }
      if (flags & F.IPV6) split_v6(sp, info); else split_v4(sp, info);
      exit(0);
    }
    if (app === APP.CHECK) exit(0);

    if (flags & F.SHOW_MODERN_INFO) {
      const jc = { v: JSON_FIRST };
      const single_host = (flags & F.IPV6) ? info.prefix === 128 : info.prefix === 32;
      output_start(jc);
      if ((!randomStr || single_host) && (single_host || info.network !== info.ip)) {
        if (info.expanded_ip) pretty_printf(jc, 'Full Address:\t', 'FULLADDRESS', info.expanded_ip);
        pretty_printf(jc, 'Address:\t', 'ADDRESS', info.ip);
      }
      if (!single_host || (flags & F.JSON)) {
        if (!(flags & F.JSON)) {
          if (info.expanded_network) pretty_printf(jc, 'Full Network:\t', 'FULLNETWORK', `${info.expanded_network}/${info.prefix}`);
          pretty_printf(jc, 'Network:\t', 'NETWORK', `${info.network}/${info.prefix}`);
          pretty_printf(jc, 'Netmask:\t', 'NETMASK', `${info.netmask} = ${info.prefix}`);
        } else {
          if (info.expanded_network) pretty_printf(jc, 'Full Network:\t', 'FULLNETWORK', info.expanded_network);
          pretty_printf(jc, 'Network:\t', 'NETWORK', info.network);
          pretty_printf(jc, 'Netmask:\t', 'NETMASK', info.netmask);
          pretty_printf(jc, 'Prefix:\t', 'PREFIX', String(info.prefix));
        }
        if (info.broadcast) pretty_printf(jc, 'Broadcast:\t', 'BROADCAST', info.broadcast);
      }
      if ((flags & F.SHOW_ALL_INFO) && info.reverse_dns) pretty_printf(jc, 'Reverse DNS:\t', 'REVERSEDNS', info.reverse_dns);
      if (!single_host || (flags & F.JSON)) {
        output_separate(jc);
        if (info.type) pretty_printf(jc, 'Address space:\t', 'ADDRSPACE', info.type);
        if ((flags & F.SHOW_ALL_INFO) && info.class) pretty_printf(jc, 'Address class:\t', 'ADDRCLASS', info.class);
        if (info.hostmin) pretty_printf(jc, 'HostMin:\t', 'MINADDR', info.hostmin);
        if (info.hostmax) pretty_printf(jc, 'HostMax:\t', 'MAXADDR', info.hostmax);
        if ((flags & F.IPV6) && info.prefix < 112 && !(flags & F.JSON)) pretty_printf(jc, 'Hosts/Net:\t', 'ADDRESSES', `2^(${128 - info.prefix}) = ${info.hosts}`);
        else pretty_printf(jc, 'Hosts/Net:\t', 'ADDRESSES', info.hosts);
      } else {
        if (info.type) pretty_printf(jc, 'Address space:\t', 'ADDRSPACE', info.type);
        if ((flags & F.SHOW_ALL_INFO) && info.class) pretty_printf(jc, 'Address class:\t', 'ADDRCLASS', info.class);
      }
      output_stop(jc);
    } else {
      const env = (flag, name, value) => {
        if (!(flags & flag)) return;
        if (!(flags & F.NO_DECORATE)) stdout(name + '=');
        if (value === null) throw new Crash(139); // printf("%s\n", NULL) -> puts(NULL)
        stdout(value + '\n');
      };
      const quoted = (v) => (v.includes(' ') ? `"${v}"` : v);
      env(F.SHOW_ADDRESS, 'ADDRESS', info.ip);
      env(F.SHOW_NETMASK, 'NETMASK', info.netmask);
      env(F.SHOW_PREFIX, 'PREFIX', String(info.prefix));
      if (!(flags & F.IPV6)) env(F.SHOW_BROADCAST, 'BROADCAST', info.broadcast);
      env(F.SHOW_NETWORK, 'NETWORK', info.network);
      env(F.SHOW_REVERSE, 'REVERSEDNS', info.reverse_dns);
      env(F.SHOW_MINADDR, 'MINADDR', info.hostmin);
      env(F.SHOW_MAXADDR, 'MAXADDR', info.hostmax);
      env(F.SHOW_ADDRSPACE, 'ADDRSPACE', quoted(info.type));
      if (info.hosts) env(F.SHOW_ADDRESSES, 'ADDRESSES', quoted(info.hosts));
    }
    exit(0);
  }

  let status;
  try {
    main();
  } catch (e) {
    if (e instanceof Exit) status = e.code;
    else if (e instanceof Crash) { pending = ''; status = e.code; }
    else if (e instanceof AssertFail) { stderr(`${PROG}: ${e.message}\n`); pending = ''; status = 134; }
    else if (e instanceof Hang) { pending = ''; status = 'hang'; }
    else if (e instanceof Truncated) { pending = ''; status = 'truncated'; }
    else throw e;
  }
  if (status !== 'truncated') out += pending; // exit() flushes stdout; a crash loses the partial line
  return { stdout: out, status };
}
