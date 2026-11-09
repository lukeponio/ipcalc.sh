// Faithful JavaScript port of ipcalc 0.51 (Debian/Ubuntu `ipcalc`, Perl,
// Copyright (C) Krischan Jodies 2000-2021, GPL-2.0-or-later).
//
// Goal: byte-identical stdout to `ipcalc <args> | cat` for every input,
// including the original's quirks. The Perl script runs under `use bignum`,
// so numbers are modelled as BigInt plus two Perl-isms that leak into output:
//   NAN   - Math::BigInt NaN (e.g. shifting by a negative amount)
//   UNDEF - an uninitialised scalar (bitcountmaskton(0) returns undef)
// Strings are "binary" strings: one JS char per input byte (latin1).
//
// Do not "fix" behaviour here. Features go in a separate layer; the golden
// tests in test/ pin this file to the real tool.

import { USAGE, HELP } from './texts.js';

const VERSION = '0.51';
const NAN = Symbol('NaN');
const UNDEF = Symbol('undef');
const T32 = 4294967295n;

// ---- Perl/bignum value semantics -------------------------------------------
const num = (x) => {
  if (x === UNDEF || x === undefined) return 0n;
  if (typeof x === 'bigint' || x === NAN) return x;
  if (typeof x === 'number') return BigInt(x);
  // numeric string (only ever digit strings reach arithmetic)
  const m = /^\s*([+-]?\d+)/.exec(x);
  return m ? BigInt(m[1]) : 0n;
};
const op = (f) => (a, b) => {
  a = num(a); b = num(b);
  return a === NAN || b === NAN ? NAN : f(a, b);
};
const add = op((a, b) => a + b);
const sub = op((a, b) => a - b);
const mul = op((a, b) => a * b);
const and = op((a, b) => a & b);
const or = op((a, b) => a | b);
const shl = op((a, b) => (b < 0n ? NAN : a << b));
const shr = op((a, b) => (b < 0n ? NAN : a >> b));
// ~undef under bignum is "" which becomes NaN when combined with a BigInt.
const not = (a) => (a === UNDEF || a === NAN ? NAN : ~num(a));
const cmp = (f) => (a, b) => {
  a = num(a); b = num(b);
  return a === NAN || b === NAN ? false : f(a, b);
};
const lt = cmp((a, b) => a < b);
const gt = cmp((a, b) => a > b);
const le = cmp((a, b) => a <= b);
const eq = cmp((a, b) => a === b);
const ne = (a, b) => !eq(a, b);
const S = (x) => (x === NAN ? 'NaN' : x === UNDEF || x === undefined ? '' : String(x));
const pad = (s, w) => s.padEnd(w, ' '); // printf "%-Ns"
const rep = (s, n) => (n > 0 ? s.repeat(n) : '');

// Perl split with a literal separator: trailing empty fields are dropped.
function psplit(sep, str) {
  if (str === '') return [];
  const parts = str.split(sep);
  while (parts.length && parts[parts.length - 1] === '') parts.pop();
  return parts;
}

// printf "%d" of a digit string.
function pd(str) {
  const v = BigInt(str);
  if (v < 2n ** 63n) return String(v);
  if (v < 2n ** 64n) return String(v - 2n ** 64n);
  return '-1';
}

class Die extends Error {}
class Hang extends Error {}

export function ipcalc(argvIn) {
  let ARGV = [...argvIn];
  let out = '';
  const print = (...s) => { out += s.join(''); };

  let quads_color = '\x1b[34m';
  let norml_color = '\x1b[m';
  let binry_color = '\x1b[33m';
  let mask_color = '\x1b[31m';
  let class_color = '\x1b[35m';
  let subnt_color = '\x1b[0m\x1b[32m';
  const error_color = '\x1b[31m';
  let break_ = '\n';
  let color_old = '';
  let color_actual = '';

  let opt_text = 1, opt_html = 0, opt_color = 0, opt_print_bits = 1;
  let opt_print_only_class = 0, opt_split = 0, opt_deaggregate = 0;
  let opt_version = 0, opt_help = 0;
  const opt_split_sizes = [];
  let error = '';
  let ipv6 = 0;

  const html = (s) => { if (opt_html) print(s); };
  const text = (s) => { if (opt_text) print(s); };

  function set_color(c) {
    if (c === 'oldcolor') c = color_old;
    color_old = color_actual;
    color_actual = c;
    return c;
  }

  function ntoa(x) {
    x = num(x);
    if (x === NAN) throw new Die("Cannot pack NaN with 'N'");
    // pack("N"): numify (IV/UV, else NV clamped), keep the low 32 bits.
    let v;
    if (x >= 2n ** 64n) v = T32;
    else if (x < -(2n ** 63n)) v = 0n;
    else v = BigInt.asUintN(32, x);
    return [24n, 16n, 8n, 0n].map((s) => String((v >> s) & 255n)).join('.');
  }

  function ntobitcountmask(mask) {
    // Leading one bits of the low 32 bits (two's complement); NaN counts as 32.
    if (mask === NAN) return 32;
    const z = BigInt.asUintN(32, num(mask)).toString(2).padStart(32, '0').indexOf('0');
    return z === -1 ? 32 : z;
  }
  function bitcountmaskton(k) {
    let n = UNDEF;
    for (let i = 0; i < k; i++) n = or(n, shl(1n, BigInt(31 - i)));
    return n;
  }

  function validate_netmask(mask) {
    let saw_zero = 0;
    if (eq(and(mask, 1n << 31n), 0n)) {
      print('WILDCARD\n');
      mask = not(mask);
    }
    for (let i = 0n; i < 32n; i++) {
      if (eq(and(mask, 1n << (31n - i)), 0n)) saw_zero = 1;
      else if (saw_zero) {
        print('INVALID NETMASK\n');
        return -1n;
      }
    }
    return mask;
  }

  function prefixlenton(p) {
    let n = 0n;
    const lim = 127 - Number(p);
    for (let i = 128; i > lim; i--) n += 1n << BigInt(i);
    return n;
  }

  function ip6ton(arg) {
    arg = arg.toLowerCase();
    if (arg.replace(/[0-9a-f:]/g, '') !== '') return -1n;
    if (/^::/.test(arg)) arg = '0' + arg;
    if (/::$/.test(arg)) arg = arg + '0';
    const tmp = psplit(':', arg);
    const slice = [];
    let compressed = 0;
    for (const s of tmp) {
      if (s === '') {
        if (compressed) return -1n;
        for (let i = 0; i < 8 - (tmp.length - 1); i++) { slice.push('0'); compressed = 1; }
      } else slice.push(s);
    }
    if (slice.length - 1 !== 7) return -1n;
    let n = 0n;
    for (let i = 0; i < 8; i++) n += BigInt('0x' + slice[i]) << BigInt(16 * (7 - i));
    return n;
  }

  function argton(arg, netmask_flag) {
    if (arg === undefined) arg = '';
    if (!netmask_flag && /^[0-9a-fA-F:]+$/.test(arg)) {
      ipv6 = 1;
      return ip6ton(arg);
    }
    let m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(arg);
    if (m) {
      let n = 0n, i = 24n;
      for (const d of m.slice(1, 5)) {
        const v = BigInt(d);
        if (v > 255n) return -1n;
        n += v << i;
        i -= 8n;
      }
      return netmask_flag ? validate_netmask(n) : n;
    }
    m = /^\/(\d+)$/.exec(arg);
    if (m) arg = m[1];
    if (ipv6) {
      if (!/^\d{1,3}$/.test(arg) || Number(arg) > 128) return -1n;
      return prefixlenton(arg);
    }
    if (/^\d{1,2}$/.test(arg)) {
      if (Number(arg) > 32) return -1n;
      let n = 0n;
      for (let i = 0; i < Number(arg); i++) n |= 1n << BigInt(31 - i);
      return n;
    }
    if (/^[0-9A-Fa-f]{8}$/.test(arg) || /^0x[0-9A-Fa-f]{8}$/.test(arg)) {
      const h = BigInt('0x' + arg.replace(/^0x/, ''));
      return netmask_flag ? validate_netmask(h) : h;
    }
    return -1n;
  }

  function getclass(network, numeric) {
    let c = 1;
    while (eq(and(network, shl(1n, BigInt(32 - c))), shl(1n, BigInt(32 - c)))) {
      c++;
      if (c > 5) return 'invalid';
    }
    return numeric ? String([0, 8, 16, 24, 4, 5, 5][c]) : String.fromCharCode(c + 64);
  }

  // Perl iterates %netblocks in hash order, which is randomised per process.
  // Any fixed order is a possible real output; we use source order.
  const NETBLOCKS = [
    ['192.168.0.0', 16, 'Private Internet,http://www.ietf.org/rfc/rfc1918.txt'],
    ['172.16.0.0', 12, 'Private Internet,http://www.ietf.org/rfc/rfc1918.txt'],
    ['10.0.0.0', 8, 'Private Internet,http://www.ietf.org/rfc/rfc1918.txt'],
    ['169.254.0.0', 16, 'APIPA,http://www.ietf.org/rfc/rfc3330.txt'],
    ['127.0.0.0', 8, 'Loopback,http://www.ietf.org/rfc/rfc1700.txt'],
    ['224.0.0.0', 4, 'Multicast,http://www.ietf.org/rfc/rfc3171.txt'],
  ];
  function netblock(my_start, my_mask) {
    const my_end = or(my_start, and(not(my_mask), T32));
    let match = 0;
    for (const [net, mask, val] of NETBLOCKS) {
      const start = BigInt(net.split('.').reduce((a, o) => a * 256 + Number(o), 0));
      const end = start + (1n << BigInt(32 - mask)) - 1n;
      if (ge(my_start, start) && le(my_start, end)) match++;
      if (ge(my_end, start) && le(my_end, end)) match++;
      if (gt(start, my_start) && lt(end, my_end)) match = 1;
      if (match === 1) return 'In Part ' + val;
      if (match === 2) return val;
    }
    return '';
  }
  function ge(a, b) { return cmp((x, y) => x >= y)(a, b); }

  function wrap_html(width, str) {
    const last = str.length - 1;
    let result = '';
    let cur = 0, start = 0, last_pos = 0, line;
    while (cur < last) {
      while (cur < last && str[cur] !== ' ') {
        if (str[cur] === '<') {
          cur++;
          while (str[cur] !== '>') cur++;
        }
        cur++;
      }
      line = str.substr(start, cur - start).replace(/<.+?>/g, '');
      if (line.length <= width) {
        last_pos = cur;
        cur++;
        continue;
      }
      if (last_pos !== start) cur = last_pos;
      line = str.substr(start, cur - start);
      cur++;
      start = cur;
      last_pos = start;
      if (cur < last) result += line + '<br>';
    }
    result += str.substr(start, cur - start);
    return result;
  }

  function get_description(network, mask) {
    const d = [];
    if (opt_color || opt_html) {
      let f = set_color(class_color) + 'Class ' + getclass(network);
      if (opt_html) f += '</font>';
      f += set_color(norml_color);
      d.push(f);
    } else d.push('Class ' + getclass(network));
    let [txt, url] = psplit(',', netblock(network, mask));
    if (txt !== undefined) {
      if (opt_html) txt = '<a href="' + (url ?? '') + '">' + txt + '</a>';
      d.push(txt);
    }
    if (ntobitcountmask(mask) === 31) {
      d.push(opt_html ? '<a href="http://www.ietf.org/rfc/rfc3021.txt">PtP Link</a>' : 'PtP Link RFC 3021');
    }
    return d.join(', ');
  }

  function printline(label, address, mask1, mask2, html_fillup) {
    mask1 = ntobitcountmask(mask1);
    mask2 = ntobitcountmask(mask2);
    let line = '';
    let newbitcolor_on = 0;
    let additional_info = '';
    let classbitcolor_on = 0;
    if (label === 'Netmask') additional_info = ' = ' + mask1;
    if (label === 'Network') { classbitcolor_on = 1; additional_info = '/' + mask1; }
    if (label === 'Hostroute' && mask1 === 32) classbitcolor_on = 1;

    html('<tr>\n');
    html('<td><tt>');
    print(set_color(norml_color));
    if (opt_html && html_fillup) print(label + ':' + rep('&nbsp;', 11 - label.length));
    else print(pad(label + ':', 11));
    html('</font></tt></td>\n');
    html('<td><tt>');
    print(set_color(quads_color));
    const second = ntoa(address) + additional_info;
    if (opt_html && html_fillup) print(second + rep('&nbsp;', 21 - second.length));
    else print(pad(second, 21));
    html('</font></tt></td>\n');

    if (opt_print_bits) {
      html('<td><tt>');
      let bit_color = set_color(binry_color);
      if (label === 'Netmask') bit_color = set_color(mask_color);
      line += classbitcolor_on ? set_color(class_color) : set_color(bit_color);
      // Bit i of the two's complement value; ntoa() above already rejected NaN.
      const bits = BigInt.asUintN(32, num(address)).toString(2).padStart(32, '0');
      for (let i = 1; i < 33; i++) {
        const bit = bits[i - 1] === '1' ? 1 : 0;
        line += bit;
        if (classbitcolor_on && bit === 0) {
          classbitcolor_on = 0;
          line += newbitcolor_on ? set_color(subnt_color) : set_color(bit_color);
        }
        if (i % 8 === 0 && i < 32) {
          line += set_color(norml_color) + '.';
          line += set_color('oldcolor');
        }
        if (i === mask1) line += ' ';
        if ((i === mask1 || i === mask2) && mask1 !== mask2) {
          if (newbitcolor_on) {
            newbitcolor_on = 0;
            if (!classbitcolor_on) line += set_color(bit_color);
          } else {
            newbitcolor_on = 1;
            if (!classbitcolor_on) line += set_color(subnt_color);
          }
        }
      }
      line += set_color(norml_color);
      print(line);
      html('</tt></font></td>\n');
    }
    html('</tr>\n');
    html('\n');
    text('\n');
  }

  function printnet(network, mask1, mask2) {
    const broadcast = or(network, and(not(mask1), T32));
    let hmin = add(network, 1n);
    let hmax = sub(broadcast, 1n);
    let hostn = add(sub(hmax, hmin), 1n);
    const mask = ntobitcountmask(mask1);
    if (mask === 31) { hmax = broadcast; hmin = network; hostn = 2n; }
    if (mask === 32) hostn = 1n;
    if (mask === 32) printline('Hostroute', network, mask1, mask2, 1);
    else {
      printline('Network', network, mask1, mask2, 1);
      printline('HostMin', hmin, mask1, mask2);
      printline('HostMax', hmax, mask1, mask2);
      if (mask < 31) printline('Broadcast', broadcast, mask1, mask2);
    }
    html('<tr>\n');
    html('<td valign="top"><tt>');
    print(set_color(norml_color));
    print('Hosts/Net: ');
    html('</font></tt></td>\n');
    html('<td valign="top"><tt>');
    print(set_color(quads_color));
    print(pad(S(hostn), 22));
    html('</font></tt></td>\n');
    html('<td>');
    print(opt_html ? wrap_html(30, get_description(network, mask1)) : get_description(network, mask1));
    html('</font></td>\n');
    html('</tr>\n');
    html('\n');
    text('\n');
    text('\n');
    return hostn;
  }

  function supernet(network, mask1, mask2) {
    network = and(network, mask2);
    printline('Netmask', mask2, mask2, mask1, 1);
    printline('Wildcard', not(mask2), mask2, mask1);
    print('\n');
    printnet(network, mask2, mask1);
  }

  function subnets(network, mask1, mask2) {
    const b1 = ntobitcountmask(mask1);
    const b2 = ntobitcountmask(mask2);
    html('<table border="0" cellspacing="0" cellpadding="0">');
    html('\n');
    printline('Netmask', mask2, mask2, mask1, 1);
    printline('Wildcard', not(mask2), mask2, mask1);
    html('</table>\n');
    print('\n');
    const limit = shl(1n, BigInt(b2 - b1));
    for (let s = 0n; lt(s, limit); s++) {
      const net = or(network, shl(s, BigInt(32 - b2)));
      print(' ' + (s + 1n) + '.\n');
      html('<table border="0" cellspacing="0" cellpadding="0">');
      html('\n');
      printnet(net, mask2, mask1);
      html('</table>\n');
      if (s >= 1000n) {
        print('... stopped at 1000 subnets ...' + break_);
        break;
      }
    }
    const subnet = limit;
    let hostn = sub(sub(or(network, and(not(mask2), T32)), network), 1n);
    if (gt(hostn, -1n)) {
      print('\nSubnets:   ' + quads_color + S(subnet));
      html('</font>');
      print(norml_color + break_);
      html('</font>');
    }
    if (lt(hostn, 1n)) hostn = 1n;
    print('Hosts:     ' + quads_color + S(mul(hostn, subnet)));
    html('</font>');
    print(norml_color + break_);
    html('</font>');
  }

  function deaggregate(start, end) {
    let base = start;
    while (le(base, end)) {
      let step = 0n;
      while (ne(or(base, shl(1n, step)), base)) {
        if (gt(or(base, shr(T32, 31n - step)), end)) break;
        step++;
        // Past bit 32 the Perl original compares against NaN forever.
        if (step > 400n) throw new Hang('deaggregate never terminates');
      }
      print(ntoa(base) + '/' + (32n - step));
      print('\n');
      base = add(base, shl(1n, step));
    }
  }

  const round2powerof2 = (x) => {
    let i = 0n;
    while (gt(x, 1n << i)) i++;
    return 1n << i;
  };
  const size2bitcountmask = (size) => {
    let i = 0n;
    while (gt(size, 1n << i)) i++;
    return Number(32n - i);
  };
  // Perl's <=> on numeric strings: exact for integers fitting 64 bits, else NV.
  const spaceship = (a, b) => {
    if (a < 2n ** 64n && b < 2n ** 64n) return a < b ? -1 : a > b ? 1 : 0;
    const x = Number(a), y = Number(b);
    return x < y ? -1 : x > y ? 1 : 0;
  };

  function split_network(network, mask1, mask2, sizes) {
    const first_address = network;
    const broadcast = or(network, and(not(mask1), T32));
    let entries = [];
    let needed = 0n;
    sizes.forEach((s, i) => {
      const ns = round2powerof2(BigInt(s) + 2n);
      entries.push([ns, i]);
      needed += ns;
    });
    entries.sort((a, b) => spaceship(b[0], a[0]));
    const net = [], mask = [];
    for (const [size, nr] of entries) {
      net[nr] = network;
      mask[nr] = size2bitcountmask(size);
      network = add(network, size);
    }
    for (let i = 0; i < sizes.length; i++) {
      print(`${i + 1}. Requested size: ${pd(sizes[i])} hosts\n`);
      printline('Netmask', bitcountmaskton(mask[i]), bitcountmaskton(mask[i]), mask2);
      printnet(net[i], bitcountmaskton(mask[i]), mask2);
    }
    const used_mask = size2bitcountmask(needed);
    if (used_mask < ntobitcountmask(mask1)) print('Network is too small\n');
    print('Needed size:  ' + needed + ' addresses.\n');
    print('Used network: ' + ntoa(first_address) + '/' + used_mask + '\n');
    print('Unused:\n');
    deaggregate(network, broadcast);
  }

  function ntob6(n) {
    let b = '';
    for (let i = 127; i > -1; i--) {
      const m = 1n << BigInt(i);
      b += (n & m) === m ? '1' : '0';
      if (i % 16 === 0 && i !== 0) b += ':';
    }
    return b;
  }

  function ntoip6(n) {
    const slices = [];
    for (let i = 7; i > -1; i--) slices.push(((n >> BigInt(i * 16)) & 65535n).toString(16));
    let result = slices.join(':');
    let max_length = 0, start = 0;
    for (let i = 0; i < 8; i++) {
      let len = 0;
      while (i + len < 8 && slices[i + len] === '0') len++;
      if (len > max_length) { start = i; max_length = len; }
    }
    if (max_length > 0) {
      result = start === 0 ? '::' : '';
      for (let i = 0; i < 8; i++) {
        if (!(i >= start && i < start + max_length)) {
          result += slices[i];
          if (i < 7) result += ':';
          if (i + 1 === start) result += ':';
        }
      }
    }
    return result;
  }

  function print_summary6(address, netmask) {
    const pm = prefixlenton(netmask);
    print(pad('Address:', 9), pad(ntoip6(address), 40), pad(ntob6(address), 130), '\n');
    print(pad('Netmask:', 9), pad(S(netmask), 40), pad(ntob6(pm), 130), '\n');
    print(pad('Prefix:', 9), pad(ntoip6(address & pm) + '/' + S(netmask), 40), pad(ntob6(address & pm), 130), '\n');
    print('\n');
  }

  function getopts() {
    const tmp = [];
    let nr_opts = 0;
    const read_opt = (prefix, opts) => {
      let read = 0;
      for (const o of opts) {
        ++read;
        if (o === 'h' || o === 'html') { opt_html = 1; opt_text = 0; }
        else if (o === 'help') opt_help = 1;
        else if (o === 'c' || o === 'color') opt_color = 1;
        else if (o === 'n' || o === 'nocolor') opt_color = 0;
        else if (o === 'v' || o === 'version') opt_version = 1;
        else if (o === 'b' || o === 'nobinary') opt_print_bits = 0;
        else if (o === 'class') opt_print_only_class = 1;
        else if (o === 'r' || o === 'range') opt_deaggregate = 1;
        else if (o === 's' || o === 'split') {
          opt_split = 1;
          while (ARGV[0] !== undefined && /^\d+$/.test(ARGV[0])) opt_split_sizes.push(ARGV.shift());
          if (opt_split_sizes.length === 0) error += 'Argument for ' + prefix + o + ' is missing or invalid \n';
        } else {
          error += 'Unknown option: ' + prefix + o + '\n';
          --read;
        }
      }
      return read;
    };
    const has_opts = () => ARGV.some((a) => /^-/.test(a));
    while (has_opts()) {
      const arg = ARGV.shift();
      let m;
      if ((m = /^--(.+)/.exec(arg))) nr_opts += read_opt('--', [m[1]]);
      else if ((m = /^-(.+)/.exec(arg))) nr_opts += read_opt('-', [...m[1]]);
      else tmp.push(arg);
    }
    tmp.push(...ARGV);
    let args = [];
    for (const a of tmp) {
      let m;
      if ((m = /^(.+?)\/(.+)$/.exec(a))) args.push(m[1], m[2]);
      else if ((m = /^(.+)\/$/.exec(a))) args.push(m[1]);
      else if ((m = /^(.+)-(.+)$/.exec(a))) { args.push(m[1], m[2]); opt_deaggregate = 1; }
      else if (a === '-') opt_deaggregate = 1;
      else args.push(a);
    }
    if (args.length === 3 && args[1] === '-') { args = [args[0], args[2]]; opt_deaggregate = 1; }
    if (opt_html && nr_opts === 1 && args.length === 0) opt_help = 1;
    if (error) { print(error); throw new Exit(); }
    return args;
  }

  class Exit extends Error {}

  function main() {
    let address = -1n, address2 = -1n, mask1 = -1n, mask2 = -1n;
    if (ARGV[0] === undefined) { print(USAGE); return; }
    ARGV = getopts();
    if (opt_help) { print(HELP, USAGE); return; }
    if (opt_version) { print(VERSION + '\n'); return; }
    if (!opt_color) {
      quads_color = norml_color = binry_color = mask_color = class_color = subnt_color = '';
    }
    if (opt_html) {
      quads_color = '<font color="#0000ff">';
      norml_color = '<font color="#000000">';
      binry_color = '<font color="#909090">';
      mask_color = '<font color="#ff0000">';
      class_color = '<font color="#009900">';
      subnt_color = '<font color="#663366">';
      break_ = '<br>';
      print('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">\n<html>\n<head>\n<meta HTTP-EQUIV="content-type" CONTENT="text/html; charset=UTF-8">\n<title>Bla</title>\n</head>\n<body>\n');
      print('<!-- Version ' + VERSION + ' -->\n');
    }
    if (ARGV[0] !== undefined) address = argton(ARGV[0], 0);
    if (eq(address, -1n)) {
      error += 'INVALID ADDRESS: ' + S(ARGV[0]) + '\n';
      address = argton('192.168.1.1', 0);
    }
    if (opt_print_only_class) { print(getclass(address, 1)); return; }
    if (opt_deaggregate) {
      if (ARGV[1] !== undefined) address2 = argton(ARGV[1], 0);
      if (eq(address2, -1n)) {
        error += 'INVALID ADDRESS2: ' + S(ARGV[1]) + '\n';
        address2 = argton('192.168.1.1', 0);
      }
      if (error) print(error + '\n');
      print('deaggregate ' + ntoa(address) + ' - ' + ntoa(address2) + '\n');
      deaggregate(address, address2);
      return;
    }
    if (ipv6) {
      if (ARGV[1] !== undefined) {
        const m = ARGV[1];
        if (!/^\d{1,3}$/.test(m) || Number(m) > 128) { print('INVALID MASK1\n\n'); return; }
        mask1 = m;
      } else mask1 = 64;
    } else {
      mask1 = ARGV[1] !== undefined ? argton(ARGV[1], 1) : argton('24', 1);
      if (eq(mask1, -1n)) {
        error += 'INVALID MASK1:   ' + S(ARGV[1]) + '\n';
        mask1 = argton('24', 1);
      }
      mask2 = ARGV[2] !== undefined ? argton(ARGV[2], 1) : mask1;
      if (eq(mask2, -1n)) {
        error += 'INVALID MASK2:   ' + S(ARGV[2]) + '\n';
        mask2 = argton('24', 1);
      }
    }
    if (error) {
      if (opt_color) print(set_color(error_color));
      print(error + '\n');
      print(set_color(norml_color));
      return;
    }
    if (ipv6) { print_summary6(address, mask1); return; }
    html('<table border="0" cellspacing="0" cellpadding="0">');
    html('\n');
    printline('Address', address, mask1, mask1, 1);
    printline('Netmask', mask1, mask1, mask1);
    printline('Wildcard', not(mask1), mask1, mask1);
    html('<tr>\n');
    html('<td colspan="3"><tt>');
    print('=>');
    html('</tt></td>\n');
    html('</tr>\n');
    print('\n');
    const network = and(address, mask1);
    printnet(network, mask1, mask1);
    html('</table>\n');
    if (opt_split) { split_network(network, mask1, mask2, opt_split_sizes); return; }
    if (lt(mask1, mask2)) {
      print('Subnets after transition from /' + ntobitcountmask(mask1));
      print(' to /' + ntobitcountmask(mask2) + '\n\n');
      subnets(network, mask1, mask2);
    }
    if (gt(mask1, mask2)) {
      print('Supernet\n\n');
      supernet(network, mask1, mask2);
      if (opt_html) html('</table>\n');
    }
    if (opt_html) {
      print('    <p>\n      <a href="http://validator.w3.org/check/referer"><img border="0"\n          src="http://www.w3.org/Icons/valid-html401"\n          alt="Valid HTML 4.01!" height="31" width="88"></a>\n    </p>\n');
    }
  }

  // status: 0 normal exit, 255 Perl die (partial stdout), 'hang' when the
  // original would loop forever (stdout is what it printed before hanging).
  let status = 0;
  try {
    main();
  } catch (e) {
    if (e instanceof Exit) status = 0;
    else if (e instanceof Die) status = 255;
    else if (e instanceof Hang) status = 'hang';
    else throw e;
  }
  return { stdout: out, status };
}
