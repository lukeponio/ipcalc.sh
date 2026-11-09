import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extras } from '../src/extras.js';
import { ipcalc } from '../src/ipcalc.js';
import { pathToArgv } from '../src/worker.js';

const run = (path) => extras(pathToArgv(path));
const out = (path) => run(path).stdout;

test('extras only take input that ipcalc 0.51 rejects', () => {
  for (const p of ['/', '/10.0.0.0/8', '/-b/10.0.0.0/8', '/10.0.0.0/20/24', '/10.0.0.1-10.0.0.77', '/in', '/--help']) assert.equal(run(p), null, p);
  for (const p of ['/10.1.2.7/in/10.1.0.0/22', '/24/in/20', '/short/10.0.0.0/20', '/merge/10.0.0.0/24', '/exclude/10.0.0.0/16/10.0.5.0/24',
    '/overlap/10.0.0.0/24', '/expand/10.0.0.0/30', '/split/10.0.0.0/16/12', '/acl/10.0.0.0/24', '/prefix-list/X/10.0.0.0/8', '/help']) {
    assert.notEqual(run(p), null, p);
    assert.match(ipcalc(pathToArgv(p)).stdout, /INVALID/, p);
  }
});

test('in: contains check and how-many questions', () => {
  assert.deepEqual(run('/10.1.2.7/in/10.1.0.0/22'), { stdout: 'yes\n', status: 0 });
  assert.deepEqual(run('/10.1.5.7/in/10.1.0.0/22'), { stdout: 'no\n', status: 1 });
  assert.equal(out('/10.0.1.0/24/in/10.0.0.0/16'), 'yes\n');
  assert.equal(out('/2001:db8::1/in/10.0.0.0/8/2001:db8::/32'), 'yes\n');
  assert.equal(out('/24/in/20'), 'A /20 holds 16 /24s, each with 254 usable hosts.\n');
  assert.equal(out('/20/in/24'), 'No /20s fit in a /24, because a /20 is bigger. A /20 holds 16 /24s.\n');
  assert.equal(out('/24/in/10.0.0.0/20'), '10.0.0.0/20 holds 16 /24s, each with 254 usable hosts.\n');
});

test('short summary has the Contains: line', () => {
  assert.equal(out('/short/10.0.0.0/20'), 'Network:   10.0.0.0/20\nNetmask:   255.255.240.0 = 20\nWildcard:  0.0.15.255\nBroadcast: 10.0.15.255\n' +
    'HostMin:   10.0.0.1\nHostMax:   10.0.15.254\nHosts:     4094\nContains:  16 x /24, 64 x /26, 1024 x /30\n');
  assert.match(out('/short/10.0.0.0/31'), /HostMin:   10\.0\.0\.0\nHostMax:   10\.0\.0\.1\nHosts:     2\n$/);
  assert.match(out('/short/2001:db8::/32'), /Contains:  65536 x \/48, 16777216 x \/56, 4294967296 x \/64\n$/);
});

test('merge, exclude, overlap, expand, split', () => {
  assert.equal(out('/merge/10.0.0.0/24/10.0.1.0/24/10.0.3.0/255.255.255.0'), '10.0.0.0/23\n10.0.3.0/24\n');
  assert.equal(out('/merge/10.0.0.5-10.0.0.200'), ipcalc(['10.0.0.5', '-', '10.0.0.200']).stdout.split('\n').slice(1).join('\n'));
  assert.equal(out('/merge/2001:db8::/33,2001:db8:8000::/33'), '2001:db8::/32\n');
  assert.equal(out('/exclude/10.0.0.0/22/10.0.1.0/24'), '10.0.0.0/24\n10.0.2.0/23\n');
  assert.deepEqual(run('/overlap/10.0.0.0/23/10.0.1.0/24/10.0.4.0/24'), { stdout: '10.0.0.0/23 overlaps 10.0.1.0/24\n', status: 0 });
  assert.deepEqual(run('/overlap/10.0.0.0/24/10.0.1.0/24'), { stdout: 'no overlap\n', status: 1 });
  assert.equal(out('/expand/10.0.0.6-10.0.0.9'), '10.0.0.6\n10.0.0.7\n10.0.0.8\n10.0.0.9\n');
  assert.match(out('/expand/10.0.0.0/8'), /^ipcalc\.sh: 16777216 addresses/);
  const s = out('/split/10.0.0.0/16/12').split('\n');
  assert.deepEqual([s.length, s[0], s[11]], [13, '10.0.0.0/20', '10.0.176.0/20']);
});

test('acl and prefix-list', () => {
  assert.equal(out('/acl/10.0.0.0/24/10.0.1.0/24/10.0.9.1'), 'permit 10.0.0.0 0.0.1.255\npermit host 10.0.9.1\n');
  assert.equal(out('/acl/0.0.0.0/0'), 'permit any\n');
  assert.equal(out('/prefix-list/BRANCH/10.0.0.0/8/2001:db8::/32'), 'ip prefix-list BRANCH seq 5 permit 10.0.0.0/8\nipv6 prefix-list BRANCH seq 10 permit 2001:db8::/32\n');
});

test('bad input gets a one-line error', () => {
  assert.deepEqual(run('/merge/foo'), { stdout: 'ipcalc.sh: not an address, CIDR or range: foo\n', status: 2 });
  assert.match(out('/split/10.0.0.0/30/8'), /^ipcalc\.sh: a \/30 can't be split into 8/);
  assert.match(out('/help'), /netdiagrams\.com\/\?utm_source=ipcalc\.sh/);
});
