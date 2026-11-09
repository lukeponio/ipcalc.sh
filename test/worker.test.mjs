import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker, { pathToArgv, pathToArgvRh } from '../src/worker.js';

test('path segments map to ipcalc argv', () => {
  assert.deepEqual(pathToArgv('/'), []);
  assert.deepEqual(pathToArgv('/192.168.0.1/24'), ['192.168.0.1', '24']);
  assert.deepEqual(pathToArgv('/10.0.0.0/20/24'), ['10.0.0.0', '20', '24']);
  assert.deepEqual(pathToArgv('/-b/10.0.0.0/8'), ['-b', '10.0.0.0', '8']);
  assert.deepEqual(pathToArgv('/10.0.0.0/24+-s+10%2020'), ['10.0.0.0', '24', '-s', '10', '20']);
  assert.deepEqual(pathToArgv('/%C3%A9'), ['??']); // non-ASCII bytes are neutralised
  assert.deepEqual(pathToArgv('/%1b]0;x%07%1b[2J'), ['?]0;x??[2J']); // no terminal escapes
});

const get = (path, ua, host = 'ipcalc.sh') =>
  worker.fetch(new Request(`https://${host}${path}`, { headers: ua ? { 'user-agent': ua } : {} }), {
    BROWSER_REDIRECT: 'https://subnetting.io/',
  });

test('curl gets plain text identical to the CLI', async () => {
  const r = await get('/192.168.0.1/24', 'curl/8.5.0');
  assert.equal(r.headers.get('content-type'), 'text/plain; charset=utf-8');
  const body = await r.text();
  assert.match(body, /^Address:   192\.168\.0\.1          11000000\.10101000\.00000000\. 00000001\n/);
  assert.match(body, /Hosts\/Net: 254                   Class C, Private Internet\n\n$/);
});

test('no user agent and wget get text; browsers get redirected with ?q=', async () => {
  assert.equal((await get('/10.0.0.0/8', '')).status, 200);
  assert.equal((await get('/10.0.0.0/8', 'Wget/1.21.4')).status, 200);
  const r = await get('/10.0.0.0/20/24', 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0');
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), 'https://subnetting.io/?q=10.0.0.0%2F20%2F24');
});

test('oversized paths are refused before running ipcalc', async () => {
  const r = await get('/-s/' + '1/'.repeat(600) + '10.0.0.0/8', 'curl/8.5.0');
  assert.equal(r.status, 414);
});

test('/ng/ paths keep address/prefix together for Red Hat ipcalc', () => {
  assert.deepEqual(pathToArgvRh('/192.168.0.1/24'), ['192.168.0.1/24']);
  assert.deepEqual(pathToArgvRh('/2001:db8::/32'), ['2001:db8::/32']);
  assert.deepEqual(pathToArgvRh('/-S/26/10.0.0.0/24'), ['-S', '26', '10.0.0.0/24']);
  assert.deepEqual(pathToArgvRh('/-S/255.255.255.192/10.0.0.0/24'), ['-S', '255.255.255.192', '10.0.0.0/24']);
  assert.deepEqual(pathToArgvRh('/--split/255.255.255.192/10.0.0.0/255.255.255.0'), ['--split', '255.255.255.192', '10.0.0.0/255.255.255.0']);
  assert.deepEqual(pathToArgvRh('/10.0.0.0/24/-j'), ['10.0.0.0/24', '-j']);
  assert.deepEqual(pathToArgvRh('/-d/10.0.0.1-10.0.0.9'), ['-d', '10.0.0.1-10.0.0.9']);
});

test('/ng/ serves Red Hat ipcalc output', async () => {
  const body = await (await get('/ng/192.168.0.1/24', 'curl/8.5.0')).text();
  assert.equal(body, 'Address:\t192.168.0.1\nNetwork:\t192.168.0.0/24\nNetmask:\t255.255.255.0 = 24\nBroadcast:\t192.168.0.255\n\nAddress space:\tPrivate Use\nHostMin:\t192.168.0.1\nHostMax:\t192.168.0.254\nHosts/Net:\t254\n');
  assert.equal((await get('/ng/-r/24', 'curl/8.5.0')).headers.get('cache-control'), 'no-store');
  assert.match(await (await get('/ng/-S/32/0.0.0.0/0', 'curl/8.5.0')).text(), /output truncated at 1 MiB\]\n$/);
});
