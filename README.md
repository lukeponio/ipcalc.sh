# ipcalc.sh

`curl ipcalc.sh/<args>` returns exactly what `ipcalc <args> | cat` prints.

Baseline: **ipcalc 0.51** by Krischan Jodies, the Perl `ipcalc` shipped by
Debian and Ubuntu (`apt install ipcalc`, package `ipcalc_0.51-1`). Not the Red
Hat/Fedora `ipcalc`, which is a different program with different output.

```
curl ipcalc.sh/192.168.0.1/24              # ipcalc 192.168.0.1/24
curl ipcalc.sh/192.168.0.1/255.255.128.0   # dotted or wildcard masks
curl ipcalc.sh/10.0.0.0/20/24              # ipcalc 10.0.0.0/20 24   (subnets)
curl ipcalc.sh/10.0.0.0/16/8               # supernet
curl ipcalc.sh/10.0.0.1-10.0.0.77          # deaggregate a range
curl ipcalc.sh/10.0.0.0/24/-s/10/20/30     # split by host counts
curl ipcalc.sh/-b/10.0.0.0/8               # any ipcalc flag: -b -c -h -r -v --class --help
curl "ipcalc.sh/10.0.0.0/24+-s+10+20"      # + or %20 also separate words
```

Each path segment is one argv word. ipcalc itself splits `a/b` into two
arguments, so `/10.0.0.0/24` and `ipcalc 10.0.0.0/24` are the same input.
Colour is off by default (like a pipe); `/-c/...` turns ANSI colour on.

## Red Hat / Fedora ipcalc at `/ng/`

`curl ipcalc.sh/ng/<args>` returns what the Red Hat `ipcalc` 1.0.3 (Fedora,
RHEL, CentOS; `ipcalc-ng` on Debian) shows in a terminal: stdout and stderr
together, in order.

```
curl ipcalc.sh/ng/192.168.0.1/24              # ipcalc 192.168.0.1/24
curl ipcalc.sh/ng/2001:db8::1/64              # IPv6
curl ipcalc.sh/ng/--all-info/8.8.8.8/24       # reverse DNS name, class
curl ipcalc.sh/ng/-S/26/10.0.0.0/24           # split into /26s
curl ipcalc.sh/ng/-d/10.0.0.1-10.0.0.77       # range to CIDRs
curl ipcalc.sh/ng/-j/10.0.0.0/30              # JSON
curl ipcalc.sh/ng/-n/-b/10.0.0.0/8            # NETWORK=... shell variables
curl ipcalc.sh/ng/-r/24                       # random private network (never cached)
```

Here `addr/prefix` stays one word (Red Hat ipcalc rejects an IPv6 address and
prefix given separately), so `/ng/2001:db8::/32` works.

Reference: upstream 1.0.3 built as Fedora ships it, with GeoIP support but no
GeoLite2 databases (so `-g` prints nothing). Debian's `ipcalc-ng` renames the
program in its messages, so `test/rh/build-reference.sh` builds upstream instead.
Differences on the web: `-h`/`--hostname` and `-o`/`--lookup-host` need DNS and
are refused with a message; output stops at 1 MiB (`-S 32 0.0.0.0/0` would be
4 billion lines). Crashes in the real tool are reproduced as what a terminal
shows (`--reverse-dns` on a /0-/7 segfaults, a full-range IPv6 `-d` aborts).

Browsers on ipcalc.sh are redirected to `https://subnetting.io/?q=<path>`.

## Layout

- `src/ipcalc.js` the faithful port. Quirks are kept on purpose (see below). Do not change its output.
- `src/ipcalc-rh.js` port of Red Hat ipcalc 1.0.3, served at `/ng/`. `test/rh/` holds its golden file, fuzzer and reference build script.
- `src/worker.js` Cloudflare Worker: URL to argv, User-Agent routing.
- `test/golden.json` real ipcalc output for ~3,000 inputs. `test/golden.test.mjs` checks the port against it.
- `test/fuzz.mjs` live differential fuzz against the real Perl tool.

## Keeping the baseline

```
npm test                     # golden + worker tests, no Perl needed
sudo apt install ipcalc      # needed only for the two below
npm run fuzz -- 2000         # fresh random inputs vs the real tool
npm run golden               # regenerate golden.json after adding cases to test/cases.mjs
test/rh/build-reference.sh   # Red Hat reference build (needs gcc), then:
node test/rh/fuzz.mjs 3000   # fresh random inputs vs the Red Hat build
node test/rh/gen-golden.mjs  # regenerate test/rh/golden.json
```

New features must not change output for anything ipcalc already accepts. Put
them in new code paths (new URL forms or new flags that ipcalc rejects today)
and keep `npm test` green.

## Faithfully reproduced quirks

- `WILDCARD` is printed when a mask is given in wildcard form; `0.0.0.0` as a mask is rejected.
- A bare 8-digit hex address (`0a000001`) is read as IPv6 and rejected; `0x0a000001` works.
- `-c` means colour, so the documented `-c` for class is unreachable; `--class` works and prints no newline.
- Wildcard mask1 with a shorter mask2 prints `Subnets: NaN` (Perl bignum NaN).
- Huge `-s` sizes print `-1 hosts` and stop at `HostMax:` where Perl dies (exit 255 is in the `x-ipcalc-exit` header).
- The "In Part ..." label for blocks containing several special ranges depends on Perl's random hash order, so it differs between runs of the real tool. The port uses source order; the tests accept any variant the real tool produces.
- `ipcalc 0.0.0.0 - 255.255.255.255` (and IPv6 ranges starting at `::`) loops forever in the real tool. The port stops and returns the header line.

## Input safety (deliberate deviations, web only)

- Input is never executed: no shell, no eval, no storage. The path becomes an argv array for a pure function.
- Bytes outside printable ASCII become `?` before ipcalc sees them. No valid input contains them, and the CLI would echo them raw in `INVALID ADDRESS:` lines, which lets a crafted link send terminal escape codes to whoever curls it.
- Paths over 1024 bytes get `414`. Real inputs are under 100 bytes; this caps CPU for things like thousands of `-s` sizes.
- Responses are `text/plain` with `nosniff`, so echoed input can't run as HTML in a browser.

## Deploy

```
npx wrangler deploy
```

## License

GPL-2.0-only. `src/ipcalc.js` translates ipcalc 0.51 (GPL-2.0-or-later) and
`src/ipcalc-rh.js` translates Red Hat ipcalc 1.0.3 (GPL-2.0-only).
