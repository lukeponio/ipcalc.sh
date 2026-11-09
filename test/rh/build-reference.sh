#!/bin/sh
# Builds the reference Red Hat ipcalc 1.0.3 exactly as upstream ships it, with
# GeoIP support compiled in but no GeoLite2 databases (a stock Fedora box).
# Debian's ipcalc-ng renames the program in its messages, so it can't be used.
set -e
OUT=${1:-/opt/ipcalc-rh}
TMP=$(mktemp -d)
cd "$TMP"
curl -sSO http://archive.ubuntu.com/ubuntu/pool/universe/i/ipcalc-ng/ipcalc-ng_1.0.3.orig.tar.gz
tar xzf ipcalc-ng_1.0.3.orig.tar.gz
cd ipcalc-1.0.3
echo 'void geo_ip_lookup(const char *a, char **b, char **c, char **d, char **e) { (void)a; (void)b; (void)c; (void)d; (void)e; }' > geostub.c
mkdir -p "$OUT"
gcc -O2 -DVERSION='"1.0.3"' -DUSE_MAXMIND -o "$OUT/ipcalc" \
  ipcalc.c ipcalc-reverse.c ipcalc-utils.c netsplit.c ipv6.c deaggregate.c geostub.c 2>/dev/null
echo "built $OUT/ipcalc"
