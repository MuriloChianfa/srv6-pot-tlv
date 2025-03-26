#!/bin/bash
set -e

rm -rf /var/run/frr/watchfrr.pid /var/tmp/frr/watchfrr.*
sysctl -p /etc/sysctl.mod.conf 2>/dev/null || true

echo "Starting FRR daemons (without watchfrr)..."
/usr/lib/frr/frrinit.sh start

#echo "Starting watchfrr in the foreground..."
#exec /usr/lib/frr/watchfrr -d -F traditional zebra staticd bgpd ospfd ospf6d isisd

exec "$@"
