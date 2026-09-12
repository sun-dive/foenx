#!/bin/sh
# THE DEVICE IS THE SERVER. Serve the page and the relay from this machine, over HTTPS, to the world.
#
#   sh tools/host.sh call.foen.xyz          # the public name that points at this machine
#
# What must be true outside this script (once):
#   1. DNS: an A record for the name → this connection's public IPv4 (check: curl -4 https://api.ipify.org).
#   2. Router: forward TCP 80 → this machine:8080 and TCP 443 → this machine:8443. Caddy listens on the
#      high ports so nothing here needs root; Let's Encrypt reaches it through the forwards.
# Then anyone opens https://<name>/ and the call runs through THIS device and no other server.
#
# Two processes: PHP's built-in server for the page and relay.php (8 workers, or posts queue behind
# long-polls), and Caddy in front for HTTPS with an automatic certificate.
set -e
cd "$(dirname "$0")/.."
NAME=${1:?usage: sh tools/host.sh <public name>}
CADDY=tools/bin/caddy
[ -x "$CADDY" ] || { echo "tools/bin/caddy is missing: download the linux_amd64 release from github.com/caddyserver/caddy/releases into tools/bin/"; exit 1; }
mkdir -p tools/bin/caddy-data
PHP_CLI_SERVER_WORKERS=8 php -S 127.0.0.1:8088 -t site tools/router.php > tools/bin/php.log 2>&1 &
PHP_PID=$!
trap 'kill $PHP_PID 2>/dev/null' EXIT INT TERM
echo "page + relay on 127.0.0.1:8088 (pid $PHP_PID); Caddy on :8080/:8443 for https://$NAME/"
XDG_DATA_HOME="$PWD/tools/bin/caddy-data" XDG_CONFIG_HOME="$PWD/tools/bin/caddy-data" \
exec "$CADDY" run --adapter caddyfile --config /dev/stdin <<EOF
{
	http_port 8080
	https_port 8443
}
$NAME {
	encode gzip
	reverse_proxy 127.0.0.1:8088 {
		flush_interval -1
	}
}
EOF
