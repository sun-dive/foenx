#!/bin/sh
# Deploy foen to the VPS: the page, the modules and relay.php into /srv/sites/<name>, tips in
# /srv/sites/foen-data (relay.php looks for that sibling of its docroot), and a Caddy site file.
#   sh tools/vps-deploy.sh [name] [host]      defaults: foen.xyz  sundive@198.13.50.9
# Streaming: php_fastcgi is a reverse proxy underneath, so flush_interval -1 lets each flush through.
set -eu
cd "$(dirname "$0")/.."
NAME=${1:-foen.xyz}
HOST=${2:-sundive@198.13.50.9}
KEY=${KEY:-$HOME/.ssh/foen-vps}
SSH="ssh -i $KEY -o BatchMode=yes $HOST"
REV=$(git rev-parse --short HEAD)

tar -czf - -C site index.html test.html .htaccess manifest.webmanifest icon.svg icon-192.png icon-512.png help.html privacy.html terms.html contact.html pages.css robots.txt js -C ../server relay.php book.php | $SSH "
  set -e
  sudo install -d -m 755 -o sundive -g sundive /srv/sites/$NAME
  sudo install -d -m 770 -o www-data -g www-data /srv/sites/foen-data
  tar -xzf - -C /srv/sites/$NAME
  rm -f /srv/sites/$NAME/.htaccess
  echo '$REV' > /srv/sites/$NAME/version.txt
  sed -i 's|https://foen.xyz/sitemap.xml|https://$NAME/sitemap.xml|' /srv/sites/$NAME/robots.txt
  printf '<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n' > /srv/sites/$NAME/sitemap.xml
  for p in '' help.html privacy.html terms.html contact.html; do printf '  <url><loc>https://$NAME/%s</loc></url>\n' \"\$p\" >> /srv/sites/$NAME/sitemap.xml; done
  printf '</urlset>\n' >> /srv/sites/$NAME/sitemap.xml
  sudo tee /etc/caddy/sites/$NAME.caddy > /dev/null <<EOF
$NAME, www.$NAME {
	root * /srv/sites/$NAME
	encode gzip
	php_fastcgi unix//run/php/php8.4-fpm.sock {
		flush_interval -1
	}
	file_server
	header Cache-Control no-store
	@manifest path *.webmanifest
	header @manifest Content-Type application/manifest+json
}
EOF
  sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
  sudo systemctl reload caddy
  echo \"$NAME <- $REV on \$(hostname)\"
"
