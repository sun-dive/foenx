#!/bin/sh
# One pass over a fresh Debian 13 VPS: lock it down, then install the web stack. Run as root on the server.
#   sh vps-setup.sh <admin user> "<ssh public key>"
# Lockdown first: a user with the key, sudo, SSH by key only with no root login, a firewall that admits
# 22/80/443 and nothing else, unattended security updates, fail2ban. Then Caddy (auto-HTTPS), PHP-FPM,
# SQLite. Sites are deployed separately, each in its own directory under /srv with data outside the docroot.
set -eu
USER_NAME=${1:?admin user}
PUBKEY=${2:?ssh public key}
export DEBIAN_FRONTEND=noninteractive

echo "== packages"
apt-get update -q
apt-get install -y -q sudo ufw fail2ban unattended-upgrades apt-listchanges curl gnupg debian-keyring debian-archive-keyring apt-transport-https ca-certificates

echo "== admin user with the key"
id "$USER_NAME" >/dev/null 2>&1 || adduser --disabled-password --gecos '' "$USER_NAME"
usermod -aG sudo "$USER_NAME"
install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "/home/$USER_NAME/.ssh"
printf '%s\n' "$PUBKEY" > "/home/$USER_NAME/.ssh/authorized_keys"
chown "$USER_NAME:$USER_NAME" "/home/$USER_NAME/.ssh/authorized_keys"; chmod 600 "/home/$USER_NAME/.ssh/authorized_keys"
printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$USER_NAME" > "/etc/sudoers.d/90-$USER_NAME"; chmod 440 "/etc/sudoers.d/90-$USER_NAME"

echo "== ssh: keys only, no root, no passwords"
cat > /etc/ssh/sshd_config.d/10-hardening.conf <<EOF
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
EOF
sshd -t && systemctl reload ssh

echo "== firewall"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp     # HTTP/3
ufw --force enable

echo "== updates + fail2ban"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
maxretry = 4
bantime = 1h
EOF
systemctl enable --now fail2ban

echo "== caddy (official repository)"
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
apt-get update -q
apt-get install -y -q caddy php-fpm php-sqlite3 php-cli sqlite3 git
PHPV=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
echo "php $PHPV"
# PHP-FPM for a relay: enough workers for long-polls, no output buffering so streaming flushes pass.
sed -i 's/^pm.max_children = .*/pm.max_children = 32/; s/^;pm.max_requests = .*/pm.max_requests = 500/' "/etc/php/$PHPV/fpm/pool.d/www.conf"
sed -i 's/^output_buffering = .*/output_buffering = Off/; s/^;*max_execution_time = .*/max_execution_time = 60/' "/etc/php/$PHPV/fpm/php.ini"
systemctl enable --now "php$PHPV-fpm"
systemctl restart "php$PHPV-fpm"

echo "== site directories"
install -d -m 755 /srv/sites
install -d -m 750 -o www-data -g www-data /srv/data
# Caddy loads every site file dropped here; sites are added as files, never by editing the main config.
install -d /etc/caddy/sites
grep -q 'import sites' /etc/caddy/Caddyfile 2>/dev/null || printf 'import /etc/caddy/sites/*.caddy\n' > /etc/caddy/Caddyfile
systemctl enable --now caddy
systemctl reload caddy

echo "== done"
echo "ssh: $USER_NAME with key, root and passwords off · ufw: 22 80 443 · caddy + php-fpm $PHPV ready · sites in /etc/caddy/sites, docroots in /srv/sites, data in /srv/data"
