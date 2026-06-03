#!/bin/sh
# Full Keenetic DNS Hosts uninstaller for Entware/Keenetic.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/Manless88/keenetic-dns-hosts/main/scripts/uninstall.sh | sh

set -e

PACKAGE="keenetic-dns-hosts"
INIT="/opt/etc/init.d/S89keenetic-dns-hosts"

info() { printf "\033[1;32m[+]\033[0m %s\n" "$1"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$1"; }

if [ -x "$INIT" ]; then
    info "Stopping service"
    "$INIT" stop >/dev/null 2>&1 || warn "Service stop returned an error, continuing"
fi

if command -v opkg >/dev/null 2>&1 && opkg status "$PACKAGE" >/dev/null 2>&1; then
    info "Removing Entware package: $PACKAGE"
    opkg remove "$PACKAGE" || warn "opkg remove returned an error, cleaning files manually"
fi

info "Removing application files, configuration, data and logs"
rm -rf /opt/share/keenetic-dns-hosts
rm -rf /opt/var/lib/keenetic-dns-hosts
rm -f /opt/etc/init.d/S89keenetic-dns-hosts
rm -f /opt/etc/keenetic-dns-hosts.conf
rm -f /opt/etc/keenetic-dns-hosts.conf.example
rm -f /opt/var/log/keenetic-dns-hosts.log
rm -f /opt/var/run/keenetic-dns-hosts.pid

echo ""
info "Keenetic DNS Hosts has been removed."
warn "DNS aliases already written to Keenetic ip host are router settings and were not removed automatically."
warn "Remove those aliases from the panel before uninstalling, or delete them manually in Keenetic CLI."
