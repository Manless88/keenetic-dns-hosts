#!/bin/sh
# Keenetic DNS Hosts installer for Entware/Keenetic.
#
# Stable install:
#   curl -fsSL https://raw.githubusercontent.com/Manless88/keenetic-dns-hosts/main/scripts/install.sh | sh
#
# The script downloads the latest GitHub Release package and installs it with opkg.

set -e

REPO="Manless88/keenetic-dns-hosts"
PACKAGE="keenetic-dns-hosts"
TMP_DIR="/opt/tmp"
INIT="/opt/etc/init.d/S89keenetic-dns-hosts"

info() { printf "\033[1;32m[+]\033[0m %s\n" "$1"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$1"; }
fail() { printf "\033[1;31m[-]\033[0m %s\n" "$1"; exit 1; }

have() {
    command -v "$1" >/dev/null 2>&1
}

ensure_tool() {
    tool="$1"
    package="${2:-$1}"
    if have "$tool"; then
        return 0
    fi
    info "Installing dependency: $package"
    opkg update >/dev/null 2>&1 || warn "opkg update returned an error, continuing"
    opkg install "$package" || fail "Could not install $package"
}

download_to_stdout() {
    url="$1"
    if have curl; then
        curl -fsSL "$url"
    elif have wget; then
        wget -qO- "$url"
    else
        return 1
    fi
}

download_file() {
    url="$1"
    output="$2"
    if have curl; then
        curl -fL "$url" -o "$output"
    elif have wget; then
        wget -O "$output" "$url"
    else
        return 1
    fi
}

latest_version() {
    api="https://api.github.com/repos/${REPO}/releases/latest"
    tag="$(download_to_stdout "$api" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    [ -n "$tag" ] || fail "Could not get latest version from GitHub Releases"
    printf '%s\n' "${tag#v}"
}

show_access_url() {
    port="$(sed -n 's/^APP_PORT=//p' /opt/etc/keenetic-dns-hosts.conf 2>/dev/null | tail -n 1)"
    [ -n "$port" ] || port="3333"

    ip_addr="$(ip -4 addr show br0 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | head -n 1)"
    [ -n "$ip_addr" ] || ip_addr="<router-ip>"

    echo ""
    info "Keenetic DNS Hosts: http://${ip_addr}:${port}/"
    echo ""
}

[ -d /opt ] || fail "/opt not found. Install Entware first."
have opkg || fail "opkg not found. This script must run on an Entware-enabled router."

ensure_tool curl curl

version="${VERSION:-$(latest_version)}"
asset="${PACKAGE}_${version}.ipk"
asset_gz="${asset}.gz"
url="https://github.com/${REPO}/releases/download/v${version}/${asset}"
url_gz="https://github.com/${REPO}/releases/download/v${version}/${asset_gz}"

mkdir -p "$TMP_DIR"
target="${TMP_DIR}/${asset}"
target_gz="${TMP_DIR}/${asset_gz}"

info "Downloading ${asset}"
if ! download_file "$url" "$target"; then
    warn "Could not download ${asset}; trying ${asset_gz}"
    download_file "$url_gz" "$target_gz" || fail "Could not download package from GitHub Releases"
    have gzip || fail "gzip is required to unpack ${asset_gz}"
    gzip -dc "$target_gz" > "$target" || fail "Could not unpack ${asset_gz}"
fi

info "Installing ${PACKAGE} ${version}"
opkg install "$target" || fail "Could not install package"

if [ -x "$INIT" ]; then
    "$INIT" restart >/dev/null 2>&1 || warn "Could not restart service automatically"
    "$INIT" status >/dev/null 2>&1 || warn "Service is not responding. Check log: /opt/var/log/keenetic-dns-hosts.log"
fi

show_access_url
