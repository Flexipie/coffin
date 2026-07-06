#!/bin/sh
# coffin installer: downloads the latest release binary for this
# platform and installs it. Usage:
#
#   curl -fsSL https://raw.githubusercontent.com/Flexipie/coffin/main/install.sh | sh
#
# Set COFFIN_INSTALL_DIR to override the target (default /usr/local/bin).
set -eu

REPO="Flexipie/coffin"
INSTALL_DIR="${COFFIN_INSTALL_DIR:-/usr/local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  darwin|linux) ;;
  *) echo "coffin installer: unsupported OS: $os" >&2; exit 1 ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "coffin installer: unsupported architecture: $arch" >&2; exit 1 ;;
esac

tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
  grep '"tag_name"' | head -1 | cut -d '"' -f 4)
if [ -z "$tag" ]; then
  echo "coffin installer: could not determine the latest release" >&2
  exit 1
fi
version=${tag#v}

url="https://github.com/$REPO/releases/download/$tag/coffin_${version}_${os}_${arch}.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading coffin $tag ($os/$arch)..."
curl -fsSL "$url" -o "$tmp/coffin.tar.gz"

sums_url="https://github.com/$REPO/releases/download/$tag/checksums.txt"
if curl -fsSL "$sums_url" -o "$tmp/checksums.txt" 2>/dev/null; then
  want=$(grep "coffin_${version}_${os}_${arch}.tar.gz" "$tmp/checksums.txt" | cut -d ' ' -f 1)
  if command -v shasum >/dev/null 2>&1; then
    got=$(shasum -a 256 "$tmp/coffin.tar.gz" | cut -d ' ' -f 1)
  else
    got=$(sha256sum "$tmp/coffin.tar.gz" | cut -d ' ' -f 1)
  fi
  if [ "$want" != "$got" ]; then
    echo "coffin installer: checksum mismatch, aborting" >&2
    exit 1
  fi
else
  echo "coffin installer: warning: could not fetch checksums.txt, skipping verification" >&2
fi

tar -xzf "$tmp/coffin.tar.gz" -C "$tmp" coffin

if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "$tmp/coffin" "$INSTALL_DIR/coffin"
else
  echo "Writing to $INSTALL_DIR needs sudo:"
  sudo install -m 0755 "$tmp/coffin" "$INSTALL_DIR/coffin"
fi

echo "Installed $("$INSTALL_DIR/coffin" version) to $INSTALL_DIR/coffin."
