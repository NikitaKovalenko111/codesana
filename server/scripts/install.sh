#!/bin/sh
set -e

VERSION="v.0.5.0"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="amd64" ;;
esac

URL="https://github.com/NikitaKovalenko111/codesana/releases/download/${VERSION}/codesana_${OS}_${ARCH}"

curl -L "$URL" -o codesana

chmod +x codesana

mkdir -p "$HOME/.local/bin"
mv codesana "$HOME/.local/bin/"

echo "Installed to $HOME/.local/bin/codesana"