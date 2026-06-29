#!/bin/sh
set -e

VERSION="v0.1.0"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
esac

URL="https://github.com/your-org/codesana/releases/download/${VERSION}/codesana-${OS}-${ARCH}"

curl -L "$URL" -o codesana

chmod +x codesana

mkdir -p "$HOME/.local/bin"
mv codesana "$HOME/.local/bin/"

echo "Installed to $HOME/.local/bin/codesana"