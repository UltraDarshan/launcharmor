#!/bin/bash
set -e

REPO="UltraDarshan/vibeshield"
VERSION="v0.1.0-alpha"

echo "[VibeShield] Downloading standalone binary for Linux (x86_64)..."

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

if [ "$OS" != "linux" ] || [ "$ARCH" != "x86_64" ]; then
    echo "Currently, this quick installer supports Linux x86_64. For Windows or other architectures, please download from: https://github.com/${REPO}/releases"
    exit 1
fi

TARGET_BIN="vibeshield-linux-amd64"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARGET_BIN}"

INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"

curl -sSL "$DOWNLOAD_URL" -o "${INSTALL_DIR}/vibeshield"
chmod +x "${INSTALL_DIR}/vibeshield"

echo "✔ VibeShield installed successfully to ${INSTALL_DIR}/vibeshield"
echo ""
echo "Run it anywhere with:"
echo "  vibeshield scan ."
