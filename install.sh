#!/bin/bash
set -euo pipefail

REPO="UltraDarshan/vibeshield"
VERSION="${VIBESHIELD_VERSION:-latest}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) ARCH="unsupported" ;;
esac

if [ "$OS" != "linux" ] && [ "$OS" != "darwin" ] || [ "$ARCH" = "unsupported" ]; then
    echo "No prebuilt binary for $(uname -s)/$(uname -m). Download one from https://github.com/${REPO}/releases or build with: go install github.com/${REPO}/cmd/vibeshield@latest" >&2
    exit 1
fi

TARGET_BIN="vibeshield-${OS}-${ARCH}"
if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${TARGET_BIN}"
else
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARGET_BIN}"
fi

INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

echo "[VibeShield] Downloading ${TARGET_BIN} (${VERSION})..."
# -f: fail on HTTP errors instead of saving a "Not Found" page as the binary
curl -fsSL "$DOWNLOAD_URL" -o "$TMP"
chmod +x "$TMP"
mv "$TMP" "${INSTALL_DIR}/vibeshield"

echo "✔ VibeShield installed to ${INSTALL_DIR}/vibeshield"
case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *) echo "  Note: ${INSTALL_DIR} is not on your PATH. Add: export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
echo ""
echo "Run it anywhere with:"
echo "  vibeshield scan ."
