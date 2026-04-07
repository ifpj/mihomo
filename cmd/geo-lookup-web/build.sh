#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST="$SCRIPT_DIR/dist"

GEOSITE_URL="https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat"
GEOIP_URL="https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geoip-lite.dat"

mkdir -p "$DIST"

# ── 1. Build WASM ─────────────────────────────────────────────────────────────
echo "==> Building WASM..."
GOOS=js GOARCH=wasm go build -o "$DIST/main.wasm" "$SCRIPT_DIR"

# ── 2. Copy wasm_exec.js ──────────────────────────────────────────────────────
echo "==> Copying wasm_exec.js..."
WASM_EXEC="$(go env GOROOT)/misc/wasm/wasm_exec.js"
[ ! -f "$WASM_EXEC" ] && WASM_EXEC="$(go env GOROOT)/lib/wasm/wasm_exec.js"
cp "$WASM_EXEC" "$DIST/wasm_exec.js"

# ── 3. Copy static files ──────────────────────────────────────────────────────
echo "==> Copying static files..."
cp "$SCRIPT_DIR/index.html" "$DIST/index.html"
cp "$SCRIPT_DIR/sw.js"      "$DIST/sw.js"

# ── 4. Download .dat files ────────────────────────────────────────────────────
echo "==> Downloading GeoSite.dat..."
curl -fL --progress-bar -o "$DIST/GeoSite.dat" "$GEOSITE_URL"

echo "==> Downloading GeoIP.dat..."
curl -fL --progress-bar -o "$DIST/GeoIP.dat" "$GEOIP_URL"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "Done. Output in $DIST:"
ls -lh "$DIST"
echo ""
echo "Zip and upload to Cloudflare Pages:"
echo "  cd $DIST && zip -r ../geo-lookup-web.zip ."
