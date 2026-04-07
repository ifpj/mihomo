#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST="$SCRIPT_DIR/dist"

GEOSITE_URL="https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat"
GEOIP_URL="https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geoip-lite.dat"

mkdir -p "$DIST"

# ── 1. Build WASM ─────────────────────────────────────────────────────────────
echo "==> Building WASM..."
GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o "$DIST/main.wasm" "$SCRIPT_DIR"
gzip -9 -c "$DIST/main.wasm" > "$DIST/main.wasm.bin" && rm "$DIST/main.wasm"

# ── 2. Copy wasm_exec.js ──────────────────────────────────────────────────────
echo "==> Copying wasm_exec.js..."
WASM_EXEC="$(go env GOROOT)/misc/wasm/wasm_exec.js"
[ ! -f "$WASM_EXEC" ] && WASM_EXEC="$(go env GOROOT)/lib/wasm/wasm_exec.js"
cp "$WASM_EXEC" "$DIST/wasm_exec.js"

# ── 3. Copy static files ──────────────────────────────────────────────────────
echo "==> Copying static files..."
cp "$SCRIPT_DIR/index.html" "$DIST/index.html"
cp "$SCRIPT_DIR/sw.js"      "$DIST/sw.js"

# ── 4. Download and gzip .dat files ──────────────────────────────────────────
echo "==> Downloading GeoSite.dat..."
curl -fL --progress-bar "$GEOSITE_URL" | gzip -9 > "$DIST/GeoSite.dat.bin"

echo "==> Downloading GeoIP.dat..."
curl -fL --progress-bar "$GEOIP_URL" | gzip -9 > "$DIST/GeoIP.dat.bin"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "Done. Output in $DIST:"
ls -lh "$DIST"
echo ""
echo "Zip and upload to Cloudflare Pages:"
echo "  cd $DIST && zip -r ../geo-lookup-web.zip ."
