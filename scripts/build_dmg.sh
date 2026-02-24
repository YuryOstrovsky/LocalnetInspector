#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_PATH="$ROOT_DIR/dist/LocalnetInspector.app"
DMG_PATH="$ROOT_DIR/dist/LocalnetInspector.dmg"

if [ ! -d "$APP_PATH" ]; then
  echo "Missing app bundle: $APP_PATH"
  echo "Run scripts/build_app.sh first"
  exit 1
fi

if ! command -v create-dmg >/dev/null 2>&1; then
  echo "create-dmg not found. Install with: brew install create-dmg"
  exit 1
fi

rm -f "$DMG_PATH"

create-dmg \
  --volname "LocalnetInspector" \
  --window-pos 200 120 \
  --window-size 800 500 \
  --icon-size 100 \
  --icon "LocalnetInspector.app" 200 220 \
  --app-drop-link 600 220 \
  "$DMG_PATH" \
  "$ROOT_DIR/dist"

echo "DMG created at: $DMG_PATH"
