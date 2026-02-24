#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

source .venv/bin/activate

export PYINSTALLER_CONFIG_DIR="$ROOT_DIR/.pyinstaller-config"

pyinstaller \
  --noconfirm \
  --windowed \
  --name LocalnetInspector \
  --paths src \
  src/localnet_inspector/__main__.py

echo "App bundle created at: $ROOT_DIR/dist/LocalnetInspector.app"
