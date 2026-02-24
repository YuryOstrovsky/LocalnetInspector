#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -x .venv/bin/python ]; then
  echo "Virtualenv not found. Run setup first."
  exit 1
fi

PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
QT_PLUGIN_PATH="$("$PYTHON_BIN" -c 'import PySide6; from pathlib import Path; print((Path(PySide6.__file__).resolve().parent/"Qt"/"plugins").as_posix())')"
QT_QPA_PLATFORM_PLUGIN_PATH="$QT_PLUGIN_PATH/platforms"

sudo -E env \
  PATH="$PATH" \
  QT_PLUGIN_PATH="$QT_PLUGIN_PATH" \
  QT_QPA_PLATFORM_PLUGIN_PATH="$QT_QPA_PLATFORM_PLUGIN_PATH" \
  "$PYTHON_BIN" -m localnet_inspector
