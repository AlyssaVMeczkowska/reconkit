#!/usr/bin/env bash
# ReconKit Web launcher
# Place reconkit.py in the same directory as app.py before running

set -e
cd "$(dirname "$0")"

if ! python3 -c "import flask_socketio" 2>/dev/null; then
  echo "[*] Installing dependencies..."
  pip3 install -r requirements.txt --break-system-packages -q
fi

if [ ! -f "reconkit.py" ]; then
  echo "[!] reconkit.py not found in $(pwd)"
  echo "    Copy reconkit.py here and try again."
  exit 1
fi

echo ""
echo "  ReconKit Web — http://127.0.0.1:5000"
echo "  Ctrl+C to stop"
echo ""
python3 app.py