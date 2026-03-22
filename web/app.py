#!/usr/bin/env python3
"""
ReconKit Web — Flask + SocketIO backend
Streams reconkit.py output live to the browser.
"""

import os
import re
import subprocess
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

# Path to reconkit.py — assumes it's in the same directory or on PATH
RECONKIT_PATH = Path(__file__).parent / "reconkit.py"

# Track active scans per session
active_scans = {}

ANSI_TO_CLASS = [
    (r"\033\[91m|\033\[38;5;208m", "c-red"),
    (r"\033\[92m",                  "c-green"),
    (r"\033\[93m",                  "c-yellow"),
    (r"\033\[94m",                  "c-blue"),
    (r"\033\[95m",                  "c-magenta"),
    (r"\033\[96m",                  "c-cyan"),
    (r"\033\[97m",                  "c-white"),
    (r"\033\[1m",                   "c-bold"),
    (r"\033\[2m",                   "c-dim"),
]
ANSI_STRIP = re.compile(r"\033\[[0-9;]*m")

def ansi_to_html(text):
    """Convert ANSI color codes to HTML spans."""
    # Build stack-based converter
    result = []
    i = 0
    open_spans = 0
    while i < len(text):
        if text[i] == '\033' and i + 1 < len(text) and text[i+1] == '[':
            end = text.find('m', i)
            if end == -1:
                result.append(text[i])
                i += 1
                continue
            code = text[i:end+1]
            if code in ('\033[0m', '\033[m'):
                result.append('</span>' * open_spans)
                open_spans = 0
            else:
                css_class = None
                for pattern, cls in ANSI_TO_CLASS:
                    if re.match(pattern, code):
                        css_class = cls
                        break
                if css_class:
                    result.append(f'<span class="{css_class}">')
                    open_spans += 1
            i = end + 1
        else:
            c = text[i]
            if c == '<': result.append('&lt;')
            elif c == '>': result.append('&gt;')
            elif c == '&': result.append('&amp;')
            else: result.append(c)
            i += 1
    result.append('</span>' * open_spans)
    return ''.join(result)

def classify_line(raw):
    """Return a line type for frontend styling."""
    clean = ANSI_STRIP.sub('', raw)
    if '[★]' in clean:    return 'finding'
    if '[+]' in clean:    return 'success'
    if '[!]' in clean:    return 'warn'
    if '[✗]' in clean:    return 'error'
    if '─' * 10 in clean: return 'section'
    if '═' * 10 in clean: return 'report'
    if '[*]' in clean:    return 'info'
    return 'output'

def run_scan(sid, target, flags):
    cmd = ["python3", str(RECONKIT_PATH), target] + flags
    socketio.emit("scan_start", {"target": target, "cmd": " ".join(cmd)}, to=sid)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        active_scans[sid] = proc

        for raw_line in proc.stdout:
            line = raw_line.rstrip()
            if not line:
                continue
            socketio.emit("scan_line", {
                "raw":   ANSI_STRIP.sub('', line),
                "html":  ansi_to_html(line),
                "type":  classify_line(line),
                "ts":    datetime.now().strftime("%H:%M:%S"),
            }, to=sid)

        proc.wait()
        code = proc.returncode
        socketio.emit("scan_done", {
            "code":    code,
            "target":  target,
            "outdir":  f"recon_for_{target}",
        }, to=sid)

    except Exception as e:
        socketio.emit("scan_error", {"msg": str(e)}, to=sid)
    finally:
        active_scans.pop(sid, None)


@app.route("/")
def index():
    return render_template("index.html")

@socketio.on("start_scan")
def handle_start_scan(data):
    sid    = request.sid
    target = (data.get("target") or "").strip()
    flags  = []

    if not re.match(r"^[\d.]+$", target):
        emit("scan_error", {"msg": "Invalid IP address"})
        return

    if data.get("vuln"):    flags.append("--vuln")
    if data.get("quick"):   flags.append("--quick")
    if data.get("resume"):  flags.append("--resume")
    if data.get("domain"):  flags += ["--domain", data["domain"].strip()]

    if sid in active_scans:
        emit("scan_error", {"msg": "A scan is already running"})
        return

    t = threading.Thread(target=run_scan, args=(sid, target, flags), daemon=True)
    t.start()

@socketio.on("stop_scan")
def handle_stop_scan():
    sid  = request.sid
    proc = active_scans.get(sid)
    if proc:
        proc.kill()
        active_scans.pop(sid, None)
        emit("scan_stopped", {})

@socketio.on("disconnect")
def handle_disconnect():
    proc = active_scans.pop(request.sid, None)
    if proc:
        proc.kill()


if __name__ == "__main__":
    print("\n  ReconKit Web — http://127.0.0.1:9001\n")
    socketio.run(app, host="0.0.0.0", port=9001, debug=False)