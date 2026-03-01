#!/usr/bin/env python3
"""
reconkit - ReconKit — Automated Recon & Enumeration
github.com/AlyssaVMeczkowska

Usage:
  python3 reconkit <target_ip> [options]

Options:
  --vuln          Run vuln scans (sqlmap, nmap vuln scripts, nuclei)
  --domain <d>    Domain for subdomain/vhost enumeration
  --quick         Fast mode — skip nikto, sqlmap, vuln scripts
  --no-parallel   Run sequentially instead of parallel web tasks
  --resume        Skip phases whose output files already exist
"""

import argparse
import os
import subprocess
import sys
import re
import shutil
import threading
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    ORANGE  = "\033[38;5;208m"
    DIM     = "\033[2m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗██╗████████╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║ ██╔╝██║╚══██╔══╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╔╝ ██║   ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔═██╗ ██║   ██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██╗██║   ██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝   ╚═╝
{C.RESET}  {C.MAGENTA}Automated Recon{C.RESET} {C.DIM}|{C.RESET} {C.CYAN}CTF{C.RESET}{C.DIM}/{C.RESET}{C.GREEN}THM{C.RESET}{C.DIM}/{C.RESET}{C.YELLOW}HTB{C.RESET} {C.MAGENTA}Edition{C.RESET}
  {C.MAGENTA}github.com{C.RESET}{C.DIM}/{C.RESET}{C.CYAN}AlyssaVMeczkowska{C.RESET} {C.DIM}|{C.RESET} {C.MAGENTA}use responsibly{C.RESET}
""")

def info(msg):    print(f"{C.BLUE}[*]{C.RESET} {msg}", flush=True)
def success(msg): print(f"{C.GREEN}[+]{C.RESET} {C.GREEN}{msg}{C.RESET}", flush=True)
def warn(msg):    print(f"{C.YELLOW}[!]{C.RESET} {C.YELLOW}{msg}{C.RESET}", flush=True)
def error(msg):   print(f"{C.RED}[✗]{C.RESET} {C.RED}{msg}{C.RESET}", flush=True)
def finding(msg): print(f"{C.MAGENTA}[★]{C.RESET} {C.BOLD}{C.MAGENTA}{msg}{C.RESET}", flush=True)
def phase_time(msg, elapsed): print(f"{C.DIM}    ↳ {msg} completed in {elapsed}{C.RESET}", flush=True)
def section(msg): print(f"\n{C.CYAN}{C.BOLD}{'─'*55}\n  {msg}\n{'─'*55}{C.RESET}", flush=True)


# ─────────────────────────────────────────
#  CONFIG  — edit these to match your system
# ─────────────────────────────────────────
# Auto-detect rustscan binary — checks PATH first, then common locations
def _find_rustscan():
    # Check PATH first
    found = shutil.which("rustscan")
    if found:
        return found
    # Common fallback locations
    candidates = [
        Path.home() / ".cargo/bin/rustscan",
        Path("/usr/local/bin/rustscan"),
        Path("/usr/bin/rustscan"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None

RUSTSCAN_BIN = _find_rustscan()

def _find_wordlist(*candidates):
    """Return the first wordlist path that exists, or None."""
    for c in candidates:
        if Path(c).exists():
            return c
    return None

# Common wordlist search locations across Kali, Parrot, BlackArch, etc.
_WL_ROOTS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/opt/wordlists",
    str(Path.home() / "wordlists"),
]

DIR_WORDLIST = _find_wordlist(
    *[f"{r}/dirbuster/directory-list-2.3-medium.txt" for r in _WL_ROOTS],
    *[f"{r}/Discovery/Web-Content/directory-list-2.3-medium.txt" for r in _WL_ROOTS],
)
DNS_WORDLIST = _find_wordlist(
    *[f"{r}/SecLists/Discovery/DNS/subdomains-top1million-5000.txt" for r in _WL_ROOTS],
    *[f"{r}/Discovery/DNS/subdomains-top1million-5000.txt" for r in _WL_ROOTS],
)
FALLBACK_WL = _find_wordlist(
    *[f"{r}/dirb/common.txt" for r in _WL_ROOTS],
    *[f"{r}/dirb/big.txt" for r in _WL_ROOTS],
)

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "123456"), ("root", "root"), ("root", "toor"),
    ("guest", "guest"), ("test", "test"), ("admin", ""), ("", ""),
]

COMMON_PORTS   = {21,22,23,25,53,80,110,139,143,443,445,
                  3306,3389,5432,5900,6379,8080,8443,8888,27017}
HTTP_PORTS     = {80, 8080, 8000, 8888}
HTTPS_PORTS    = {443, 8443}
SMB_PORTS      = {445, 139}
FTP_PORTS      = {21}
SSH_PORTS      = {22}
SQL_PORTS      = {3306, 5432}
REDIS_PORTS    = {6379}
MONGO_PORTS    = {27017}
KERBEROS_PORTS = {88}
RDP_PORTS      = {3389}
VNC_PORTS      = {5900, 5901}
SNMP_SENTINEL  = 999161   # fake port used as flag when UDP 161 found


# ─────────────────────────────────────────
#  STREAM HIGHLIGHT PATTERNS
# ─────────────────────────────────────────
_HIGHLIGHTS = [
    (r"CVE-\d{4}-\d+",                                                       C.RED),
    (r"VULNERABLE",                                                           C.RED),
    (r"anonymous\s*ftp|anonymous login allowed",                              C.RED),
    (r"No authentication",                                                    C.RED),
    (r"Status:\s*200[^\n]*",                                                  C.GREEN),
    (r"Status:\s*(301|302|401|403)[^\n]*",                                    C.YELLOW),
    (r"Open\s+[\d.]+:\d+",                                                    C.GREEN),
    (r"\d+/tcp\s+open\s+\S+[^\n]*",                                          C.GREEN),
    (r"\d+/udp\s+open\s+\S+[^\n]*",                                          C.GREEN),
    (r"(ssh|openssh)\s+[\d.]+[^\n]*",                                        C.CYAN),
    (r"Apache[\s/][\d.]+[^\n]*",                                             C.GREEN),
    (r"nginx[\s/][\d.]+[^\n]*",                                              C.GREEN),
    (r"WordPress|Drupal|Joomla|Magento",                                     C.YELLOW),
    (r"(mysql|postgresql|mariadb)[^\n]*",                                    C.MAGENTA),
    (r"(smb|samba|microsoft-ds)[^\n]*",                                      C.YELLOW),
    (r"redis_version|unauthenticated",                                       C.RED),
    (r"\+[^\n]*(admin|login|config|backup|password|secret|\.bak|\.old)[^\n]*",C.RED),
    (r"\[med\].*|\[high\].*|\[crit\].*",                                     C.RED),
    (r"X-Powered-By:[^\n]*",                                                 C.YELLOW),
    (r"^Server:[^\n]*",                                                      C.CYAN),
]

def _highlight_line(line):
    for pattern, color in _HIGHLIGHTS:
        if re.search(pattern, line, re.IGNORECASE):
            finding(f"{color}{line.strip()}{C.RESET}")
            return


# ─────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────
def check_tool(name):
    if shutil.which(name) is None:
        warn(f"{name} not found in PATH — skipping")
        return False
    return True

def notify(title, body):
    try:
        subprocess.run(["notify-send", "-i", "dialog-information",
                        "-t", "8000", title, body], capture_output=True)
    except Exception:
        pass

def elapsed_str(start):
    secs = int((datetime.now() - start).total_seconds())
    return f"{secs//60}m {secs%60}s"

def skip_if_exists(path, label):
    if Path(path).exists() and Path(path).stat().st_size > 0:
        warn(f"[resume] Skipping {label} — output already exists")
        return True
    return False

def run(cmd, outfile=None, shell=False, timeout=600, stream=True, label=None):
    display = label or (cmd if isinstance(cmd, str) else " ".join(str(x) for x in cmd))
    info(f"Running: {C.WHITE}{display}{C.RESET}")
    collected = []
    fh = open(outfile, "w") if outfile else None
    try:
        proc = subprocess.Popen(
            cmd, shell=shell,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        timer = threading.Timer(timeout, proc.kill)
        timer.start()
        try:
            for line in proc.stdout:
                collected.append(line)
                if fh:
                    fh.write(line); fh.flush()
                if stream:
                    print(f"  {C.DIM}{line.rstrip()}{C.RESET}", flush=True)
                _highlight_line(line)
        finally:
            timer.cancel()
        proc.wait()
    except FileNotFoundError:
        error(f"Tool not found: {cmd[0] if isinstance(cmd, list) else cmd.split()[0]}")
    finally:
        if fh:
            fh.close()
    return "".join(collected)

def run_parallel(tasks):
    threads = [threading.Thread(target=fn, args=a, daemon=True) for fn, a in tasks]
    for t in threads: t.start()
    for t in threads: t.join()


# ─────────────────────────────────────────
#  PHASE 1 — RUSTSCAN + UDP
# ─────────────────────────────────────────
def run_rustscan(target, outdir, resume=False):
    section("PHASE 1 — RustScan (TCP) + UDP Scan")
    start = datetime.now()

    if not RUSTSCAN_BIN:
        error("rustscan not found! Install it: cargo install rustscan")
        error("Or add it to your PATH and retry.")
        sys.exit(1)

    open_ports = set()

    rs_out = f"{outdir}/rustscan.txt"
    if resume and skip_if_exists(rs_out, "rustscan"):
        output = Path(rs_out).read_text()
    else:
        output = run([
            RUSTSCAN_BIN, "-a", target, "--ulimit", "5000",
            "--", "-sC", "-sV",
            "-oN", f"{outdir}/nmap_services.txt",
            "-oX", f"{outdir}/nmap_services.xml"
        ], outfile=rs_out, timeout=300, label="rustscan → nmap -sC -sV")

    for m in re.finditer(r"(\d+)/tcp\s+open", output):
        open_ports.add(int(m.group(1)))
    for m in re.finditer(r"Open [^:]+:(\d+)", output):
        open_ports.add(int(m.group(1)))

    # UDP top 20
    udp_out = f"{outdir}/nmap_udp.txt"
    if check_tool("nmap") and not (resume and skip_if_exists(udp_out, "UDP scan")):
        udp_out_data = run(
            ["nmap", "-sU", "--top-ports", "20", "-oN", udp_out, target],
            timeout=180, label="nmap UDP top 20"
        )
        if re.search(r"161/udp\s+open", udp_out_data):
            open_ports.add(SNMP_SENTINEL)
            finding(f"{C.YELLOW}[UDP] SNMP port 161 is open!{C.RESET}")

    tcp_ports = sorted(p for p in open_ports if p < 99999)
    if tcp_ports:
        success(f"Open TCP ports: {C.BOLD}{tcp_ports}{C.RESET}")
    else:
        warn("No open ports parsed — check rustscan.txt manually")

    phase_time("Port scan", elapsed_str(start))
    notify("reconkit — Ports found", f"{target}: {tcp_ports}")
    return open_ports


# ─────────────────────────────────────────
#  PHASE 2 — WEB ENUM
# ─────────────────────────────────────────
def _fetch_web_file(base_url, path, outdir, proto, port):
    """Silently try to fetch a well-known file and save it if found."""
    import base64
    try:
        req = urllib.request.Request(
            f"{base_url}/{path}",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            if r.status == 200:
                body = r.read(8192).decode(errors="replace")
                safe = path.replace("/", "_").replace(".", "_")
                out  = f"{outdir}/web_{proto}_{port}_{safe}.txt"
                Path(out).write_text(body)
                finding(f"{C.YELLOW}[{path}] Found and saved → {out}{C.RESET}")
                for line in body.splitlines()[:8]:
                    if line.strip():
                        print(f"  {C.DIM}{line}{C.RESET}", flush=True)
    except Exception:
        pass

LOGIN_PATH_PATTERNS = re.compile(
    r"(login|signin|sign-in|admin|administrator|wp-login|wp-admin|"
    r"auth|portal|dashboard|manager|phpmyadmin|pma|console|panel|cpanel|"
    r"account|user/login|users/login)",
    re.IGNORECASE
)

def _parse_found_paths(outdir, proto, port):
    """Parse gobuster or feroxbuster output and return list of found URLs."""
    found = []
    for fname in [
        f"feroxbuster_{proto}_{port}.txt",
        f"gobuster_{proto}_{port}.txt",
    ]:
        fpath = Path(outdir) / fname
        if not fpath.exists():
            continue
        for line in fpath.read_text().splitlines():
            # feroxbuster: "200      GET  ... http://..."
            # gobuster:    "/path (Status: 200)"
            url_match  = re.search(r"(https?://\S+)", line)
            path_match = re.search(r"^(/\S+)\s", line)
            if url_match:
                found.append(url_match.group(1).rstrip("/"))
            elif path_match:
                found.append(path_match.group(1).rstrip("/"))
    return found

def _check_default_creds(base_url, proto, port, outdir):
    """
    After dir enum finishes, look through its output for login-looking paths.
    For each one: try HTTP Basic Auth if it returns 401, otherwise note it
    for manual review. Does NOT attempt form POST bruteforce (that's hydra's job).
    """
    import base64

    found_paths = _parse_found_paths(outdir, proto, port)
    login_paths = [p for p in found_paths if LOGIN_PATH_PATTERNS.search(p)]

    if not login_paths:
        return  # nothing that looks like a login page found

    info(f"[Default Creds] Login-looking paths found: {login_paths}")
    results = []

    for path in login_paths:
        # Build full URL — handle both full URLs and path-only strings
        if path.startswith("http"):
            url = path
        else:
            url = f"{base_url}{path}"

        # Probe with no creds first
        status = None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                status = r.status
        except urllib.error.HTTPError as e:
            status = e.code
        except Exception:
            continue

        if status == 401:
            # HTTP Basic Auth — try default creds
            info(f"[Default Creds] Basic Auth challenge at {url} — trying defaults...")
            for user, passwd in DEFAULT_CREDS:
                try:
                    cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
                    req2 = urllib.request.Request(
                        url,
                        headers={"Authorization": f"Basic {cred}", "User-Agent": "Mozilla/5.0"}
                    )
                    with urllib.request.urlopen(req2, timeout=5) as r2:
                        if r2.status == 200:
                            hit = f"Basic Auth {user}:{passwd} @ {url}"
                            finding(f"{C.RED}[Default Creds] SUCCESS: {hit}{C.RESET}")
                            results.append(hit)
                except Exception:
                    pass

        elif status in (200, 302, 301, 403):
            # Form-based login — flag for manual review, don't attempt blind POST
            finding(f"{C.YELLOW}[Login Page] {url} (HTTP {status}) — check manually / run hydra{C.RESET}")
            results.append(f"Login page (HTTP {status}): {url}")

    if results:
        Path(f"{outdir}/login_pages_{proto}_{port}.txt").write_text("\n".join(results))

def phase_web(target, port, proto, outdir, quick=False, resume=False):
    section(f"WEB ENUM — {proto.upper()}://{target}:{port}")
    start    = datetime.now()
    base_url = f"{proto}://{target}:{port}"
    ssl_flag = ["-k"] if proto == "https" else []

    # ── Well-known files ──────────────────
    for path in ["robots.txt", "sitemap.xml", ".htaccess", "crossdomain.xml", "security.txt"]:
        _fetch_web_file(base_url, path, outdir, proto, port)

    # ── curl header grab ──────────────────
    if check_tool("curl"):
        run(["curl", "-sI", "--max-time", "10"] + ssl_flag + [base_url],
            outfile=f"{outdir}/headers_{proto}_{port}.txt",
            timeout=15, label=f"curl headers {proto}:{port}")

    # ── WhatWeb ───────────────────────────
    if check_tool("whatweb"):
        ww_out = f"{outdir}/whatweb_{proto}_{port}.txt"
        if not (resume and skip_if_exists(ww_out, f"whatweb {proto}:{port}")):
            run(["whatweb", "--color=never", "-a", "3", base_url],
                outfile=ww_out, timeout=60, label=f"whatweb {proto}:{port}")

    # ── WAF detection ─────────────────────
    if check_tool("wafw00f"):
        waf_out = f"{outdir}/wafw00f_{proto}_{port}.txt"
        if not (resume and skip_if_exists(waf_out, "wafw00f")):
            run(["wafw00f", base_url],
                outfile=waf_out, timeout=30, label=f"wafw00f {proto}:{port}")

    # ── Dir enum: feroxbuster > gobuster ──
    if check_tool("feroxbuster"):
        fb_out = f"{outdir}/feroxbuster_{proto}_{port}.txt"
        if not (resume and skip_if_exists(fb_out, f"feroxbuster {proto}:{port}")):
            wl = DIR_WORDLIST if os.path.exists(DIR_WORDLIST) else FALLBACK_WL
            run([
                "feroxbuster", "-u", base_url, "-w", wl,
                "-t", "50", "-o", fb_out, "--no-state", "-q",
            ] + ssl_flag, timeout=600, label=f"feroxbuster {proto}:{port}")
    elif check_tool("gobuster"):
        gb_out = f"{outdir}/gobuster_{proto}_{port}.txt"
        if not (resume and skip_if_exists(gb_out, f"gobuster {proto}:{port}")):
            wl = DIR_WORDLIST if os.path.exists(DIR_WORDLIST) else FALLBACK_WL
            if os.path.exists(wl):
                run([
                    "gobuster", "dir", "-u", base_url, "-w", wl,
                    "-t", "50", "-o", gb_out, "--no-error", "-q",
                ] + ssl_flag, timeout=600, label=f"gobuster {proto}:{port}")

    # ── Default cred check ────────────────
    _check_default_creds(base_url, proto, port, outdir)

    if quick:
        phase_time(f"Web enum {proto}:{port} (quick)", elapsed_str(start))
        return

    # ── Nikto ─────────────────────────────
    if check_tool("nikto"):
        nikto_out = f"{outdir}/nikto_{proto}_{port}.txt"
        if not (resume and skip_if_exists(nikto_out, f"nikto {proto}:{port}")):
            run(["nikto", "-h", base_url, "-o", nikto_out,
                 "-Format", "txt", "-maxtime", "300"]
                + (["-ssl"] if proto == "https" else []),
                timeout=360, label=f"nikto {proto}:{port}")

    # ── Nuclei ────────────────────────────
    if check_tool("nuclei"):
        nc_out = f"{outdir}/nuclei_{proto}_{port}.txt"
        if not (resume and skip_if_exists(nc_out, f"nuclei {proto}:{port}")):
            run([
                "nuclei", "-u", base_url,
                "-t", "cves/,exposures/,misconfiguration/",
                "-o", nc_out, "-silent"
            ], timeout=300, label=f"nuclei {proto}:{port}")

    # ── Gowitness screenshot ──────────────
    if check_tool("gowitness"):
        gw_out = f"{outdir}/screenshots"
        os.makedirs(gw_out, exist_ok=True)
        run(["gowitness", "single", "-u", base_url, "--destination", gw_out],
            timeout=30, stream=False, label=f"gowitness {proto}:{port}")
        success(f"Screenshot → {gw_out}/")

    # ── WordPress → wpscan ───────────────
    ww_file = f"{outdir}/whatweb_{proto}_{port}.txt"
    if os.path.exists(ww_file) and re.search(r"WordPress", Path(ww_file).read_text(), re.I):
        finding(f"{C.YELLOW}[WordPress detected on {proto}:{port}] Running wpscan...{C.RESET}")
        if check_tool("wpscan"):
            run([
                "wpscan", "--url", base_url,
                "--enumerate", "u,p,t", "--no-banner",
                "-o", f"{outdir}/wpscan_{proto}_{port}.txt",
            ] + (["--disable-tls-checks"] if proto == "https" else []),
                timeout=300, label=f"wpscan {proto}:{port}")

    phase_time(f"Web enum {proto}:{port}", elapsed_str(start))
    notify("reconkit — Web enum done", f"{proto}://{target}:{port} finished")


# ─────────────────────────────────────────
#  PHASE 2 — OTHER SERVICES
# ─────────────────────────────────────────
def phase_smb(target, outdir, resume=False):
    section("SMB ENUM")
    start = datetime.now()
    if check_tool("enum4linux"):
        out = f"{outdir}/enum4linux.txt"
        if not (resume and skip_if_exists(out, "enum4linux")):
            run(["enum4linux", "-A", target], outfile=out, timeout=300, label="enum4linux -A")
    if check_tool("smbclient"):
        out = f"{outdir}/smb_shares.txt"
        if not (resume and skip_if_exists(out, "smbclient")):
            run(["smbclient", "-L", f"//{target}", "-N"],
                outfile=out, timeout=60, label="smbclient list shares")
    if check_tool("nmap"):
        run(["nmap", "-p", "445", "--script", "smb-vuln*,smb-enum-shares,smb-enum-users",
             "-oN", f"{outdir}/nmap_smb.txt", target],
            timeout=120, label="nmap smb scripts")
    phase_time("SMB enum", elapsed_str(start))

def phase_ftp(target, outdir, resume=False):
    section("FTP ENUM")
    start = datetime.now()
    out   = f"{outdir}/nmap_ftp.txt"
    if check_tool("nmap") and not (resume and skip_if_exists(out, "nmap ftp")):
        run(["nmap", "-p", "21", "--script", "ftp-anon,ftp-bounce,ftp-syst",
             "-oN", out, target], timeout=60, label="nmap ftp scripts")
    phase_time("FTP enum", elapsed_str(start))

def phase_ssh(target, port, outdir, resume=False):
    section(f"SSH ENUM — port {port}")
    start = datetime.now()
    if check_tool("nmap"):
        out = f"{outdir}/nmap_ssh_{port}.txt"
        if not (resume and skip_if_exists(out, f"nmap ssh {port}")):
            run(["nmap", "-p", str(port), "--script", "ssh-auth-methods,ssh-hostkey",
                 "-oN", out, target], timeout=60, label=f"nmap ssh port {port}")
    phase_time(f"SSH enum port {port}", elapsed_str(start))

def phase_sql(target, port, outdir, resume=False):
    section(f"SQL ENUM — port {port}")
    start  = datetime.now()
    script = "mysql-empty-password,mysql-info" if port == 3306 else "pgsql-brute"
    if check_tool("nmap"):
        out = f"{outdir}/nmap_sql_{port}.txt"
        if not (resume and skip_if_exists(out, f"nmap sql {port}")):
            run(["nmap", "-p", str(port), "--script", script,
                 "-oN", out, target], timeout=60, label=f"nmap sql port {port}")
    phase_time(f"SQL enum port {port}", elapsed_str(start))

def phase_redis(target, outdir, resume=False):
    section("REDIS ENUM")
    start = datetime.now()
    if check_tool("nmap"):
        out = f"{outdir}/nmap_redis.txt"
        if not (resume and skip_if_exists(out, "redis")):
            run(["nmap", "-p", "6379", "--script", "redis-info",
                 "-oN", out, target], timeout=60, label="nmap redis-info")
    phase_time("Redis enum", elapsed_str(start))

def phase_mongo(target, outdir, resume=False):
    section("MONGODB ENUM")
    start = datetime.now()
    if check_tool("nmap"):
        out = f"{outdir}/nmap_mongo.txt"
        if not (resume and skip_if_exists(out, "mongo")):
            run(["nmap", "-p", "27017", "--script", "mongodb-info,mongodb-databases",
                 "-oN", out, target], timeout=60, label="nmap mongodb scripts")
    phase_time("MongoDB enum", elapsed_str(start))

def phase_snmp(target, outdir, resume=False):
    section("SNMP ENUM")
    start = datetime.now()
    if check_tool("snmpwalk"):
        for community in ["public", "private", "manager"]:
            out = f"{outdir}/snmpwalk_{community}.txt"
            if not (resume and skip_if_exists(out, f"snmpwalk {community}")):
                result = run(
                    ["snmpwalk", "-v2c", "-c", community, target],
                    outfile=out, timeout=60, label=f"snmpwalk community={community}"
                )
                if result.strip():
                    finding(f"{C.YELLOW}[SNMP] community '{community}' returned data!{C.RESET}")
    if check_tool("nmap"):
        run(["nmap", "-sU", "-p", "161", "--script", "snmp-info,snmp-sysdescr",
             "-oN", f"{outdir}/nmap_snmp.txt", target],
            timeout=90, label="nmap snmp scripts")
    phase_time("SNMP enum", elapsed_str(start))

def phase_kerberos(target, outdir, resume=False):
    section("KERBEROS ENUM — port 88")
    start = datetime.now()
    if check_tool("kerbrute"):
        wl = f"{WORDLIST_DIR}/SecLists/Usernames/top-usernames-shortlist.txt"
        if os.path.exists(wl):
            out = f"{outdir}/kerbrute_users.txt"
            if not (resume and skip_if_exists(out, "kerbrute")):
                run(["kerbrute", "userenum", "--dc", target, "-d", target, wl, "-o", out],
                    timeout=120, label="kerbrute userenum")
        else:
            warn("kerbrute wordlist not found — skipping kerbrute")
    if check_tool("nmap"):
        run(["nmap", "-p", "88", "--script", "krb5-enum-users",
             "-oN", f"{outdir}/nmap_kerberos.txt", target],
            timeout=60, label="nmap kerberos scripts")
    phase_time("Kerberos enum", elapsed_str(start))


# ─────────────────────────────────────────
#  PHASE 3 — VULN SCANNING
# ─────────────────────────────────────────
def phase_sqlmap(target, port, proto, outdir, resume=False):
    if not check_tool("sqlmap"):
        return
    section(f"SQLMAP — {proto}://{target}:{port}")
    start   = datetime.now()
    out_dir = f"{outdir}/sqlmap_{port}"
    if resume and os.path.isdir(out_dir):
        warn(f"[resume] Skipping sqlmap — {out_dir} exists")
        return
    run([
        "sqlmap", "-u", f"{proto}://{target}:{port}",
        "--crawl=2", "--batch", "--output-dir", out_dir,
        "--level=3", "--risk=2", "--forms", "--random-agent"
    ], timeout=600, label=f"sqlmap {proto}:{port}")
    phase_time(f"SQLMap {proto}:{port}", elapsed_str(start))

def phase_vuln_nmap(target, open_ports, outdir, resume=False):
    if not check_tool("nmap"):
        return
    section("NMAP VULN SCRIPTS")
    start = datetime.now()
    out   = f"{outdir}/nmap_vuln.txt"
    if resume and skip_if_exists(out, "nmap vuln"):
        return
    ports_str = ",".join(str(p) for p in sorted(p for p in open_ports if p < 99999))
    run(["nmap", "-p", ports_str, "--script", "vuln", "-oN", out, target],
        timeout=600, label="nmap vuln scripts")
    phase_time("Nmap vuln scripts", elapsed_str(start))


# ─────────────────────────────────────────
#  EXTRAS
# ─────────────────────────────────────────
def phase_searchsploit(outdir):
    if not check_tool("searchsploit"):
        return
    section("SEARCHSPLOIT")
    start    = datetime.now()
    xml_file = f"{outdir}/nmap_services.xml"
    if not os.path.exists(xml_file):
        warn("nmap_services.xml not found — skipping searchsploit")
        return
    run(["searchsploit", "--nmap", xml_file],
        outfile=f"{outdir}/searchsploit.txt", timeout=120, label="searchsploit --nmap")
    phase_time("Searchsploit", elapsed_str(start))

def phase_subdomain(target, domain, outdir, resume=False):
    if not domain:
        return
    section(f"SUBDOMAIN / VHOST ENUM — {domain}")
    start = datetime.now()
    wl    = DNS_WORDLIST if os.path.exists(DNS_WORDLIST) else FALLBACK_WL
    if check_tool("gobuster"):
        out = f"{outdir}/gobuster_dns.txt"
        if not (resume and skip_if_exists(out, "gobuster dns")):
            run(["gobuster", "dns", "-d", domain, "-w", wl, "-t", "50", "-o", out],
                timeout=300, label=f"gobuster dns {domain}")
    if check_tool("ffuf"):
        out = f"{outdir}/ffuf_vhosts.json"
        if not (resume and skip_if_exists(out, "ffuf vhosts")):
            run([
                "ffuf", "-u", f"http://{target}",
                "-H", f"Host: FUZZ.{domain}", "-w", wl,
                "-o", out, "-of", "json",
                "-mc", "200,301,302,403", "-fs", "0"
            ], timeout=300, label=f"ffuf vhost fuzz {domain}")
    phase_time("Subdomain/vhost enum", elapsed_str(start))

def flag_unusual_ports(open_ports, outdir):
    unusual = sorted({p for p in open_ports if p < 99999} - COMMON_PORTS)
    if unusual:
        section("UNUSUAL PORTS")
        for p in unusual:
            finding(f"{C.ORANGE}[Unusual Port] {p}/tcp — investigate manually{C.RESET}")
        Path(f"{outdir}/unusual_ports.txt").write_text(
            "Unusual open ports:\n" + "\n".join(str(p) for p in unusual))

def generate_report(target, open_ports, outdir, start_time):
    section("REPORT")
    elapsed   = datetime.now() - start_time
    tcp_ports = sorted(p for p in open_ports if p < 99999)
    has_snmp  = SNMP_SENTINEL in open_ports

    lines = [
        "=" * 55,
        f"  RECON REPORT — {target}",
        "=" * 55,
        f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Elapsed   : {str(elapsed).split('.')[0]}",
        f"  Output dir: {outdir}",
        "",
        f"  Open TCP Ports : {tcp_ports}",
        f"  SNMP (UDP 161) : {'YES' if has_snmp else 'no'}",
        "",
        "  Files generated:",
    ]
    for f in sorted(Path(outdir).rglob("*")):
        if f.is_file():
            size = f.stat().st_size
            lines.append(f"    {str(f.relative_to(outdir)):<45} {size:>8} bytes")
    lines.append("=" * 55)

    report_path = f"{outdir}/report.txt"
    Path(report_path).write_text("\n".join(lines))

    print(f"\n{C.CYAN}{C.BOLD}{'═'*55}")
    print(f"  SCAN COMPLETE — {target}")
    print(f"  Elapsed   : {str(elapsed).split('.')[0]}")
    print(f"  TCP ports : {tcp_ports}")
    print(f"  SNMP      : {'YES' if has_snmp else 'no'}")
    print(f"  Results   : {outdir}/")
    print(f"{'═'*55}{C.RESET}\n")
    success(f"Full report → {report_path}")


# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Automated recon — CTF/THM/HTB",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target",        help="Target IP address")
    parser.add_argument("--vuln",        action="store_true",
                        help="Run vuln scans (sqlmap, nmap vuln, nuclei)")
    parser.add_argument("--domain",      default=None,
                        help="Domain for subdomain/vhost enum")
    parser.add_argument("--quick",       action="store_true",
                        help="Skip nikto, sqlmap, vuln scripts (fast mode)")
    parser.add_argument("--no-parallel", action="store_true",
                        help="Run web tasks sequentially")
    parser.add_argument("--resume",      action="store_true",
                        help="Skip phases whose output files already exist")
    args = parser.parse_args()

    target     = args.target
    start_time = datetime.now()
    outdir     = f"recon_for_{target}"
    os.makedirs(outdir, exist_ok=True)

    success(f"Target  : {C.BOLD}{target}{C.RESET}")
    success(f"Output  : {C.BOLD}{outdir}/{C.RESET}")
    success(f"Started : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    if args.quick:  warn("Quick mode — nikto / sqlmap / vuln scripts skipped")
    if args.vuln:   warn("Vuln mode ON — sqlmap + nmap vuln + nuclei will run")
    if args.resume: warn("Resume mode — existing outputs will be skipped")

    notify("reconkit started", f"Target: {target}")

    # Phase 1 — port scan
    open_ports = run_rustscan(target, outdir, resume=args.resume)
    if not open_ports:
        warn("No open ports found. Is the target reachable?")
        sys.exit(0)

    flag_unusual_ports(open_ports, outdir)

    # Phase 2 — service enum
    web_tasks = []
    smb_done  = False

    for port in sorted(p for p in open_ports if p < 99999):
        if port in HTTP_PORTS:
            t = (target, port, "http", outdir, args.quick, args.resume)
            web_tasks.append((phase_web, t)) if not args.no_parallel else phase_web(*t)

        if port in HTTPS_PORTS:
            t = (target, port, "https", outdir, args.quick, args.resume)
            web_tasks.append((phase_web, t)) if not args.no_parallel else phase_web(*t)

        if port in SMB_PORTS and not smb_done:
            phase_smb(target, outdir, resume=args.resume)
            smb_done = True

        if port in FTP_PORTS:
            phase_ftp(target, outdir, resume=args.resume)

        if port in SSH_PORTS:
            phase_ssh(target, port, outdir, resume=args.resume)

        if port in SQL_PORTS:
            phase_sql(target, port, outdir, resume=args.resume)

        if port in REDIS_PORTS:
            phase_redis(target, outdir, resume=args.resume)

        if port in MONGO_PORTS:
            phase_mongo(target, outdir, resume=args.resume)

        if port in KERBEROS_PORTS:
            phase_kerberos(target, outdir, resume=args.resume)

    if SNMP_SENTINEL in open_ports:
        phase_snmp(target, outdir, resume=args.resume)

    if web_tasks:
        info(f"Launching {len(web_tasks)} web enum task(s) in parallel...")
        run_parallel(web_tasks)

    # Subdomain enum
    if args.domain:
        phase_subdomain(target, args.domain, outdir, resume=args.resume)

    # Searchsploit
    phase_searchsploit(outdir)

    # Phase 3 — vuln scans
    if args.vuln and not args.quick:
        phase_vuln_nmap(target, open_ports, outdir, resume=args.resume)
        for port in sorted(p for p in open_ports if p < 99999):
            if port in HTTP_PORTS:
                phase_sqlmap(target, port, "http", outdir, resume=args.resume)
            if port in HTTPS_PORTS:
                phase_sqlmap(target, port, "https", outdir, resume=args.resume)

    # Report
    generate_report(target, open_ports, outdir, start_time)

    elapsed = datetime.now() - start_time
    notify("reconkit — DONE ✓",
           f"{target} | {str(elapsed).split('.')[0]} | Results in {outdir}/")


if __name__ == "__main__":
    main()
