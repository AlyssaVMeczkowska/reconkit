# 🔍 ReconKit

> Automated recon & enumeration script for CTFs / TryHackMe

ReconKit chains together the most common enumeration tools into a single command. Point it at an IP, walk away, and come back to a fully organized output folder with color-coded live findings as everything runs.

---

## Features

- **RustScan → Nmap** — blazing fast TCP port discovery piped into full service/script detection
- **UDP scan** — automatic top-20 UDP sweep, SNMP flagged if found
- **Feroxbuster / Gobuster** — recursive directory enumeration (feroxbuster preferred, gobuster as fallback)
- **WhatWeb** — full tech stack fingerprinting
- **wafw00f** — WAF detection before you waste time getting blocked
- **Nikto** — web server vulnerability scanning
- **Nuclei** — CVE, misconfiguration, and exposure template scanning
- **Well-known file fetch** — auto-grabs `robots.txt`, `sitemap.xml`, `.htaccess`, `security.txt`
- **curl header grab** — highlights `Server`, `X-Powered-By`, `Set-Cookie`, auth headers
- **Login page detection** — parses dir enum output for login paths, checks HTTP Basic Auth with default creds if challenged (401), flags form-based logins for manual review
- **WordPress detection → wpscan** — auto-triggered if WhatWeb finds WordPress
- **SMB** — enum4linux, smbclient share listing, nmap SMB vuln/enum scripts
- **FTP** — anonymous login check via nmap scripts
- **SSH** — auth methods and hostkey enumeration
- **MySQL / PostgreSQL** — nmap sql scripts
- **Redis** — unauthenticated access check
- **MongoDB** — database enumeration
- **SNMP** — snmpwalk against common community strings (public/private/manager)
- **Kerberos** — kerbrute user enum + nmap scripts if port 88 is open
- **Searchsploit** — automatically runs against nmap XML output
- **Subdomain / vhost enum** — gobuster DNS + ffuf vhost fuzzing (with `--domain`)
- **Gowitness** — screenshots of discovered web services
- **Desktop notifications** — `notify-send` pops on scan start, port discovery, web enum completion, and full scan done
- **Resume mode** — skips phases whose output files already exist
- **Per-phase elapsed time** — know exactly where your time is going
- **Organized output** — everything saved to `recon_for_<TARGET_IP>/` with a summary `report.txt`
- **Live color-coded output** — findings stream in real time, interesting lines re-highlighted as they arrive

---

## Output Structure

```
recon_for_<TARGET_IP>/
├── rustscan.txt
├── nmap_services.txt
├── nmap_services.xml
├── nmap_udp.txt
├── headers_http_80.txt
├── whatweb_http_80.txt
├── wafw00f_http_80.txt
├── feroxbuster_http_80.txt
├── nikto_http_80.txt
├── nuclei_http_80.txt
├── web_http_80_robots_txt.txt
├── login_pages_http_80.txt
├── enum4linux.txt
├── smb_shares.txt
├── nmap_smb.txt
├── nmap_ftp.txt
├── nmap_ssh_22.txt
├── searchsploit.txt
├── unusual_ports.txt
├── screenshots/
├── sqlmap_80/           # --vuln only
├── nmap_vuln.txt        # --vuln only
└── report.txt
```

---

## Usage

```bash
# Basic recon
python3 reconkit.py <TARGET_IP>

# With subdomain/vhost enumeration
python3 reconkit.py <TARGET_IP> --domain example.thm

# Full vuln mode (sqlmap + nmap vuln scripts + nuclei)
python3 reconkit.py <TARGET_IP> --vuln

# Fast mode — port scan + dir enum only, skips nikto/sqlmap/vuln
python3 reconkit.py <TARGET_IP> --quick

# Resume an interrupted scan
python3 reconkit.py <TARGET_IP> --resume

# Everything
python3 reconkit.py <TARGET_IP> --vuln --domain box.thm
```

### Make it executable from anywhere

```bash
chmod +x reconkit.py
sudo mv reconkit.py /usr/local/bin/reconkit
reconkit <TARGET_IP>
```

---

## Requirements

**Required:**
- Python 3.8+
- [RustScan](https://github.com/RustScan/RustScan) — `cargo install rustscan`
- nmap

**Recommended (auto-skipped if missing):**

| Tool | Purpose | Install |
|------|---------|---------|
| feroxbuster | Recursive dir enum | `sudo apt install feroxbuster` |
| gobuster | Dir/DNS enum (fallback) | `sudo apt install gobuster` |
| nikto | Web vuln scanner | `sudo apt install nikto` |
| nuclei | CVE/template scanner | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| whatweb | Tech fingerprinting | `sudo apt install whatweb` |
| wafw00f | WAF detection | `pip install wafw00f` |
| wpscan | WordPress scanner | `sudo apt install wpscan` |
| sqlmap | SQL injection | `sudo apt install sqlmap` |
| enum4linux | SMB enumeration | `sudo apt install enum4linux` |
| smbclient | SMB shares | `sudo apt install smbclient` |
| snmpwalk | SNMP enumeration | `sudo apt install snmp` |
| kerbrute | Kerberos user enum | [releases](https://github.com/ropnop/kerbrute/releases) |
| ffuf | Vhost fuzzing | `sudo apt install ffuf` |
| gowitness | Web screenshots | `go install github.com/sensepost/gowitness@latest` |
| searchsploit | Exploit-DB lookup | `sudo apt install exploitdb` |
| curl | Header grabbing | `sudo apt install curl` |

**Wordlists** (auto-detected across common locations):
- SecLists — `sudo apt install seclists`
- dirbuster wordlists — `sudo apt install dirb`

---

## Color Guide

| Color | Meaning |
|-------|---------|
| 🟣 `[★]` magenta | Interesting finding — look at this |
| 🟢 `[+]` green | Success / open port / 200 response |
| 🔵 `[*]` blue | Info / running command |
| 🟡 `[!]` yellow | Warning / redirect / unusual port |
| 🔴 `[✗]` red | Error / CVE / vulnerable / anonymous access |

---

## Notes

- Designed for authorized use on machines you own or have explicit permission to test (CTF/lab environments)
- Vuln mode (`--vuln`) runs noisier, slower scans — use intentionally
- Form-based login pages are flagged for manual review; the script does not attempt blind POST bruteforce (use hydra for that with known field names)
- All tools are optional — reconkit checks for each one at runtime and skips gracefully if not installed

---

## Author

**Alyssa Meczkowska** — [@AlyssaVMeczkowska](https://github.com/AlyssaVMeczkowska)
