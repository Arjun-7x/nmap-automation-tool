# Python Nmap Automation Tool

A simple, menu-driven Python CLI that automates [Nmap](https://nmap.org) for **authorized** network discovery. It runs a scan, parses Nmap's XML output, prints a clean table of hosts / ports / services / versions, and exports the results to **TXT, JSON and CSV**.

Built for the InternNova Cybersecurity Internship (Week 6, Project 1: Python-Based Network Scanner & Nmap Automation Tool).

> ⚠️ **Legal / ethical use only.** Scan only systems you own or have **written permission** to test. The tool asks for confirmation before every scan and warns on non-private targets. I tested it only against my own isolated lab (Kali Linux → Metasploitable2 in VirtualBox).

## Features

| # | Scan profile | Nmap flags |
|---|--------------|-----------|
| 1 | Host discovery (ping sweep) | `-sn` |
| 2 | Quick port scan (top 100 ports) | `-F` |
| 3 | Full TCP connect scan (all ports, no versions) | `-sT -p-` |
| 4 | Service/version detection (top 100 ports) | `-sV -F` |
| 5 | Full port + version detection (all ports, slower) | `-sV -p- -T4` |

- Standard library only, no `pip install` needed
- Nmap runs through `subprocess` with an argument list (no shell, no injection risk)
- Parses Nmap XML (`-oX -`) instead of fragile text output
- Authorization prompt, private-address check, per-scan timeouts, error handling
- Timestamped export: `scan_YYYYMMDD_HHMMSS.{json,csv,txt}`

## Requirements

- Python 3.8+
- Nmap (`sudo apt install nmap`)

## Usage

```bash
python3 nmap_scanner.py
```

```
1. Host discovery (ping sweep)
2. Quick port scan (top 100 ports)
3. Full TCP connect scan (all ports, no versions)
4. Service/version detection (top 100 ports)
5. Full port + version detection (all ports, slower)
0. Exit
Select scan: 5
Target (IP, range or CIDR, e.g. 192.168.56.101): 192.168.56.102
```

## Sample result

Option 5 against Metasploitable2 (`192.168.56.102`) found **30 open TCP ports** with service versions, e.g.:

| Port | Service | Version |
|------|---------|---------|
| 21 | ftp | vsftpd 2.3.4 |
| 22 | ssh | OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) |
| 80 | http | Apache httpd 2.2.8 ((Ubuntu) DAV/2) |
| 1524 | bindshell | Metasploitable root shell |
| 3306 | mysql | MySQL 5.0.51a-3ubuntu5 |
| 8180 | http | Apache Tomcat/Coyote JSP engine 1.1 |

Full output is in [`sample_output/`](sample_output) and screenshots in [`screenshots/`](screenshots).

## Project layout

```
nmap_scanner.py      # the tool
sample_output/       # real JSON / CSV / TXT export from the lab scan
screenshots/         # terminal screenshots
report/              # one-page project report (PDF)
```

## What I learned

TCP connect scans vs. version detection, mapping open ports to attack surface, parsing XML in Python, safe `subprocess` use, and responsible scanning practice.

## Possible improvements

- Scan profiles for UDP and NSE scripts
- HTML report output
- Compare two scans to spot changes
- Flag known-risky services automatically

## Author

**Kanagala Mahesh** - B.Tech CSE student and ethical hacker (CEH)
