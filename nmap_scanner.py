#!/usr/bin/env python3
"""Simple Nmap Automation Tool - authorized lab use only.
Requires: nmap installed (sudo apt install nmap). No extra Python packages."""

import csv
import ipaddress
import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

# key: (description, nmap flags, timeout in seconds)
SCANS = {
    "1": ("Host discovery (ping sweep)", ["-sn"], 300),
    "2": ("Quick port scan (top 100 ports)", ["-F"], 600),
    "3": ("Full TCP connect scan (all ports, no versions)", ["-sT", "-p-"], 1800),
    "4": ("Service/version detection (top 100 ports)", ["-sV", "-F"], 900),
    "5": ("Full port + version detection (all ports, slower)", ["-sV", "-p-", "-T4"], 3600),
}


def check_target(target):
    """Warn if the target is not a private/lab address and ask for confirmation."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        private = net.is_private
    except ValueError:
        private = False  # hostname or unusual input
    if not private:
        print("\n[!] Target is not a private/lab address.")
        print("[!] Only continue if you have WRITTEN permission to scan it.")
    ok = input("Do you own this target or have written permission to scan it? (yes/no): ")
    return ok.strip().lower() == "yes"


def run_nmap(target, flags, timeout):
    cmd = ["nmap", *flags, "-oX", "-", target]
    print(f"\n[*] Running: {' '.join(cmd)}")
    print(f"[*] Timeout: {timeout // 60} min. Please wait...\n")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print("[!] Scan timed out.")
        return None
    if result.returncode != 0:
        print("[!] Nmap error:", result.stderr.strip())
        return None
    return result.stdout


def parse_xml(xml_text):
    """Return a list of rows: host, port, protocol, state, service, version."""
    rows = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        if host.find("status") is None or host.find("status").get("state") != "up":
            continue
        addr = host.find("address").get("addr")
        ports = host.find("ports")
        if ports is None or not ports.findall("port"):
            rows.append({"host": addr, "port": "", "protocol": "", "state": "up",
                         "service": "", "version": ""})
            continue
        for p in ports.findall("port"):
            svc = p.find("service")
            version = ""
            if svc is not None:
                # product + version, plus extra info (e.g. "protocol 2.0", "Ubuntu")
                parts = [svc.get("product"), svc.get("version")]
                version = " ".join(filter(None, parts))
                extra = svc.get("extrainfo")
                if extra:
                    version = f"{version} ({extra})".strip()
            rows.append({
                "host": addr,
                "port": p.get("portid"),
                "protocol": p.get("protocol"),
                "state": p.find("state").get("state"),
                "service": svc.get("name") if svc is not None else "",
                "version": version,
            })
    return rows


def show(rows):
    if not rows:
        print("[-] No live hosts found.")
        return
    print(f"{'HOST':<16}{'PORT':<11}{'STATE':<8}{'SERVICE':<14}VERSION")
    print("-" * 90)
    for r in rows:
        port = f"{r['port']}/{r['protocol']}" if r['port'] else "-"
        print(f"{r['host']:<16}{port:<11}{r['state']:<8}{r['service']:<14}{r['version']}")


def export(rows, target):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"scan_{stamp}"
    with open(base + ".json", "w") as f:
        json.dump({"target": target, "time": stamp, "results": rows}, f, indent=2)
    with open(base + ".csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["host", "port", "protocol", "state", "service", "version"])
        w.writeheader()
        w.writerows(rows)
    with open(base + ".txt", "w") as f:
        f.write(f"Scan report - target: {target} - {stamp}\n\n")
        for r in rows:
            f.write(f"{r['host']}  {r['port']}/{r['protocol']}  {r['state']}  "
                    f"{r['service']}  {r['version']}\n")
    print(f"\n[+] Saved: {base}.json, {base}.csv, {base}.txt")


def main():
    if not shutil.which("nmap"):
        sys.exit("Nmap not found. Install it with: sudo apt install nmap")
    print("=== Simple Nmap Automation Tool (authorized lab use only) ===")
    while True:
        print("\n" + "\n".join(f"{k}. {v[0]}" for k, v in SCANS.items()) + "\n0. Exit")
        choice = input("Select scan: ").strip()
        if choice == "0":
            break
        if choice not in SCANS:
            print("Invalid choice.")
            continue
        target = input("Target (IP, range or CIDR, e.g. 192.168.56.101): ").strip()
        if not target or not check_target(target):
            print("[!] Scan cancelled.")
            continue
        _, flags, timeout = SCANS[choice]
        xml_text = run_nmap(target, flags, timeout)
        if xml_text:
            rows = parse_xml(xml_text)
            show(rows)
            if rows and input("\nExport results? (y/n): ").strip().lower() == "y":
                export(rows, target)


if __name__ == "__main__":
    main()
