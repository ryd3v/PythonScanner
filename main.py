#!/usr/bin/env python3
"""
Network Scanner – Lightweight ARP/ICMP sweep

Author:        Ryan Collins
Email:         hello@ryd3v.com
GitHub:        https://github.com/ryd3v
License:       MIT

Description:
    • Scans a CIDR subnet.
    • Pings each host, retrieves MAC address via ARP (ip neigh on Linux/macOS).
    • Looks up vendor using mac_vendor_lookup.
    • Prints a clean table of IP / MAC / Vendor.

Usage:
    python3 scanner.py 192.168.2.0/24
    # or just run without arguments and input the subnet when prompted

Prerequisites:
    • Python 3.8+
    • mac_vendor_lookup (pip install mac_vendor_lookup) – optional
"""

import os
import sys
import socket
import struct
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional vendor lookup package (pip install mac_vendor_lookup)
try:
    from mac_vendor_lookup import MacLookup
except ImportError:
    MacLookup = None


def ping(host: str, timeout=1) -> bool:
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-W", str(timeout), host]
    try:
        # Suppress output
        result = subprocess.run(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def arp_request(host: str) -> tuple[str, str]:
    try:
        if platform.system().lower() == "windows":
            # Windows: ensure the entry exists
            subprocess.run(
                ["arp", "-a", host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            output = subprocess.check_output(["arp", "-a"], text=True)
        else:
            # Unix-like: use ip neigh (no usage output)
            output = subprocess.check_output(
                ["ip", "neigh", "show", host], text=True, stderr=subprocess.DEVNULL
            )

        for line in output.splitlines():
            # Lines look like: 192.168.1.5 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
            if host in line:
                parts = line.split()
                mac_candidates = [p for p in parts if ":" in p or "-" in p]
                if mac_candidates:
                    mac = mac_candidates[0].replace("-", ":")
                    return host, mac
        return host, ""
    except Exception:
        return host, ""


def get_vendor(mac: str) -> str:
    if MacLookup is None:
        return "Unknown"
    try:
        lookup = MacLookup()
        vendor = lookup.lookup(mac)
        return vendor if vendor else "Unknown"
    except Exception:
        return "Unknown"


def cidr_hosts(cidr: str):
    try:
        ip, mask = cidr.split("/")
        mask = int(mask)
        start = struct.unpack(">I", socket.inet_aton(ip))[0]
        end = start + (1 << (32 - mask)) - 1
        for ip_int in range(start, end + 1):
            yield socket.inet_ntoa(struct.pack(">I", ip_int))
    except Exception as e:
        print(f"Error parsing CIDR '{cidr}': {e}")
        sys.exit(1)


def scan_subnet(cidr: str, threads=100):
    results = []

    def worker(ip):
        if ping(ip):
            _, mac = arp_request(ip)
            vendor = get_vendor(mac) if mac else "Unknown"
            return {"ip": ip, "mac": mac or "N/A", "vendor": vendor}
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ip = {executor.submit(worker, ip): ip for ip in cidr_hosts(cidr)}
        for future in as_completed(future_to_ip):
            res = future.result()
            if res:
                results.append(res)

    return results


def print_results(results):
    header = f"{'IP Address':<15} {'MAC Address':<20} Vendor"
    print("\n" + header)
    print("-" * len(header))
    for r in sorted(results, key=lambda x: socket.inet_aton(x["ip"])):
        print(f"{r['ip']:<15} {r['mac']:<20} {r['vendor']}")


def main():
    if len(sys.argv) > 1:
        cidr = sys.argv[1]
    else:
        cidr = input("Enter subnet to scan (e.g. 192.168.2.0/24): ").strip()
    if not cidr:
        print("No subnet provided.")
        sys.exit(1)

    print(f"\nScanning {cidr} ... (this may take a while)")
    results = scan_subnet(cidr)
    print_results(results)


if __name__ == "__main__":
    main()
