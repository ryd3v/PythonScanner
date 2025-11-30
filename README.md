# Python Network Scanner

*A lightweight, command‑line network scanner that discovers live hosts in a subnet and prints their IP, MAC address, and vendor.*

> **Important**  
> The script uses raw ICMP (ping) and ARP packets.  
> On most systems you’ll need **root/Administrator** privileges to run it.

---

## Features

| Feature | Description |
|---------|-------------|
| **Subnet scan** | Accepts a CIDR block (e.g., `192.168.2.0/24`) and pings every address in that range. |
| **ARP lookup** | Retrieves the MAC address of each live host via `ip neigh` (Linux/macOS) or `arp -a` (Windows). |
| **Vendor discovery** | Uses the `mac_vendor_lookup` library to resolve the MAC prefix to a vendor name. |
| **Threaded execution** | Scans up to 100 hosts in parallel (configurable). |
| **Clean output** | Prints a simple table: `IP Address | MAC Address | Vendor`. |

---

## Prerequisites

- Python 3.8 or newer
- (Optional) `mac_vendor_lookup` for vendor lookup

```bash
pip install mac_vendor_lookup   # optional, but recommended
