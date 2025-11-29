# NetSentinel

**Real-time Network Traffic Analysis & Threat Detection**

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge\&logo=python\&logoColor=white)](https://python.org)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-2C2D72?style=for-the-badge\&logo=wireshark\&logoColor=white)](https://scapy.net)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge\&logo=linux\&logoColor=black)](https://linux.org)

![NetSentinel Demo](https://raw.githubusercontent.com/yourusername/netsentinel/main/assets/demo.gif)

Lightweight, terminal-based network monitoring with real-time threat detection.

---

## Table of Contents

* [Overview](#overview)
* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
* [Detection Rules](#detection-rules)
* [Output Format](#output-format)
* [Architecture](#architecture)
* [Protocol Colors](#protocol-colors)
* [Extensibility](#extensibility)
* [Performance & Limitations](#performance--limitations)
* [Contributing](#contributing)
* [Disclaimer](#disclaimer)

---

## Overview

NetSentinel is a lightweight network analysis tool for real-time packet capture, protocol inspection and threat detection. It features a terminal-based dashboard built with [Rich](https://github.com/Textualize/rich) that shows live traffic, top talkers, protocol stats and alerts.

Example dashboard (illustrative):

```
NetSentinel | Pkts: 15,847 | Bytes: 12.4MB | Rate: 245.3 pps
────────────────────────────────────────────────────────────────
Live Traffic                 | Top Source IPs
14:23:45 TCP  192.168.1.10 → 8.8.8.8   | 192.168.1.10   4,521
14:23:45 DNS  192.168.1.15 → Q google.com | 10.0.0.1    2,847
14:23:44 TLS  192.168.1.10 → github.com     | 192.168.1.15 1,923

Threat Detection              | Protocols
[HIGH] 14:23:41 arp-spoofing: MAC Conflict | TCP  8,421 (53.1%)
[MED]  14:23:38 port-scan: 20+ ports        | UDP  4,892 (30.9%)
[LOW]  14:23:35 ssh-high-port: SSH on 2222   | DNS  1,847 (11.7%)
```

---

## Features

**Packet analysis**

* Multi-protocol support: TCP, UDP, ICMP, ICMPv6, ARP, DNS, HTTP, TLS, SSH, QUIC
* Deep packet inspection: TLS SNI extraction and HTTP host parsing
* IPv4 & IPv6 dual-stack support
* Optional GeoIP lookup for public IPs

**Threat detection**

* ARP Spoofing detection (MAC conflicts, ARP cache poisoning)
* Port scan detection (vertical and massive scans)
* Attack tool detection via User-Agent (sqlmap, nikto, nmap, hydra)
* Protocol anomalies: SSH on non-standard ports, suspicious TLS SNI patterns

**Real-time dashboard**

* Live traffic feed with protocol highlight
* Top talkers ranking
* Protocol distribution bars
* Severity-based alert feed

**Export & filters**

* PCAP writing for offline analysis
* JSONL event export for SIEM ingestion
* BPF filtering for precise capture control

---

## Installation

### Prerequisites

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install -y python3 python3-venv python3-pip libpcap-dev

# Fedora / RHEL
sudo dnf install -y python3 python3-venv python3-pip libpcap-devel

# Arch Linux
sudo pacman -S --noconfirm python python-virtualenv libpcap
```

### Clone and install

```bash
git clone https://github.com/yourusername/netsentinel.git
cd netsentinel

# create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# install dependencies
pip install -r requirements.txt
```

Example `requirements.txt`:

```
scapy>=2.5.0
rich>=13.0.0
typer>=0.9.0
geoip2>=4.7.0  # optional for GeoIP
```

### GeoIP (optional)

Download the GeoLite2 database from MaxMind ([https://www.maxmind.com](https://www.maxmind.com)) and place the `.mmdb` file in the project directory or configure `geoipupdate`.

---

## Usage

```bash
# live capture on default interface (requires root)
sudo python3 netsentinel.py

# capture on a specific interface
sudo python3 netsentinel.py --iface eth0

# apply a BPF filter
sudo python3 netsentinel.py --bpf "tcp port 80 or tcp port 443"

# read from a pcap file
python3 netsentinel.py --read-pcap capture.pcap

# write packets to PCAP
sudo python3 netsentinel.py --write-pcap output

# export events to JSONL
sudo python3 netsentinel.py --export-json logs.jsonl

# headless mode (no UI)
sudo python3 netsentinel.py --no-ui --export-json /var/log/netsentinel.jsonl

# silent mode
sudo python3 netsentinel.py --silent --export-json alerts.jsonl
```

### CLI options (summary)

| Option          | Default | Description                             |
| --------------- | ------: | --------------------------------------- |
| `--iface`       |     any | Network interface to capture from       |
| `--bpf`         |       - | BPF expression to filter capture        |
| `--read-pcap`   |       - | Read packets from a PCAP file           |
| `--write-pcap`  |       - | Write captured packets to PCAP (prefix) |
| `--export-json` |       - | Export events/alerts to JSONL           |
| `--geoip-db`    |       - | Path to GeoLite2 `.mmdb` file           |
| `--ui/--no-ui`  |    --ui | Enable/disable terminal dashboard       |
| `--silent`      |   false | Silent mode (no console output)         |

#### BPF examples

```bash
# HTTP/HTTPS only
--bpf "tcp port 80 or tcp port 443"

# specific host
--bpf "host 192.168.1.100"

# exclude local traffic
--bpf "not net 192.168.0.0/16"

# DNS traffic only
--bpf "udp port 53"

# large packets
--bpf "greater 1000"
```

---

## Detection Rules (examples)

### ARP Spoofing (`arp-spoofing`)

**Severity:** high

Detects when an IP address is associated with multiple MAC addresses (possible ARP cache poisoning).

Alert example:

```json
{
  "type": "alert",
  "rule": "arp-spoofing",
  "severity": "high",
  "summary": "MAC Conflict 192.168.1.1",
  "extra": {
    "mac_old": "aa:bb:cc:dd:ee:ff",
    "mac_new": "11:22:33:44:55:66"
  }
}
```

### Port Scan - Vertical (`port-scan-vertical`)

**Severity:** medium

Triggered when a source probes 20+ different ports within the detection window (e.g., 30s).

### Port Scan - Massive (`port-scan-massive`)

**Severity:** high

Triggered when a source probes 100+ ports (aggressive scanning).

### Attack Tool Detection (`tool-ua`)

**Severity:** high

Identifies HTTP requests with User-Agent strings matching known attack tools (sqlmap, nikto, nmap, hydra).

### SSH on High Port (`ssh-high-port`)

**Severity:** low

Detects SSH traffic on non-standard ports (>1024, excluding 22).

### TLS Local SNI (`tls-local-sni`)

**Severity:** low

Detects TLS connections with SNI values ending in `.local` or `.lan`.

---

## Output Format

### Packet record (JSONL)

```json
{
  "type": "packet",
  "ts_ms": 1699876543210,
  "length": 1500,
  "proto": "TLS",
  "src": "192.168.1.10",
  "dst": "140.82.121.4",
  "sport": 54321,
  "dport": 443,
  "info": "TLS github.com",
  "country_src": "LOC",
  "country_dst": "US"
}
```

### Alert record (JSONL)

```json
{
  "type": "alert",
  "ts_ms": 1699876543210,
  "rule": "port-scan-vertical",
  "severity": "medium",
  "summary": "Scan: 20+ ports",
  "src": "10.0.0.50",
  "dst": "",
  "extra": {}
}
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        NetSentinel                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │   Capture   │───▶│   Packet     │───▶│    Analyzers     │   │
│  │   Engine    │    │   Queue      │    │                  │   │
│  │  • Scapy    │    │  (10k max)   │    │  • ARP Analyzer  │   │
│  │  • PCAP R/W │    └──────────────┘    │  • PortScan      │   │
│  │  • BPF      │                        │  • Protocol      │   │
│  └─────────────┘                                 └────────┬─────────┘   │
│                                                  ▼             │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │   GeoIP     │◀───│  PacketMeta  │───▶│    Dashboard     │   │
│  │   Lookup    │    │   + Alerts   │    │                  │   │
│  └─────────────┘    └──────┬───────┘    │  • Live Traffic  │   │
│                            │            │  • Top Talkers   │   │
│                            ▼            │  • Alerts        │   │
│                    ┌──────────────┐     │  • Protocol Stats│   │
│                    │   Exporters  │     └──────────────────┘   │
│                    │  • JSONL     │                            │
│                    │  • PCAP      │                            │
│                    └──────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Protocol Colors

| Protocol    | Suggested Color | Description                       |
| ----------- | --------------: | --------------------------------- |
| TCP         |            Blue | Transmission Control Protocol     |
| UDP         |            Cyan | User Datagram Protocol            |
| ICMP/ICMPv6 |             Red | Internet Control Message Protocol |
| ARP         |          Yellow | Address Resolution Protocol       |
| DNS         |         Magenta | Domain Name System                |
| TLS         |           Green | Transport Layer Security          |
| HTTP        |           White | Hypertext Transfer Protocol       |
| SSH         |      Bright Red | Secure Shell                      |
| QUIC        |     Bright Cyan | Quick UDP Internet Connections    |

---

## Extensibility

Add custom analyzers by subclassing the `Analyzer` base and appending instances to the engine's analyzer list.

Example:

```python
class MyCustomAnalyzer(Analyzer):
    def __init__(self):
        self.suspicious_ips = set()

    def handle(self, pkt: PacketMeta) -> Iterable[Alert]:
        if pkt.src in self.suspicious_ips:
            yield Alert(
                ts_ms=pkt.ts_ms,
                rule="custom-rule",
                severity="medium",
                summary=f"Suspicious activity from {pkt.src}",
                src=pkt.src
            )

# Register in CaptureEngine.__init__:
self.analyzers.append(MyCustomAnalyzer())
```

---

## Performance & Limitations

**Typical metrics**

* Max queue size: 10,000 packets
* Dashboard refresh: ~4 fps
* Batch processing: ~50 packets/cycle
* Memory usage: ~50–100 MB
* Default detection window: 30 seconds

**Known limitations**

* Requires root/sudo for live packet capture
* Linux-only (uses `os.geteuid()`)
* PCAP write may not be integrated into the main loop
* High-speed links (>1 Gbps) may drop packets

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/YourFeature`
3. Commit changes: `git commit -m "Add YourFeature"`
4. Push branch: `git push origin feature/YourFeature`
5. Open a Pull Request

Include tests and documentation for significant changes.

---

## Disclaimer

This tool is intended for authorized network monitoring and security testing only. Ensure you have proper authorization before capturing network traffic. Unauthorized monitoring may violate local laws.

---

Made for the security community.
