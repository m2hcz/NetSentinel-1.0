markdownDownloadCopy code<div align="center">

# 🛡️ NetSentinel

**Real-time Network Traffic Analysis & Threat Detection**

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-2C2D72?style=for-the-badge&logo=wireshark&logoColor=white)](https://scapy.net)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://linux.org)

<img src="https://raw.githubusercontent.com/yourusername/netsentinel/main/assets/demo.gif" alt="NetSentinel Demo" width="800">

*A lightweight, terminal-based network monitoring tool with real-time threat detection capabilities*

[Features](#-features) •
[Installation](#-installation) •
[Usage](#-usage) •
[Detection Rules](#-detection-rules) •
[Configuration](#%EF%B8%8F-configuration)

</div>

---

## 📋 Overview

NetSentinel is a powerful yet lightweight network analysis tool designed for security professionals and system administrators. It provides real-time packet capture, protocol analysis, and threat detection through an intuitive terminal-based dashboard built with [Rich](https://github.com/Textualize/rich).

┌──────────────────────────────────────────────────────────────────────────────┐
│                NetSentinel | Pkts: 15,847 | Bytes: 12.4MB | Rate: 245.3 pps  │
├────────────────────────────────────────────┬─────────────────────────────────┤
│              Live Traffic                  │         Top Source IPs          │
│ ─────────────────────────────────────────  │  ───────────────────────────    │
│ 14:23:45 TCP  192.168.1.10:443 → 8.8.8.8   │  192.168.1.10        4,521      │
│ 14:23:45 DNS  192.168.1.15 → Q google.com  │  10.0.0.1            2,847      │
│ 14:23:44 TLS  192.168.1.10 → github.com    │  192.168.1.15        1,923      │
│ 14:23:44 HTTP 192.168.1.22 → example.com   │                                 │
├────────────────────────────────────────────┼─────────────────────────────────┤
│           Threat Detection                 │           Protocols             │
│  ─────────────────────────────────────     │  ───────────────────────────    │
│  🔴 14:23:41 arp-spoofing: MAC Conflict    │  TCP    8,421  (53.1%) ████████ │
│  🟡 14:23:38 port-scan: 20+ ports          │  UDP    4,892  (30.9%) █████    │
│  🔵 14:23:35 ssh-high-port: SSH on 2222    │  DNS    1,847  (11.7%) ██       │
└────────────────────────────────────────────┴─────────────────────────────────┘

---

## ✨ Features

### 🔍 Packet Analysis
- **Multi-protocol support**: TCP, UDP, ICMP, ICMPv6, ARP, DNS, HTTP, TLS, SSH, QUIC
- **Deep packet inspection**: TLS SNI extraction, HTTP host parsing
- **IPv4 & IPv6**: Full dual-stack support
- **GeoIP lookup**: Country identification for public IPs (optional)

### 🚨 Threat Detection
- **ARP Spoofing Detection**: Identifies MAC address conflicts and ARP cache poisoning attempts
- **Port Scan Detection**: Detects vertical and mass port scanning activities
- **Attack Tool Detection**: Recognizes common security tools (sqlmap, nikto, nmap, hydra)
- **Protocol Anomalies**: SSH on non-standard ports, suspicious TLS SNI patterns

### 📊 Real-time Dashboard
- **Live traffic view**: Color-coded protocol visualization
- **Top talkers**: Most active source IPs
- **Protocol statistics**: Distribution with visual bars
- **Alert feed**: Severity-based threat notifications

### 💾 Data Export
- **PCAP writing**: Save captured packets for later analysis
- **JSONL export**: Structured logs for SIEM integration
- **BPF filtering**: Precise traffic selection

---

## 📦 Installation

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install python3 python3-pip libpcap-dev

# Fedora/RHEL
sudo dnf install python3 python3-pip libpcap-devel

# Arch Linux
sudo pacman -S python python-pip libpcap

Install NetSentinel
bashDownloadCopy code# Clone the repository
git clone https://github.com/yourusername/netsentinel.git
cd netsentinel

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
Requirements
Create a requirements.txt:
txtDownloadCopy codescapy>=2.5.0
rich>=13.0.0
typer>=0.9.0
geoip2>=4.7.0  # Optional: for GeoIP support
GeoIP Database (Optional)
For country identification, download the free GeoLite2 database:
bashDownloadCopy code# Register at https://www.maxmind.com/en/geolite2/signup
# Download GeoLite2-Country.mmdb and place in project directory

# Or use geoipupdate
sudo apt install geoipupdate
sudo geoipupdate

🚀 Usage
Basic Usage
bashDownloadCopy code# Live capture on default interface (requires root)
sudo python3 netsentinel.py

# Capture on specific interface
sudo python3 netsentinel.py --iface eth0

# Apply BPF filter
sudo python3 netsentinel.py --bpf "tcp port 80 or tcp port 443"
Read from PCAP
bashDownloadCopy code# Analyze existing capture file
python3 netsentinel.py --read-pcap capture.pcap
Export Data
bashDownloadCopy code# Write packets to PCAP
sudo python3 netsentinel.py --write-pcap output

# Export to JSON Lines format
sudo python3 netsentinel.py --export-json logs.jsonl

# Combined
sudo python3 netsentinel.py --write-pcap capture --export-json events.jsonl
Headless Mode
bashDownloadCopy code# Run without UI (for logging/automation)
sudo python3 netsentinel.py --no-ui --export-json /var/log/netsentinel.jsonl

# Silent mode
sudo python3 netsentinel.py --silent --export-json alerts.jsonl

⚙️ Configuration
Command Line Options
OptionDefaultDescription--ifaceanyNetwork interface to capture from--bpfNoneBerkeley Packet Filter expression--read-pcapNoneRead packets from PCAP file--write-pcapNoneWrite packets to PCAP file (prefix)--export-jsonNoneExport events to JSONL file--geoip-dbGeoLite2-City.mmdbPath to MaxMind GeoIP database--ui / --no-uiTrueEnable/disable terminal dashboard--silentFalseSilent mode (no output)
BPF Filter Examples
bashDownloadCopy code# Only HTTP/HTTPS traffic
--bpf "tcp port 80 or tcp port 443"

# Specific host
--bpf "host 192.168.1.100"

# Exclude local traffic
--bpf "not net 192.168.0.0/16"

# DNS traffic only
--bpf "udp port 53"

# Large packets
--bpf "greater 1000"

🔐 Detection Rules
ARP Spoofing (arp-spoofing)
Severity: 🔴 High
Detects when an IP address is associated with multiple MAC addresses, indicating potential ARP cache poisoning attacks.
jsonDownloadCopy code{
  "type": "alert",
  "rule": "arp-spoofing",
  "severity": "high",
  "summary": "MAC Conflict 192.168.1.1",
  "extra": {
    "mac_old": "aa:bb:cc:dd:ee:ff",
    "mac_new": "11:22:33:44:55:66"
  }
}
Port Scan - Vertical (port-scan-vertical)
Severity: 🟡 Medium
Triggered when a single source IP probes 20+ different ports within the detection window (30 seconds).
Port Scan - Mass (port-scan-massivo)
Severity: 🔴 High
Triggered when a source IP probes 100+ ports, indicating aggressive scanning activity.
Attack Tool Detection (tool-ua)
Severity: 🔴 High
Identifies HTTP requests with User-Agent strings matching known security/attack tools:

* sqlmap
* nikto
* nmap
* hydra

SSH on High Port (ssh-high-port)
Severity: 🔵 Low
Detects SSH protocol traffic on non-standard ports (above 1024, excluding 22).
Local TLS SNI (tls-local-sni)
Severity: 🔵 Low
Identifies TLS connections with SNI values ending in .local or .lan.

📁 Output Format
JSONL Export Structure
Packet Record:
jsonDownloadCopy code{
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
Alert Record:
jsonDownloadCopy code{
  "type": "alert",
  "ts_ms": 1699876543210,
  "rule": "port-scan-vertical",
  "severity": "medium",
  "summary": "Scan: 20+ ports",
  "src": "10.0.0.50",
  "dst": "",
  "extra": {}
}

🏗️ Architecture
┌─────────────────────────────────────────────────────────────────┐
│                        NetSentinel                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │   Capture   │───▶│   Packet     │───▶│    Analyzers     │   │
│  │   Engine    │    │   Queue      │    │                  │   │
│  │             │    │  (10k max)   │    │  • ARP Analyzer  │   │
│  │  • Scapy    │    └──────────────┘    │  • PortScan      │   │
│  │  • PCAP R/W │                        │  • Protocol      │   │
│  │  • BPF      │                        └────────┬─────────┘   │
│  └─────────────┘                                 │             │
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
│                                                                 │
└─────────────────────────────────────────────────────────────────┘


🎨 Protocol Colors
ProtocolColorDescriptionTCP🔵 BlueTransmission Control ProtocolUDP🔷 CyanUser Datagram ProtocolICMP/ICMPv6🔴 RedInternet Control Message ProtocolARP🟡 YellowAddress Resolution ProtocolDNS🟣 MagentaDomain Name SystemTLS🟢 GreenTransport Layer SecurityHTTP⚪ WhiteHypertext Transfer ProtocolSSH🔺 Bright RedSecure ShellQUIC🔹 Bright CyanQuick UDP Internet Connections

🔧 Extending NetSentinel
Adding Custom Analyzers
pythonDownloadCopy codeclass MyCustomAnalyzer(Analyzer):
    def __init__(self):
        self.suspicious_ips = set()
    
    def handle(self, pkt: PacketMeta) -> Iterable[Alert]:
        # Your detection logic here
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

📊 Performance
MetricValueMax Queue Size10,000 packetsDashboard Refresh4 fpsBatch Processing50 packets/cycleMemory (typical)~50-100 MBScan Window30 seconds

⚠️ Known Limitations

* Requires root/sudo for live packet capture
* Linux only (uses os.geteuid())
* PCAP write functionality currently unused in main loop
* High-speed networks (>1 Gbps) may experience packet drops


🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (git checkout -b feature/AmazingFeature)
3. Commit your changes (git commit -m 'Add some AmazingFeature')
4. Push to the branch (git push origin feature/AmazingFeature)
5. Open a Pull Request

⚖️ Disclaimer
This tool is intended for authorized network monitoring and security testing only. Users are responsible for ensuring they have proper authorization before capturing network traffic. Unauthorized network monitoring may violate local laws and regulations.

⬆ Back to Top
Made with ❤️ for the security community
