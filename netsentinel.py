#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, time, math, json, queue, threading, socket, datetime, re
from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Any, Iterable, List, Deque
from collections import deque, Counter, defaultdict
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.align import Align
from rich import box
import typer
from scapy.all import sniff, PcapReader, PcapWriter, IP, IPv6, TCP, UDP, ARP, Ether, Raw, DNS, conf

try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False

console = Console()
app = typer.Typer(add_completion=False, help="NetSentinel")

PROTO_COLORS = {
    "TCP": "blue", "UDP": "cyan", "ICMP": "red", "ICMPv6": "red",
    "ARP": "yellow", "DNS": "magenta", "TLS": "green", "HTTP": "white",
    "SSH": "bright_red", "QUIC": "bright_cyan"
}

def now_ms() -> int:
    return int(time.time() * 1000)

def fmt_bytes(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024: return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"

def is_private_ip(ip: str) -> bool:
    return ip.startswith(("192.168.", "10.", "172.16.", "127.", "fe80:", "::1"))

def get_country(ip: str, reader) -> str:
    if not HAS_GEOIP or not reader or is_private_ip(ip):
        return "LOC" if is_private_ip(ip) else "??"
    try:
        response = reader.country(ip)
        return response.country.iso_code or "??"
    except:
        return "??"

def safe_parse_tls_sni(payload: bytes) -> Optional[str]:
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
            return None
        p = 43
        if p >= len(payload): return None
        sid_len = payload[p]; p += 1 + sid_len
        if p + 2 > len(payload): return None
        p += 2 + int.from_bytes(payload[p:p+2], 'big')
        if p + 1 > len(payload): return None
        p += 1 + payload[p]
        if p + 2 > len(payload): return None
        ext_len = int.from_bytes(payload[p:p+2], 'big'); p += 2
        end = min(len(payload), p + ext_len)
        while p + 4 <= end:
            etype = int.from_bytes(payload[p:p+2], 'big')
            elen = int.from_bytes(payload[p+2:p+4], 'big')
            p += 4
            if p + elen > end: break
            if etype == 0:
                if p + 2 > end: break
                list_len = int.from_bytes(payload[p:p+2], 'big')
                if p + 2 + list_len > end: break
                q = p + 2
                while q + 3 <= p + 2 + list_len:
                    ntype = payload[q]
                    nlen = int.from_bytes(payload[q+1:q+3], 'big')
                    if ntype == 0:
                        return payload[q+3:q+3+nlen].decode(errors='ignore')
                    q += 3 + nlen
                break
            p += elen
        return None
    except:
        return None

def extract_http_host(payload: bytes) -> Optional[str]:
    try:
        if not payload.startswith((b'GET', b'POST', b'HEAD', b'PUT', b'DELETE', b'CONNECT')):
            return None
        lines = payload.split(b'\r\n', 10)
        for ln in lines:
            if ln.lower().startswith(b'host:'):
                return ln.split(b':', 1)[1].strip().decode(errors='ignore')
    except:
        pass
    return None

@dataclass
class Alert:
    ts_ms: int
    rule: str
    severity: str
    summary: str
    src: str = ""
    dst: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    def to_dict(self):
        return asdict(self)

@dataclass
class PacketMeta:
    ts_ms: int
    length: int
    proto: str
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    flags: Optional[int] = None
    info: str = ""
    payload: bytes = b""
    mac_src: str = ""
    mac_dst: str = ""
    country_src: str = ""
    country_dst: str = ""

class Analyzer:
    def handle(self, pkt: PacketMeta) -> Iterable[Alert]:
        return []

class ARPAnalyzer(Analyzer):
    def __init__(self):
        self.ip_mac_map: Dict[str, str] = {}
        self.mac_history: Dict[str, set] = defaultdict(set)
    def handle(self, pkt: PacketMeta) -> Iterable[Alert]:
        if pkt.proto != "ARP": return []
        if pkt.src and pkt.mac_src:
            if pkt.src in self.ip_mac_map:
                known_mac = self.ip_mac_map[pkt.src]
                if known_mac != pkt.mac_src:
                    self.mac_history[pkt.src].add(pkt.mac_src)
                    if len(self.mac_history[pkt.src]) > 1:
                        yield Alert(pkt.ts_ms, "arp-spoofing", "high", f"MAC Conflict {pkt.src}", src=pkt.src, extra={"mac_old": known_mac, "mac_new": pkt.mac_src})
            self.ip_mac_map[pkt.src] = pkt.mac_src
        return []

class PortScanAnalyzer(Analyzer):
    def __init__(self):
        self.scans: Dict[str, set] = defaultdict(set)
        self.last_clean = now_ms()
        self.window = 30000
    def handle(self, pkt: PacketMeta) -> Iterable[Alert]:
        if pkt.proto not in ("TCP", "UDP"): return []
        if pkt.flags is not None and (pkt.flags & 0x12 == 0x02):
            self.scans[pkt.src].add(pkt.dport)
            count = len(self.scans[pkt.src])
            if pkt.ts_ms - self.last_clean > self.window:
                self.scans.clear()
                self.last_clean = pkt.ts_ms
            if count == 20:
                yield Alert(pkt.ts_ms, "port-scan-vertical", "medium", f"Scan: {count}+ ports", src=pkt.src)
            elif count > 100 and count % 100 == 0:
                yield Alert(pkt.ts_ms, "port-scan-massivo", "high", f"Mass Scan: {count}+ ports", src=pkt.src)
        return []

class ProtocolAnomalyAnalyzer(Analyzer):
    def handle(self, pkt: PacketMeta) -> Iterable[Alert]:
        if pkt.proto == "TCP" and pkt.dport not in [80, 443, 53, 8080, 22] and pkt.dport > 1024:
            if b"ssh-" in pkt.payload.lower():
                 yield Alert(pkt.ts_ms, "ssh-high-port", "low", f"SSH on high port {pkt.dport}", src=pkt.src, dst=pkt.dst)
        if pkt.proto == "TCP" and pkt.payload:
            if b"User-Agent: " in pkt.payload:
                ua = ""
                try:
                    head = pkt.payload.split(b"\r\n\r\n")[0]
                    for line in head.split(b"\r\n"):
                        if line.lower().startswith(b"user-agent:"):
                            ua = line.split(b":", 1)[1].strip().decode(errors='ignore')
                            break
                except: pass
                lower_ua = ua.lower()
                if "sqlmap" in lower_ua or "nikto" in lower_ua or "nmap" in lower_ua or "hydra" in lower_ua:
                    yield Alert(pkt.ts_ms, "tool-ua", "high", f"Attack Tool: {ua[:30]}", src=pkt.src, extra={"ua": ua})
        if pkt.proto == "TCP" and pkt.info.startswith("TLS"):
            sni = pkt.info.replace("TLS ", "")
            if sni.endswith(".local") or sni.endswith(".lan"):
                 yield Alert(pkt.ts_ms, "tls-local-sni", "low", f"Local SNI: {sni}", src=pkt.src)
        return []

class CaptureEngine:
    def __init__(self, iface: str, bpf: Optional[str], pcap_file: Optional[str], geoip_db: Optional[str]):
        self.iface = iface
        self.bpf = bpf
        self.pcap_file = pcap_file
        self.running = False
        self.queue = queue.Queue(maxsize=10000)
        self.thread = None
        self.geoip_reader = None
        if HAS_GEOIP and geoip_db and os.path.exists(geoip_db):
            try: self.geoip_reader = geoip2.database.Reader(geoip_db)
            except: pass
        self.analyzers: List[Analyzer] = [ARPAnalyzer(), PortScanAnalyzer(), ProtocolAnomalyAnalyzer()]

    def _process_pkt(self, scapy_pkt):
        try:
            ts = int(time.time() * 1000)
            length = len(scapy_pkt)
            meta = PacketMeta(ts_ms=ts, length=length, proto="OTH")
            if scapy_pkt.haslayer(Ether):
                meta.mac_src = scapy_pkt[Ether].src
                meta.mac_dst = scapy_pkt[Ether].dst
            if scapy_pkt.haslayer(IP):
                ip = scapy_pkt[IP]
                meta.src = ip.src
                meta.dst = ip.dst
                meta.proto = "TCP" if ip.proto == 6 else ("UDP" if ip.proto == 17 else ("ICMP" if ip.proto == 1 else str(ip.proto)))
            elif scapy_pkt.haslayer(IPv6):
                ip = scapy_pkt[IPv6]
                meta.src = ip.src
                meta.dst = ip.dst
                meta.proto = "TCP" if ip.nh == 6 else ("UDP" if ip.nh == 17 else ("ICMPv6" if ip.nh == 58 else str(ip.nh)))
            elif scapy_pkt.haslayer(ARP):
                arp = scapy_pkt[ARP]
                meta.proto = "ARP"
                meta.src = arp.psrc
                meta.dst = arp.pdst
                meta.info = f"Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else f"{arp.psrc} is at {arp.hwsrc}"
            if meta.src: meta.country_src = get_country(meta.src, self.geoip_reader)
            if meta.dst: meta.country_dst = get_country(meta.dst, self.geoip_reader)
            if scapy_pkt.haslayer(TCP):
                tcp = scapy_pkt[TCP]
                meta.sport = tcp.sport
                meta.dport = tcp.dport
                meta.flags = int(tcp.flags)
                if scapy_pkt.haslayer(Raw):
                    meta.payload = bytes(scapy_pkt[Raw].load)
                    sni = safe_parse_tls_sni(meta.payload)
                    if sni:
                        meta.info = f"TLS {sni}"
                        meta.proto = "TLS"
                    host = extract_http_host(meta.payload)
                    if host:
                        meta.info = f"HTTP {host}"
                        meta.proto = "HTTP"
                    if not meta.info and (meta.sport == 22 or meta.dport == 22):
                        meta.proto = "SSH"
            elif scapy_pkt.haslayer(UDP):
                udp = scapy_pkt[UDP]
                meta.sport = udp.sport
                meta.dport = udp.dport
                if scapy_pkt.haslayer(DNS) and scapy_pkt[DNS].qd:
                    qname = scapy_pkt[DNS].qd.qname.decode(errors='ignore').rstrip('.')
                    meta.proto = "DNS"
                    meta.info = f"Q {qname}"
                elif scapy_pkt.haslayer(Raw):
                    if (meta.sport == 443 or meta.dport == 443) and len(scapy_pkt[Raw].load) > 1200:
                         meta.proto = "QUIC"
            self.queue.put(meta)
        except Exception:
            pass

    def start(self):
        self.running = True
        def loop():
            if self.pcap_file:
                try:
                    with PcapReader(self.pcap_file) as pcap:
                        for pkt in pcap:
                            if not self.running: break
                            self._process_pkt(pkt)
                            time.sleep(0.0001)
                except Exception as e:
                    self.queue.put(PacketMeta(now_ms(), 0, "ERR", info=str(e)))
                self.running = False
            else:
                try:
                    sniff(iface=self.iface, prn=self._process_pkt, filter=self.bpf, store=False, stop_filter=lambda x: not self.running)
                except Exception as e:
                    self.queue.put(PacketMeta(now_ms(), 0, "ERR", info=f"Sniff Error: {e}"))
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread: self.thread.join(timeout=1.0)
        if self.geoip_reader: self.geoip_reader.close()

class Dashboard:
    def __init__(self):
        self.packets_buf: Deque[PacketMeta] = deque(maxlen=30)
        self.alerts_buf: Deque[Alert] = deque(maxlen=20)
        self.stats_proto = Counter()
        self.stats_talkers = Counter()
        self.total_pkts = 0
        self.total_bytes = 0
        self.start_time = time.time()

    def update(self, pkt: PacketMeta, alerts: List[Alert]):
        self.total_pkts += 1
        self.total_bytes += pkt.length
        self.packets_buf.append(pkt)
        self.stats_proto[pkt.proto] += 1
        if pkt.src: self.stats_talkers[pkt.src] += 1
        for a in alerts:
            self.alerts_buf.append(a)

    def render(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1)
        )
        layout["main"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1)
        )
        layout["right"].split_column(
            Layout(name="top_talkers", ratio=1),
            Layout(name="alerts", ratio=1),
            Layout(name="stats", size=8)
        )
        elapsed = time.time() - self.start_time
        rate = self.total_pkts / elapsed if elapsed > 0 else 0
        header_txt = f"[bold green]NetSentinel[/] | Pkts: {self.total_pkts} | Bytes: {fmt_bytes(self.total_bytes)} | Rate: {rate:.1f} pps | Time: {datetime.timedelta(seconds=int(elapsed))}"
        layout["header"].update(Panel(Align.center(header_txt), style="white on blue"))
        ptable = Table(expand=True, box=box.SIMPLE_HEAD, row_styles=["dim", ""])
        ptable.add_column("Time", width=12)
        ptable.add_column("Proto", width=6)
        ptable.add_column("Source", ratio=1)
        ptable.add_column("Dest", ratio=1)
        ptable.add_column("Info", ratio=2, overflow="fold")
        for p in list(self.packets_buf)[::-1]:
            c = PROTO_COLORS.get(p.proto, "white")
            ts = datetime.datetime.fromtimestamp(p.ts_ms/1000).strftime("%H:%M:%S.%f")[:-3]
            src_fmt = f"{p.src}:{p.sport}" if p.sport else p.src
            dst_fmt = f"{p.dst}:{p.dport}" if p.dport else p.dst
            if p.country_src and p.country_src != "??": src_fmt += f" [{p.country_src}]"
            if p.country_dst and p.country_dst != "??": dst_fmt += f" [{p.country_dst}]"
            ptable.add_row(ts, f"[{c}]{p.proto}[/]", src_fmt, dst_fmt, p.info or "-")
        layout["left"].update(Panel(ptable, title="Live Traffic", border_style="cyan"))
        atable = Table(expand=True, show_header=False, box=None)
        for a in list(self.alerts_buf)[::-1]:
            color = "red" if a.severity == "high" else ("yellow" if a.severity == "medium" else "blue")
            ts = datetime.datetime.fromtimestamp(a.ts_ms/1000).strftime("%H:%M:%S")
            atable.add_row(f"[{color}]{ts} [bold]{a.rule}[/]: {a.summary}[/]")
        layout["alerts"].update(Panel(atable, title="Threat Detection", border_style="red"))
        ttable = Table(expand=True, box=box.SIMPLE)
        ttable.add_column("IP", justify="left")
        ttable.add_column("Pkts", justify="right")
        for ip, count in self.stats_talkers.most_common(10):
            ttable.add_row(ip, str(count))
        layout["top_talkers"].update(Panel(ttable, title="Top Source IPs", border_style="green"))
        stable = Table(expand=True, show_header=False, box=None)
        total = sum(self.stats_proto.values()) or 1
        for proto, count in self.stats_proto.most_common(5):
            pct = (count / total) * 100
            bar_len = int(pct / 4)
            bar = "█" * bar_len
            c = PROTO_COLORS.get(proto, "white")
            stable.add_row(f"[{c}]{proto}[/]", f"{count}", f"({pct:.1f}%) {bar}")
        layout["stats"].update(Panel(stable, title="Protocols", border_style="yellow"))
        return layout

@app.command()
def main(
    iface: str = typer.Option("any", help="Interface"),
    bpf: str = typer.Option(None, help="BPF Filter"),
    read_pcap: str = typer.Option(None, help="Read PCAP"),
    write_pcap: str = typer.Option(None, help="Write PCAP"),
    export_json: str = typer.Option(None, help="JSONL Export"),
    geoip_db: str = typer.Option("GeoLite2-City.mmdb", help="GeoIP DB path"),
    ui: bool = typer.Option(True, help="Show UI"),
    silent: bool = typer.Option(False, help="Silent mode"),
):
    if os.geteuid() != 0 and not read_pcap:
        console.print("[bold red]ERROR:[/] Root privileges required for live capture.")
        raise typer.Exit(1)
    engine = CaptureEngine(iface, bpf, read_pcap, geoip_db)
    pcap_writer = None
    if write_pcap:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"{write_pcap}_{ts}.pcap"
        pcap_writer = PcapWriter(fname, append=True, sync=True)
        console.print(f"[green]Writing PCAP to: {fname}[/]")
    json_file = None
    if export_json:
        json_file = open(export_json, "a", encoding="utf-8")
        console.print(f"[green]Exporting logs to: {export_json}[/]")
    dashboard = Dashboard()
    engine.start()
    try:
        if ui and not silent:
            with Live(dashboard.render(), refresh_per_second=4, console=console) as live:
                while engine.running or not engine.queue.empty():
                    try:
                        batch_count = 0
                        while batch_count < 50:
                            try:
                                pkt = engine.queue.get_nowait()
                            except queue.Empty:
                                break
                            batch_count += 1
                            alerts = []
                            for analyzer in engine.analyzers:
                                alerts.extend(list(analyzer.handle(pkt)))
                            if json_file:
                                doc = {"type": "packet", **asdict(pkt)}
                                doc.pop("payload")
                                json_file.write(json.dumps(doc) + "\n")
                                for a in alerts:
                                    json_file.write(json.dumps({"type": "alert", **a.to_dict()}) + "\n")
                                json_file.flush()
                            dashboard.update(pkt, alerts)
                            live.update(dashboard.render())
                        time.sleep(0.1)
                    except KeyboardInterrupt:
                        break
        else:
            try:
                while engine.running:
                    try:
                        pkt = engine.queue.get(timeout=1.0)
                        alerts = []
                        for analyzer in engine.analyzers:
                            alerts.extend(list(analyzer.handle(pkt)))
                        if json_file:
                            doc = {"type": "packet", **asdict(pkt)}
                            doc.pop("payload")
                            json_file.write(json.dumps(doc) + "\n")
                            for a in alerts:
                                json_file.write(json.dumps({"type": "alert", **a.to_dict()}) + "\n")
                            json_file.flush()
                    except queue.Empty:
                        continue
            except KeyboardInterrupt:
                pass
    finally:
        engine.stop()
        if json_file: json_file.close()
        if pcap_writer: pcap_writer.close()
        console.print("[green]NetSentinel Stopped[/]")

if __name__ == "__main__":
    app()
