#!/usr/bin/env python3
"""
Mini Network Traffic Analyzer / NIDS
-------------------------------------
Live packet capture + anomaly detection (SYN scan, unencrypted traffic)
Exports captured session to PCAP and CSV.

Requirements:
    pip install scapy rich

Run with root/admin privileges (packet sniffing needs raw socket access):
    sudo python3 mini_nids.py

Press Ctrl+C to stop capture and auto-export.
"""

import csv
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Console

console = Console()


# ---------------------------------------------------------------------
# Interface selection (Windows adapters are often not picked correctly
# by default, so let the user choose explicitly)
# ---------------------------------------------------------------------
def choose_interface():
    try:
        from scapy.all import get_windows_if_list
        interfaces = get_windows_if_list()
    except ImportError:
        # not on Windows, fall back to default scapy behaviour
        return None

    if not interfaces:
        console.print("[red]No network interfaces found by Scapy.[/red]")
        sys.exit(1)

    console.print("[bold cyan]Available network interfaces:[/bold cyan]")
    for idx, iface in enumerate(interfaces):
        name = iface.get("name", "?")
        desc = iface.get("description", "")
        console.print(f"  [{idx}] {name}  -  {desc}")

    while True:
        choice = console.input("\nSelect interface number to sniff on: ").strip()
        if choice.isdigit() and 0 <= int(choice) < len(interfaces):
            selected = interfaces[int(choice)]
            console.print(f"[green]Using interface:[/green] {selected['name']}\n")
            return selected["name"]
        console.print("[yellow]Invalid choice, try again.[/yellow]")

# ---------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------
MAX_ROWS_DISPLAYED = 15          # how many recent packets to show in table
SYN_THRESHOLD = 10                # SYNs from one IP within window = scan alert
SYN_WINDOW_SECONDS = 5

packet_log = deque(maxlen=1000)   # for CSV/PCAP export + display
raw_packets = []                  # scapy packet objects for wrpcap()

ip_packet_count = defaultdict(int)      # total packets per source IP
ip_data_bytes = defaultdict(int)        # total bytes per source IP
syn_timestamps = defaultdict(list)      # source IP -> list of SYN times
alerts = deque(maxlen=10)               # recent alerts to display

unique_hosts = set()
total_packets = 0
start_time = time.time()

COMMON_PORTS = {
    80: "HTTP (Web)", 443: "HTTPS (Web)", 22: "SSH",
    21: "FTP", 25: "SMTP", 53: "DNS", 993: "IMAPS", 995: "POP3S",
}

# ---------------------------------------------------------------------
# Core packet handler
# ---------------------------------------------------------------------
def classify_service(sport, dport):
    """Return a readable service name for the packet."""
    if dport in COMMON_PORTS:
        return COMMON_PORTS[dport]
    if sport in COMMON_PORTS:
        return COMMON_PORTS[sport]
    return f"Port {dport}"


def check_syn_scan(src_ip):
    """Track SYN packets per source IP; flag if too many within window."""
    now = time.time()
    syn_timestamps[src_ip].append(now)
    # keep only timestamps within the window
    syn_timestamps[src_ip] = [t for t in syn_timestamps[src_ip] if now - t <= SYN_WINDOW_SECONDS]

    if len(syn_timestamps[src_ip]) >= SYN_THRESHOLD:
        msg = f"[{datetime.now().strftime('%H:%M:%S')}] Possible SYN scan from {src_ip} ({len(syn_timestamps[src_ip])} SYNs/{SYN_WINDOW_SECONDS}s)"
        if msg not in alerts:
            alerts.appendleft(msg)


def process_packet(pkt):
    global total_packets

    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    size = len(pkt)
    proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "ICMP" if ICMP in pkt else "OTHER"

    sport = dport = None
    flags = ""
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = str(pkt[TCP].flags)
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    service = classify_service(sport, dport) if sport else proto

    # unencrypted traffic flag (plain HTTP / FTP / Telnet)
    if dport in (80, 21, 23) or sport in (80, 21, 23):
        msg = f"[{datetime.now().strftime('%H:%M:%S')}] Unencrypted traffic ({service}) {src} -> {dst}"
        if msg not in alerts:
            alerts.appendleft(msg)

    # SYN scan detection: TCP flag 'S' means SYN, without 'A' (ACK)
    if TCP in pkt and "S" in flags and "A" not in flags:
        check_syn_scan(src)

    # update stats
    total_packets += 1
    ip_packet_count[src] += 1
    ip_data_bytes[src] += size
    unique_hosts.add(src)
    unique_hosts.add(dst)

    row = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "time": datetime.now().strftime("%H:%M:%S"),
        "src": src,
        "dst": dst,
        "proto": proto,
        "service": service,
        "size": size,
    }
    packet_log.append(row)
    raw_packets.append(pkt)


# ---------------------------------------------------------------------
# Dashboard rendering
# ---------------------------------------------------------------------
def build_packet_table():
    table = Table(title=f"Live Packet Stream | Packets: {total_packets}", expand=True)
    table.add_column("Time", style="dim")
    table.add_column("Source IP")
    table.add_column("Destination IP")
    table.add_column("Proto")
    table.add_column("Service")
    table.add_column("Size", justify="right")

    for row in list(packet_log)[-MAX_ROWS_DISPLAYED:]:
        table.add_row(row["time"], row["src"], row["dst"], row["proto"], row["service"], f"{row['size']} B")
    return table


def build_top_generators_table():
    table = Table(title="Top Network Generators")
    table.add_column("IP Address")
    table.add_column("Packets", justify="right")
    table.add_column("Data (KB)", justify="right")

    top = sorted(ip_packet_count.items(), key=lambda x: x[1], reverse=True)[:10]
    for ip, count in top:
        kb = ip_data_bytes[ip] / 1024
        table.add_row(ip, str(count), f"{kb:.1f}")
    return table


def build_telemetry_panel():
    elapsed = max(time.time() - start_time, 1)
    velocity = total_packets / elapsed
    lines = [
        f"Velocity: {velocity:.1f} pkts/sec",
        f"Unique Hosts Detected: {len(unique_hosts)}",
        f"Total Packets: {total_packets}",
        "",
        "[bold]Recent Alerts:[/bold]",
    ]
    if alerts:
        lines.extend(f"- {a}" for a in list(alerts)[:6])
    else:
        lines.append("- None yet")
    return Panel("\n".join(lines), title="Telemetry & Watchlist")


def build_dashboard():
    layout = Layout()
    layout.split_column(
        Layout(build_packet_table(), name="stream", ratio=2),
        Layout(name="bottom", ratio=1),
    )
    layout["bottom"].split_row(
        Layout(build_top_generators_table()),
        Layout(build_telemetry_panel()),
    )
    return layout


# ---------------------------------------------------------------------
# Export functions
# ---------------------------------------------------------------------
def export_session():
    if not packet_log:
        console.print("[yellow]No packets captured, nothing to export.[/yellow]")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = f"capture_{timestamp}.csv"
    pcap_path = f"capture_{timestamp}.pcap"

    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["date", "time", "src", "dst", "proto", "service", "size"])
        writer.writeheader()
        writer.writerows(packet_log)

    if raw_packets:
        wrpcap(pcap_path, raw_packets)

    console.print(f"\n[green]Exported:[/green] {csv_path}, {pcap_path}")


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main():
    iface = choose_interface()

    console.print("[bold cyan]Mini NIDS - Live Capture Starting...[/bold cyan]")
    console.print("[dim]Press Ctrl+C to stop and export session.[/dim]\n")
    time.sleep(1)

    try:
        with Live(build_dashboard(), refresh_per_second=2, screen=True) as live:
            def sniff_and_update(pkt):
                process_packet(pkt)
                live.update(build_dashboard())

            sniff_kwargs = {"prn": sniff_and_update, "store": False}
            if iface:
                sniff_kwargs["iface"] = iface
            sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        pass
    finally:
        export_session()


if __name__ == "__main__":
    main()
