"""
packet_sniffer.py
Captures live network packets and extracts basic flow features
for real-time intrusion detection.

Requires: scapy (pip install scapy)
Note: Requires root/admin privileges to sniff network interfaces.
"""

from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import csv
import os

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTPUT_FILE = os.path.join(_PROJECT_ROOT, "data", "raw", "live_capture.csv")

FIELDNAMES = [
    "timestamp", "src_ip", "dst_ip", "protocol",
    "src_port", "dst_port", "packet_size", "ttl"
]


def _ensure_output_file():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    if not os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()


def process_packet(packet):
    """Extract relevant fields from a captured packet and append to CSV."""
    if IP not in packet:
        return

    record = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": packet[IP].proto,
        "src_port": None,
        "dst_port": None,
        "packet_size": len(packet),
        "ttl": packet[IP].ttl,
    }

    if TCP in packet:
        record["src_port"] = packet[TCP].sport
        record["dst_port"] = packet[TCP].dport
        record["protocol"] = "TCP"
    elif UDP in packet:
        record["src_port"] = packet[UDP].sport
        record["dst_port"] = packet[UDP].dport
        record["protocol"] = "UDP"

    with open(OUTPUT_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writerow(record)

    print(f"[CAPTURED] {record['src_ip']} -> {record['dst_ip']} "
          f"({record['protocol']}, {record['packet_size']} bytes)")


def start_sniffing(interface=None, packet_count=0):
    """
    Start sniffing network traffic.

    Args:
        interface: Network interface name (e.g., 'eth0'). None = default interface.
        packet_count: Number of packets to capture (0 = infinite, until Ctrl+C).
    """
    _ensure_output_file()
    print(f"[INFO] Starting packet capture on interface: {interface or 'default'}")
    print(f"[INFO] Writing captured data to: {OUTPUT_FILE}")
    print("[INFO] Press Ctrl+C to stop.\n")

    sniff(iface=interface, prn=process_packet, count=packet_count, store=False)


if __name__ == "__main__":
    start_sniffing()
