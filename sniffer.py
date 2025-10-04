#!/usr/bin/env python3
from scapy.all import *
import time

print("🚀 Simple Network Sniffer Starting...")
print("Press Ctrl+C to stop\n")

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        print(f"{time.strftime('%H:%M:%S')} | {src_ip} -> {dst_ip} | {protocol}")

try:
    sniff(iface="en0", prn=packet_handler, count=10, timeout=20)
    print("✅ Capture completed!")
except Exception as e:
    print(f"❌ Error: {e}")
