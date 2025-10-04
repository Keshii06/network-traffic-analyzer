#!/usr/bin/env python3
from scapy.all import *
import matplotlib.pyplot as plt
import pandas as pd
from collections import defaultdict
import time

class AdvancedSniffer:
    def __init__(self):
        self.packet_data = []
        self.protocol_count = defaultdict(int)
        self.packet_count = 0
        
    def packet_handler(self, packet):
        self.packet_count += 1
        packet_info = {
            'timestamp': time.time(),
            'src_ip': 'Unknown',
            'dst_ip': 'Unknown', 
            'protocol': 'Unknown',
            'size': len(packet)
        }
        
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                
            self.protocol_count[packet_info['protocol']] += 1
            
        self.packet_data.append(packet_info)
        print(f"[{self.packet_count:02d}] {time.strftime('%H:%M:%S')} | {packet_info['src_ip']:15} -> {packet_info['dst_ip']:15} | {packet_info['protocol']} | {packet_info['size']:4} bytes")

    def generate_report(self):
        print("\n" + "="*50)
        print("📊 NETWORK TRAFFIC ANALYSIS REPORT")
        print("="*50)
        
        print(f"\nTotal packets: {len(self.packet_data)}")
        
        print("\nProtocol Distribution:")
        for protocol, count in self.protocol_count.items():
            percent = (count / len(self.packet_data)) * 100
            print(f"  {protocol}: {count} packets ({percent:.1f}%)")
            
        # Save to CSV
        df = pd.DataFrame(self.packet_data)
        df.to_csv('network_traffic.csv', index=False)
        print("\n💾 Data saved to 'network_traffic.csv'")

def main():
    sniffer = AdvancedSniffer()
    print("🚀 Advanced Network Sniffer Starting...")
    print("Press Ctrl+C to stop\n")
    
    try:
        sniff(iface="en0", prn=sniffer.packet_handler, count=20, timeout=30)
        sniffer.generate_report()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

