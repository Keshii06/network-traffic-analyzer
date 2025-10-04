#!/usr/bin/env python3
from scapy.all import *
import matplotlib.pyplot as plt
import pandas as pd
from collections import defaultdict
import time

class VisualSniffer:
    def __init__(self):
        self.packet_data = []
        self.protocol_count = defaultdict(int)
        self.source_ips = defaultdict(int)
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
            self.source_ips[packet[IP].src] += 1
            
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
            else:
                packet_info['protocol'] = 'Other'
                
            self.protocol_count[packet_info['protocol']] += 1
            
        self.packet_data.append(packet_info)
        print(f"[{self.packet_count:02d}] {time.strftime('%H:%M:%S')} | {packet_info['src_ip']:15} -> {packet_info['dst_ip']:15} | {packet_info['protocol']} | {packet_info['size']:4} bytes")

    def create_visualizations(self):
        print("\n📊 Creating Visualizations...")
        
        # Create a dashboard with 4 charts
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('Network Traffic Analysis Dashboard', fontsize=16, fontweight='bold')
        
        # 1. Protocol Distribution Pie Chart
        protocols = list(self.protocol_count.keys())
        counts = list(self.protocol_count.values())
        colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']
        ax1.pie(counts, labels=protocols, autopct='%1.1f%%', colors=colors, startangle=90)
        ax1.set_title('Protocol Distribution')
        
        # 2. Top Source IPs Bar Chart
        top_sources = sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True)[:6]
        if top_sources:
            sources, counts = zip(*top_sources)
            bars = ax2.bar(sources, counts, color='skyblue', edgecolor='black')
            ax2.set_title('Top Source IPs')
            ax2.tick_params(axis='x', rotation=45)
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height,
                        f'{int(height)}', ha='center', va='bottom')
        
        # 3. Packet Size Distribution
        packet_sizes = [p['size'] for p in self.packet_data]
        ax3.hist(packet_sizes, bins=15, alpha=0.7, color='lightgreen', edgecolor='black')
        ax3.set_title('Packet Size Distribution')
        ax3.set_xlabel('Packet Size (bytes)')
        ax3.set_ylabel('Frequency')
        
        # 4. Traffic Over Time
        if len(self.packet_data) > 1:
            time_series = defaultdict(int)
            start_time = self.packet_data[0]['timestamp']
            for packet in self.packet_data:
                time_key = int(packet['timestamp'] - start_time)
                time_series[time_key] += 1
            
            times, counts = zip(*sorted(time_series.items()))
            ax4.plot(times, counts, 'ro-', linewidth=2, markersize=4)
            ax4.set_title('Packets Over Time')
            ax4.set_xlabel('Time (seconds)')
            ax4.set_ylabel('Packets per second')
            ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('network_dashboard.png', dpi=300, bbox_inches='tight')
        print("✅ Dashboard saved as 'network_dashboard.png'")
        plt.show()

    def generate_report(self):
        print("\n" + "="*50)
        print("📊 NETWORK TRAFFIC ANALYSIS REPORT")
        print("="*50)
        
        print(f"\nTotal packets captured: {len(self.packet_data)}")
        
        print("\nProtocol Distribution:")
        for protocol, count in sorted(self.protocol_count.items(), key=lambda x: x[1], reverse=True):
            percent = (count / len(self.packet_data)) * 100
            print(f"  {protocol:6}: {count:3} packets ({percent:5.1f}%)")
        
        # Save to CSV
        df = pd.DataFrame(self.packet_data)
        df.to_csv('network_traffic_analysis.csv', index=False)
        print(f"\n💾 Data exported to 'network_traffic_analysis.csv'")

def main():
    sniffer = VisualSniffer()
    print("🚀 Visual Network Sniffer Starting...")
    print("Press Ctrl+C to stop\n")
    
    try:
        sniff(iface="en0", prn=sniffer.packet_handler, count=30, timeout=40)
        sniffer.generate_report()
        sniffer.create_visualizations()
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
