# import scapy.all as scapy
# import time
# from collections import defaultdict

# interface = 'Wi-Fi'

# suspected_ips = defaultdict(lambda: {'pps': 0, 'bps': 0, 'packets': 0, 'bytes': 0})

# def process_packet(packet):
#     global suspected_ips
#     if packet.haslayer(scapy.IP):
#         ip_src = packet[scapy.IP].src
#         ip_dst = packet[scapy.IP].dst
#         packet_size = len(packet)
#         suspected_ips[ip_src]['pps'] += 1
#         suspected_ips[ip_src]['bps'] += packet_size
#         suspected_ips[ip_src]['packets'] += 1
#         suspected_ips[ip_src]['bytes'] += packet_size
#         suspected_ips[ip_dst]['pps'] += 1
#         suspected_ips[ip_dst]['bps'] += packet_size
#         suspected_ips[ip_dst]['packets'] += 1
#         suspected_ips[ip_dst]['bytes'] += packet_size

# def identify_suspicious_ips():
#     suspicious_ips = []
#     pps_threshold = 100
#     bps_threshold = 5000
#     for ip, stats in suspected_ips.items():
#         if stats['pps'] > pps_threshold or stats['bps'] > bps_threshold:
#             suspicious_ips.append(ip)
#     return suspicious_ips

# def generate_traffic_report():
#     print("\n=== Detailed Traffic Report ===")
#     print(f"{'IP Address':<20}{'Packets (PPS)':<20}{'Bytes (BPS)':<20}{'Total Packets':<20}{'Total Bytes':<20}")
#     print("="*100)
#     for ip, stats in suspected_ips.items():
#         print(f"{ip:<20}{stats['pps']:<20}{stats['bps']:<20}{stats['packets']:<20}{stats['bytes']:<20}")
#     print("="*100)

# def monitor_traffic(interval=10):
#     global suspected_ips
#     print(f"Monitoring traffic for {interval} seconds...")
#     scapy.sniff(prn=process_packet, store=False, timeout=interval, iface=interface)

# def traffic_analysis():
#     try:
#         while True:
#             monitor_traffic(interval=5)
#             generate_traffic_report()
#             suspicious_ips = identify_suspicious_ips()
#             if suspicious_ips:
#                 print("Suspicious IPs detected:", suspicious_ips)
#             else:
#                 print("No suspicious IPs detected.")
#             suspected_ips.clear()
#             time.sleep(5)
#     except KeyboardInterrupt:
#         print("Traffic monitoring stopped.")

# if __name__ == "__main__":
#     traffic_analysis()



# import scapy.all as scapy
# import time
# from collections import defaultdict
# import matplotlib.pyplot as plt
# import seaborn as sns

# # Set the network interface to monitor
# interface = 'Wi-Fi'  # Change to your actual interface name

# # Stores traffic statistics
# suspected_ips = defaultdict(lambda: {'pps': 0, 'bps': 0, 'packets': 0, 'bytes': 0})

# # Process each captured packet
# def process_packet(packet):
#     global suspected_ips
#     if packet.haslayer(scapy.IP):
#         ip_src = packet[scapy.IP].src
#         ip_dst = packet[scapy.IP].dst
#         packet_size = len(packet)

#         # Source IP updates
#         suspected_ips[ip_src]['pps'] += 1
#         suspected_ips[ip_src]['bps'] += packet_size
#         suspected_ips[ip_src]['packets'] += 1
#         suspected_ips[ip_src]['bytes'] += packet_size

#         # Destination IP updates
#         suspected_ips[ip_dst]['pps'] += 1
#         suspected_ips[ip_dst]['bps'] += packet_size
#         suspected_ips[ip_dst]['packets'] += 1
#         suspected_ips[ip_dst]['bytes'] += packet_size

# # Identify suspicious IPs based on thresholds
# def identify_suspicious_ips():
#     suspicious_ips = []
#     pps_threshold = 100
#     bps_threshold = 5000
#     for ip, stats in suspected_ips.items():
#         if stats['pps'] > pps_threshold or stats['bps'] > bps_threshold:
#             suspicious_ips.append(ip)
#     return suspicious_ips

# # Display traffic stats in console
# def generate_traffic_report():
#     print("\n=== Detailed Traffic Report ===")
#     print(f"{'IP Address':<20}{'Packets (PPS)':<20}{'Bytes (BPS)':<20}{'Total Packets':<20}{'Total Bytes':<20}")
#     print("=" * 100)
#     for ip, stats in suspected_ips.items():
#         print(f"{ip:<20}{stats['pps']:<20}{stats['bps']:<20}{stats['packets']:<20}{stats['bytes']:<20}")
#     print("=" * 100)

# # Visualize the traffic using graphs
# def plot_graphs():
#     if not suspected_ips:
#         return

#     ips = list(suspected_ips.keys())
#     pps = [stats['pps'] for stats in suspected_ips.values()]
#     bps = [stats['bps'] for stats in suspected_ips.values()]
#     total_packets = [stats['packets'] for stats in suspected_ips.values()]

#     sns.set(style="whitegrid")
#     num_ips = len(ips)
#     width = max(10, num_ips * 1.2)

#     # PPS Vertical Bar Chart
#     plt.figure(figsize=(width, 6))
#     sns.barplot(x=ips, y=pps, palette="Blues_d")
#     plt.title("Packets Per Second (PPS) per IP")
#     plt.xlabel("IP Address")
#     plt.ylabel("Packets Per Second")
#     plt.xticks(rotation=60, ha='right')
#     plt.tight_layout()
#     plt.show()

#     # BPS Vertical Bar Chart
#     plt.figure(figsize=(width, 6))
#     sns.barplot(x=ips, y=bps, palette="Oranges_d")
#     plt.title("Bytes Per Second (BPS) per IP")
#     plt.xlabel("IP Address")
#     plt.ylabel("Bytes Per Second")
#     plt.xticks(rotation=60, ha='right')
#     plt.tight_layout()
#     plt.show()

#     # Pie Chart for Packet Distribution with Legend
#     plt.figure(figsize=(15, 15))
#     wedges, texts, autotexts = plt.pie(
#         total_packets,
#         autopct='%1.1f%%',
#         startangle=140
#     )
#     plt.legend(wedges, ips, title="IP Addresses", loc="center left", bbox_to_anchor=(1, 0.5))
#     plt.title("Packet Distribution Among IPs")
#     plt.tight_layout()
#     plt.show()

# # Capture traffic for a set interval
# def monitor_traffic(interval=10):
#     global suspected_ips
#     print(f"Monitoring traffic for {interval} seconds...")
#     scapy.sniff(prn=process_packet, store=False, timeout=interval, iface=interface)

# # Main loop for live analysis
# def traffic_analysis():
#     try:
#         while True:
#             monitor_traffic(interval=5)
#             generate_traffic_report()
#             plot_graphs()
#             suspicious_ips = identify_suspicious_ips()
#             if suspicious_ips:
#                 print("Suspicious IPs detected:", suspicious_ips)
#             else:
#                 print("No suspicious IPs detected.")
#             suspected_ips.clear()
#             time.sleep(5)
#     except KeyboardInterrupt:
#         print("Traffic monitoring stopped.")

# # Entry point
# if __name__ == "__main__":
#     traffic_analysis()





# import scapy.all as scapy
# import time
# from collections import defaultdict
# import matplotlib.pyplot as plt
# import seaborn as sns

# # Set the network interface to monitor
# interface = 'Wi-Fi'  # Change to your actual interface

# # Dictionary to track statistics
# suspected_ips = defaultdict(lambda: {'pps': 0, 'bps': 0, 'packets': 0, 'bytes': 0})

# # Process captured packets
# def process_packet(packet):
#     global suspected_ips
#     if packet.haslayer(scapy.IP):
#         ip_src = packet[scapy.IP].src
#         ip_dst = packet[scapy.IP].dst
#         packet_size = len(packet)

#         # Update source IP
#         suspected_ips[ip_src]['pps'] += 1
#         suspected_ips[ip_src]['bps'] += packet_size
#         suspected_ips[ip_src]['packets'] += 1
#         suspected_ips[ip_src]['bytes'] += packet_size

#         # Update destination IP
#         suspected_ips[ip_dst]['pps'] += 1
#         suspected_ips[ip_dst]['bps'] += packet_size
#         suspected_ips[ip_dst]['packets'] += 1
#         suspected_ips[ip_dst]['bytes'] += packet_size

# # Identify IPs that exceed thresholds
# def identify_suspicious_ips():
#     suspicious_ips = []
#     pps_threshold = 100
#     bps_threshold = 5000
#     for ip, stats in suspected_ips.items():
#         if stats['pps'] > pps_threshold or stats['bps'] > bps_threshold:
#             suspicious_ips.append(ip)
#     return suspicious_ips

# # Print a detailed traffic table
# def generate_traffic_report():
#     print("\n=== Detailed Traffic Report ===")
#     print(f"{'IP Address':<20}{'Packets (PPS)':<20}{'Bytes (BPS)':<20}{'Total Packets':<20}{'Total Bytes':<20}")
#     print("=" * 100)
#     for ip, stats in suspected_ips.items():
#         print(f"{ip:<20}{stats['pps']:<20}{stats['bps']:<20}{stats['packets']:<20}{stats['bytes']:<20}")
#     print("=" * 100)

# # Plot graphs: PPS, BPS, and Total Packets
# def plot_graphs():
#     if not suspected_ips:
#         return

#     ips = list(suspected_ips.keys())
#     pps = [stats['pps'] for stats in suspected_ips.values()]
#     bps = [stats['bps'] for stats in suspected_ips.values()]
#     total_packets = [stats['packets'] for stats in suspected_ips.values()]

#     sns.set(style="whitegrid")
#     width = max(10, len(ips) * 1.2)

#     # PPS Bar Graph
#     plt.figure(figsize=(width, 6))
#     sns.barplot(x=ips, y=pps, palette="Blues_d")
#     plt.title("Packets Per Second (PPS) per IP")
#     plt.xlabel("IP Address")
#     plt.ylabel("PPS")
#     plt.xticks(rotation=60, ha='right')
#     plt.tight_layout()
#     plt.show()

#     # BPS Bar Graph
#     plt.figure(figsize=(width, 6))
#     sns.barplot(x=ips, y=bps, palette="Oranges_d")
#     plt.title("Bytes Per Second (BPS) per IP")
#     plt.xlabel("IP Address")
#     plt.ylabel("BPS")
#     plt.xticks(rotation=60, ha='right')
#     plt.tight_layout()
#     plt.show()

#     # Total Packets Graph
#     plt.figure(figsize=(width, 6))
#     sns.barplot(x=ips, y=total_packets, palette="Greens_d")
#     plt.title("Total Packets per IP")
#     plt.xlabel("IP Address")
#     plt.ylabel("Total Packets")
#     plt.xticks(rotation=60, ha='right')
#     plt.tight_layout()
#     plt.show()

# # Capture packets for a specific interval
# def monitor_traffic(interval=10):
#     global suspected_ips
#     print(f"Monitoring traffic for {interval} seconds...")
#     scapy.sniff(prn=process_packet, store=False, timeout=interval, iface=interface)

# # Main loop for continuous monitoring
# def traffic_analysis():
#     try:
#         while True:
#             monitor_traffic(interval=5)
#             generate_traffic_report()
#             plot_graphs()
#             suspicious_ips = identify_suspicious_ips()
#             if suspicious_ips:
#                 print("Suspicious IPs detected:", suspicious_ips)
#             else:
#                 print("No suspicious IPs detected.")
#             suspected_ips.clear()
#             time.sleep(5)
#     except KeyboardInterrupt:
#         print("Traffic monitoring stopped.")

# # Start the program
# if __name__ == "__main__":
#     traffic_analysis()



import scapy.all as scapy
scapy.get_if_list()

import time
from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns

# Set the network interface to monitor
interface = 'Wi-Fi'  # Change to your actual interface name

# Stores traffic statistics
suspected_ips = defaultdict(lambda: {'pps': 0, 'bps': 0, 'packets': 0, 'bytes': 0})

# Process each captured packet
def process_packet(packet):
    global suspected_ips
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        packet_size = len(packet)

        # Source IP updates
        suspected_ips[ip_src]['pps'] += 1
        suspected_ips[ip_src]['bps'] += packet_size
        suspected_ips[ip_src]['packets'] += 1
        suspected_ips[ip_src]['bytes'] += packet_size

        # Destination IP updates
        suspected_ips[ip_dst]['pps'] += 1
        suspected_ips[ip_dst]['bps'] += packet_size
        suspected_ips[ip_dst]['packets'] += 1
        suspected_ips[ip_dst]['bytes'] += packet_size

# Identify suspicious IPs based on thresholds
def identify_suspicious_ips():
    suspicious_ips = []
    pps_threshold = 100
    bps_threshold = 5000
    for ip, stats in suspected_ips.items():
        if stats['pps'] > pps_threshold or stats['bps'] > bps_threshold:
            suspicious_ips.append(ip)
    return suspicious_ips

# Display traffic stats in console
def generate_traffic_report():
    print("\n=== Detailed Traffic Report ===")
    print(f"{'IP Address':<20}{'Packets (PPS)':<20}{'Bytes (BPS)':<20}{'Total Packets':<20}{'Total Bytes':<20}")
    print("=" * 100)
    for ip, stats in suspected_ips.items():
        print(f"{ip:<20}{stats['pps']:<20}{stats['bps']:<20}{stats['packets']:<20}{stats['bytes']:<20}")
    print("=" * 100)

# Visualize the traffic using graphs
def plot_graphs():
    if not suspected_ips:
        return

    ips = list(suspected_ips.keys())
    pps = [stats['pps'] for stats in suspected_ips.values()]
    bps = [stats['bps'] for stats in suspected_ips.values()]
    total_packets = [stats['packets'] for stats in suspected_ips.values()]

    sns.set(style="whitegrid")
    num_ips = len(ips)
    width = max(10, num_ips * 1.2)

    # PPS Vertical Bar Chart
    plt.figure(figsize=(width, 6))
    sns.barplot(x=ips, y=pps, palette="Blues_d")
    plt.title("Packets Per Second (PPS) per IP")
    plt.xlabel("IP Address")
    plt.ylabel("Packets Per Second")
    plt.xticks(rotation=60, ha='right')
    plt.tight_layout()
    plt.show()

    # BPS Vertical Bar Chart
    plt.figure(figsize=(width, 6))
    sns.barplot(x=ips, y=bps, palette="Oranges_d")
    plt.title("Bytes Per Second (BPS) per IP")
    plt.xlabel("IP Address")
    plt.ylabel("Bytes Per Second")
    plt.xticks(rotation=60, ha='right')
    plt.tight_layout()
    plt.show()

    # Pie Chart without slice percentages, but with side legend including percentages
    total = sum(total_packets)
    percentages = [(count / total) * 100 for count in total_packets]
    labels_with_percent = [f"{ip} ({p:.1f}%)" for ip, p in zip(ips, percentages)]

    plt.figure(figsize=(15, 15))
    wedges, texts = plt.pie(
        total_packets,
        startangle=140
    )
    plt.legend(wedges, labels_with_percent, title="IP Addresses", loc="center left", bbox_to_anchor=(1, 0.5))
    plt.title("Packet Distribution Among IPs")
    plt.tight_layout()
    plt.show()

# Capture traffic for a set interval
def monitor_traffic(interval=10):
    global suspected_ips
    print(f"Monitoring traffic for {interval} seconds...")
    scapy.sniff(prn=process_packet, store=False, timeout=interval, iface=interface)

# Main loop for live analysis
def traffic_analysis():
    try:
        while True:
            monitor_traffic(interval=5)
            generate_traffic_report()
            plot_graphs()
            suspicious_ips = identify_suspicious_ips()
            if suspicious_ips:
                print("Suspicious IPs detected:", suspicious_ips)
            else:
                print("No suspicious IPs detected.")
            suspected_ips.clear()
            time.sleep(5)
    except KeyboardInterrupt:
        print("Traffic monitoring stopped.")

# Entry point
if __name__ == "__main__":
    traffic_analysis()
