from scapy.all import sniff, IP, TCP, UDP
from collections import Counter
import time

# Define thresholds
SCAN_THRESHOLD = 10  # Number of connection attempts to a single host (port scanning)
TRAFFIC_THRESHOLD = 100  # Number of packets in a short time window

# Store information about packets
packet_counts = Counter()

def detect_scan(packet):
    """Detects port scanning activities."""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        
        # Count connection attempts
        packet_counts[(src_ip, dst_ip, dst_port)] += 1
        if packet_counts[(src_ip, dst_ip, dst_port)] > SCAN_THRESHOLD:
            print(f"[ALERT] Possible port scan detected from {src_ip} to {dst_ip} on port {dst_port}")

def detect_flood(packet):
    """Detects flooding or unusual traffic volumes."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        
        # Increment packet count for source IP
        packet_counts[src_ip] += 1
        if packet_counts[src_ip] > TRAFFIC_THRESHOLD:
            print(f"[ALERT] Possible flooding detected from {src_ip}")

def packet_callback(packet):
    """Processes each captured packet."""
    try:
        detect_scan(packet)
        detect_flood(packet)
    except Exception as e:
        print(f"Error processing packet: {e}")

def reset_counters():
    """Resets packet counters periodically to avoid stale data."""
    while True:
        time.sleep(10)  # Reset every 10 seconds
        packet_counts.clear()

def main():
    print("Starting Network Intrusion Detection System...")
    print("Press Ctrl+C to stop.")
    try:
        # Start sniffing on all interfaces
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nStopping NIDS.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
