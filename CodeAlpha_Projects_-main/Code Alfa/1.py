from scapy.all import *
import sys

def packet_handler(packet):
    print("Packet captured!")  # Debug statement
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        print(f"IP Packet: {ip_src} -> {ip_dst} Protocol: {proto}")

        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"TCP Segment: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")

        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"UDP Segment: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")

        elif ICMP in packet:
            print("ICMP Packet")

def start_sniffing(interface=None):
    print("Starting packet capture...")
    if interface:
        print(f"Sniffing on interface: {interface}")
        sniff(iface=interface, prn=packet_handler, store=False)
    else:
        print("Sniffing on default interface")
        sniff(prn=packet_handler, store=False)

if __name__ == "__main__":
    interface = sys.argv[1] if len(sys.argv) > 1 else None
    start_sniffing(interface)