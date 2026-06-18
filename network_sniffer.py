from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = ""
        info = ""

        if TCP in packet:
            protocol = "TCP"
            info = f"Port {packet[TCP].sport} → {packet[TCP].dport}"
        elif UDP in packet:
            protocol = "UDP"
            info = f"Port {packet[UDP].sport} → {packet[UDP].dport}"
        elif ICMP in packet:
            protocol = "ICMP"
            info = "Ping packet"
        else:
            protocol = "OTHER"
            info = ""

        print(f"[{protocol}] {src_ip} → {dst_ip}  |  {info}")

print("Network Sniffer Started... Press Ctrl+C to stop\n")
sniff(prn=packet_handler, store=0, count=20)
print("\nDone! 20 packets captured.")
