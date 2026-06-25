from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

print("=" * 60)
print("      CodeAlpha - Basic Network Sniffer")
print("      Internship Task 1 | By: Tamizharasan")
print("=" * 60)

packet_count = 0

def analyze_packet(packet):
    global packet_count
    packet_count += 1
    timestamp = datetime.now().strftime("%H:%M:%S")

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        proto_name = "OTHER"
        info = ""

        if TCP in packet:
            proto_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            info = f"Ports: {src_port} → {dst_port} | Flags: {flags}"

        elif UDP in packet:
            proto_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            info = f"Ports: {src_port} → {dst_port}"

        elif ICMP in packet:
            proto_name = "ICMP"
            info = f"Type: {packet[ICMP].type} | Code: {packet[ICMP].code}"

        payload = ""
        if Raw in packet:
            raw_data = packet[Raw].load
            try:
                payload = raw_data.decode("utf-8", errors="ignore")[:40]
            except:
                payload = str(raw_data)[:40]

        print(f"\n[{packet_count}] [{timestamp}] Protocol: {proto_name}")
        print(f"    SRC: {src_ip}  →  DST: {dst_ip}")
        print(f"    {info}")
        if payload:
            print(f"    Payload: {payload}")
        print("-" * 60)

print("\n[*] Starting packet capture... Press Ctrl+C to stop.\n")
try:
    sniff(prn=analyze_packet, store=False, count=30)
except KeyboardInterrupt:
    print(f"\n[*] Capture stopped. Total packets captured: {packet_count}")
