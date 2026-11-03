from scapy.all import sniff, IP, TCP, UDP

packet_count = 0

def process_packet(packet):
    global packet_count

    if IP in packet:
        packet_count += 1

        source = packet[IP].src
        destination = packet[IP].dst
        protocol = packet[IP].proto
        size = len(packet)

        if TCP in packet:
            protocol_name = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            protocol_name = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        else:
            protocol_name = str(protocol)
            source_port = "-"
            destination_port = "-"

        print(
            f"Packet {packet_count}: "
            f"{source}:{source_port} -> "
            f"{destination}:{destination_port} | "
            f"{protocol_name} | {size} bytes"
        )


print("CyberShield Packet Capture Test")
print("Capturing 20 IP packets...")
print("Press Ctrl+C to stop early.\n")

sniff(
    iface="Wi-Fi",
    filter="ip",
    prn=process_packet,
    count=20,
    store=False
)

print("\nCapture completed.")
print("Total packets captured:", packet_count)