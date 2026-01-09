from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def analyze_packet(packet):
    # Check if packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        print("\n==============================")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {protocol}")

        # Display payload if available
        if Raw in packet:
            payload = packet[Raw].load
            try:
                print(f"Payload        : {payload.decode(errors='ignore')}")
            except:
                print("Payload        : [Binary Data]")
        else:
            print("Payload        : None")

        print("==============================")

def start_sniffing():
    print("Starting packet capture... Press Ctrl+C to stop.")
    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
