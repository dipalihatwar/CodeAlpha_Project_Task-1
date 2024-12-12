from scapy.all import sniff, IP, Ether, TCP, UDP, ICMP

def packet_analyzer(packet):
    if IP in packet:
        # Extract IP layer details
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto
        ttl = packet[IP].ttl
        packet_length = len(packet)
        
        print(f"Source IP: {source_ip}, Destination IP: {destination_ip}")
        print(f"Protocol: {protocol}, TTL: {ttl}, Length: {packet_length}")
        
        # Check if Ethernet layer is present
        if Ether in packet:
            source_mac = packet[Ether].src
            destination_mac = packet[Ether].dst
            print(f"Source MAC: {source_mac}, Destination MAC: {destination_mac}")
        
        # Handle specific protocols
        if protocol == 6 and TCP in packet:  # TCP
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            tcp_seq = packet[TCP].seq
            tcp_flags = packet[TCP].flags
            print(f"TCP Source Port: {tcp_sport}, Destination Port: {tcp_dport}")
            print(f"Sequence: {tcp_seq}, Flags: {tcp_flags}")
        
        elif protocol == 17 and UDP in packet:  # UDP
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"UDP Source Port: {udp_sport}, Destination Port: {udp_dport}")
        
        elif protocol == 1 and ICMP in packet:  # ICMP
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(f"ICMP Type: {icmp_type}, Code: {icmp_code}")
        
        else:
            print("Other or Unknown Protocol")
        
        print("-" * 50)

def main():
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    # Start sniffing packets and analyze each
    sniff(prn=packet_analyzer, store=0)

if __name__ == "__main__":
    main()
