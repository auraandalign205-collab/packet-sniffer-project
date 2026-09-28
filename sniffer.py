import sys
from scapy.all import sniff, IP, TCP, UDP, Raw
# Keep track of metrics for project statistics
stats = {"TCP": 0, "UDP": 0, "TOTAL": 0}

def process_packet(packet):
    if packet.haslayer(IP):
        stats["TOTAL"] += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"
        src_port = "N/A"
        dst_port = "N/A"
        
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            stats["TCP"] += 1
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            stats["UDP"] += 1

        print(f"\n[+] {protocol} Packet | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        
        # Analyze and format the payload
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            # If it looks like plain text (like your SSDP/M-SEARCH packet), print it cleanly
            if b"HTTP" in payload or b"SEARCH" in payload:
                print(f"    ↳ Plaintext Data: {payload.decode('utf-8', errors='ignore').strip()}")
            else:
                # Format encrypted bytes cleanly into a short hex string snippet
                hex_data = ' '.join(f'{b:02x}' for b in payload[:16])
                print(f"    ↳ Payload (Hex): {hex_data} ...")

def show_summary():
    print("\n\n" + "="*40)
    print("         SESSION TRAFFIC SUMMARY         ")
    print("="*40)
    print(f" Total Packets Captured : {stats['TOTAL']}")
    print(f" TCP Packets            : {stats['TCP']}")
    print(f" UDP Packets            : {stats['UDP']}")
    print("="*40)
    print("[*] Project closed successfully.")

if __name__ == "__main__":
    print("="*50)
    print("  CYBERSECURITY PACKET SNIFFER (SCAPY ENGINE)  ")
    print("="*50)
    print("[*] Monitoring network interface card...")
    print("[*] Press Ctrl+C to safely exit and view metrics.")
    
    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        show_summary()
        sys.exit(0)