# --- IMPORTANT: Add this block to any file in a subdirectory if you run it directly ---
import sys
import os

# Get the path to the project root (pyai_ids directory)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# --- END IMPORTANT BLOCK ---
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Ether, wrpcap
from utils.logger import app_logger
import os # Make sure os is imported for path operations

def parse_pcap_file(pcap_file_path):
    """
    Parses a PCAP file and extracts basic information from packets.
    Returns a list of dictionaries, where each dictionary represents a packet's features.
    """
    app_logger.info(f"Starting to parse PCAP file: {pcap_file_path}")
    parsed_packets = []
    try:
        packets = rdpcap(pcap_file_path)
        for i, packet in enumerate(packets):
            packet_info = {
                "id": i,
                "timestamp": float(packet.time),
                "len": len(packet) # Total length of the packet
            }

            if Ether in packet:
                packet_info["src_mac"] = packet[Ether].src
                packet_info["dst_mac"] = packet[Ether].dst

            if IP in packet:
                packet_info["src_ip"] = packet[IP].src
                packet_info["dst_ip"] = packet[IP].dst
                packet_info["protocol"] = packet[IP].proto # IP protocol number (e.g., 6 for TCP, 17 for UDP)

                if TCP in packet:
                    packet_info["protocol_name"] = "TCP"
                    packet_info["src_port"] = packet[TCP].sport
                    packet_info["dst_port"] = packet[TCP].dport
                    packet_info["tcp_flags"] = str(packet[TCP].flags) # Convert flags object to string
                    packet_info["payload_len"] = len(packet[TCP].payload) if packet[TCP].payload else 0
                    packet_info["payload_present"] = bool(packet[TCP].payload)
                elif UDP in packet:
                    packet_info["protocol_name"] = "UDP"
                    packet_info["src_port"] = packet[UDP].sport
                    packet_info["dst_port"] = packet[UDP].dport
                    packet_info["payload_len"] = len(packet[UDP].payload) if packet[UDP].payload else 0
                    packet_info["payload_present"] = bool(packet[UDP].payload)
                elif ICMP in packet:
                    packet_info["protocol_name"] = "ICMP"
                    packet_info["icmp_type"] = packet[ICMP].type
                    packet_info["icmp_code"] = packet[ICMP].code
                    packet_info["payload_len"] = len(packet[ICMP].payload) if packet[ICMP].payload else 0
                    packet_info["payload_present"] = bool(packet[ICMP].payload)
                else:
                    packet_info["protocol_name"] = f"IP_Proto_{packet[IP].proto}"
                    # Generic IP payload length
                    packet_info["payload_len"] = len(packet[IP].payload) if packet[IP].payload else 0
                    packet_info["payload_present"] = bool(packet[IP].payload)

            else:
                packet_info["protocol_name"] = "Non-IP" # E.g., ARP, spanning tree
                packet_info["payload_len"] = 0
                packet_info["payload_present"] = False # No IP layer, so no standard payload

            parsed_packets.append(packet_info)

        app_logger.info(f"Successfully parsed {len(parsed_packets)} packets from {pcap_file_path}")
        return parsed_packets
    except FileNotFoundError:
        app_logger.error(f"PCAP file not found: {pcap_file_path}")
        return []
    except Exception as e:
        app_logger.error(f"Error parsing PCAP file {pcap_file_path}: {e}")
        return []

if __name__ == '__main__':
    # Ensure datasets directory exists relative to project root
    datasets_dir = os.path.join(project_root, 'datasets')
    if not os.path.exists(datasets_dir):
        os.makedirs(datasets_dir)

    sample_pcap = os.path.join(datasets_dir, "sample.pcap")

    if not os.path.exists(sample_pcap):
        app_logger.info(f"Creating a dummy sample PCAP at {sample_pcap} for testing.")
        # Create a sample pcap with diverse packets for better testing
        from scapy.all import Ether, IP, TCP, UDP, ICMP as SCAPY_ICMP, Raw
        test_packets = [
            # Normal HTTP
            Ether()/IP(src="192.168.1.100", dst="172.217.0.1")/TCP(sport=50000, dport=80, flags="S"),
            Ether()/IP(src="172.217.0.1", dst="192.168.1.100")/TCP(sport=80, dport=50000, flags="SA"),
            Ether()/IP(src="192.168.1.100", dst="172.217.0.1")/TCP(sport=50000, dport=80, flags="A")/Raw(load="GET / HTTP/1.1"),
            # Normal DNS
            Ether()/IP(src="192.168.1.101", dst="8.8.8.8")/UDP(sport=50001, dport=53),
            # ICMP Flood (for RULE001) - 15 packets from 192.168.2.127
            *[Ether()/IP(src="192.168.2.127", dst="10.0.0.2")/SCAPY_ICMP() for _ in range(15)],
            # Suspicious Outbound (for RULE002) - TCP to 31337
            Ether()/IP(src="192.168.1.102", dst="1.2.3.4")/TCP(sport=50002, dport=31337),
            # Non-Standard HTTP (for RULE003) - src_port < 1024
            Ether()/IP(src="192.168.1.103", dst="172.217.0.2")/TCP(sport=800, dport=80),
            # Another ICMP from a different source
            Ether()/IP(src="192.168.2.128", dst="10.0.0.3")/SCAPY_ICMP(),
            # Short flow with unusual ports (potential anomaly)
            Ether()/IP(src="172.16.0.1", dst="172.16.0.2")/TCP(sport=12345, dport=60000),
            # Blacklisted IP (for RULE004/005)
            Ether()/IP(src="10.10.10.10", dst="192.168.1.1")/TCP(sport=1234, dport=80),
            Ether()/IP(src="192.168.1.1", dst="10.10.10.10")/TCP(sport=80, dport=1234)
        ]
        wrpcap(sample_pcap, test_packets)
        app_logger.info(f"Dummy PCAP created at {sample_pcap}.")

    packets = parse_pcap_file(sample_pcap)
    if packets:
        app_logger.info("First 5 parsed packets:")
        for i in range(min(5, len(packets))):
            app_logger.info(packets[i])
