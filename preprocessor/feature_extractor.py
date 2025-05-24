# --- IMPORTANT: Add this block to any file in a subdirectory if you run it directly ---
import sys
import os

# Get the path to the project root (pyai_ids directory)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# --- END IMPORTANT BLOCK ---
import pandas as pd
import numpy as np
from utils.logger import app_logger
from utils.helpers import get_flow_key
from data_collector.packet_parser import parse_pcap_file, wrpcap # Added wrpcap for test in __main__
import os # For path operations

def extract_packet_features(parsed_packets_list): # Renamed from extract_basic_features
    """
    Converts list of parsed packet dictionaries into a Pandas DataFrame.
    This DataFrame is per-packet.
    """
    app_logger.info(f"Extracting packet-level features from {len(parsed_packets_list)} packets.")
    if not parsed_packets_list:
        app_logger.warning("No packets to process for packet feature extraction.")
        return pd.DataFrame()

    df = pd.DataFrame(parsed_packets_list)
    app_logger.info(f"Packet DataFrame created with shape: {df.shape}")
    return df

def extract_flow_features(packet_df):
    """
    Aggregates packet features into flow-based features.
    Returns a DataFrame where each row represents a flow.
    Includes more statistical features.
    """
    if packet_df.empty:
        app_logger.warning("Packet DataFrame is empty. Cannot extract flow features.")
        return pd.DataFrame()

    app_logger.info(f"Starting flow feature extraction from {len(packet_df)} packets.")
    
    # Ensure necessary columns exist. Add optional ones to list as None to prevent KeyError later.
    required_cols = ['src_ip', 'dst_ip', 'protocol_name', 'timestamp', 'len', 'src_port', 'dst_port']
    for col in required_cols:
        if col not in packet_df.columns:
            packet_df[col] = None # Add missing columns as None to avoid errors later

    # Create 'flow_key' column for grouping
    # Use .copy() to avoid SettingWithCopyWarning if packet_df is a slice
    packet_df_copy = packet_df.copy()
    packet_df_copy['flow_key'] = packet_df_copy.apply(get_flow_key, axis=1)

    flow_features_list = []

    # Group by flow_key
    grouped_flows = packet_df_copy.groupby('flow_key')

    for flow_id, flow_packets_df in grouped_flows:
        if flow_packets_df.empty:
            continue

        flow_start_time = flow_packets_df['timestamp'].min()
        flow_end_time = flow_packets_df['timestamp'].max()
        flow_duration = flow_end_time - flow_start_time

        num_packets = len(flow_packets_df)
        total_bytes = flow_packets_df['len'].sum()

        # Handle division by zero for duration if it's 0 (single packet flow)
        # Use a small epsilon to avoid ZeroDivisionError for very short flows
        epsilon = 1e-6 
        packets_per_sec = num_packets / (flow_duration + epsilon)
        bytes_per_sec = total_bytes / (flow_duration + epsilon)
        
        # Average packet size and standard deviation of packet sizes
        avg_packet_size = flow_packets_df['len'].mean()
        std_packet_size = flow_packets_df['len'].std() if num_packets > 1 else 0

        # Number of unique source and destination ports
        num_unique_src_ports = flow_packets_df['src_port'].dropna().nunique()
        num_unique_dst_ports = flow_packets_df['dst_port'].dropna().nunique()

        # Min/Max packet lengths
        min_packet_len = flow_packets_df['len'].min()
        max_packet_len = flow_packets_df['len'].max()

        # Unpack flow_id_tuple safely
        src_ip, dst_ip, proto, src_port, dst_port = (None,)*5
        if len(flow_id) == 5: # TCP/UDP like (src_ip, src_port, dst_ip, dst_port, proto)
            src_ip, src_port, dst_ip, dst_port, proto = flow_id
        elif len(flow_id) == 3: # ICMP/Other (src_ip, dst_ip, proto)
            src_ip, dst_ip, proto = flow_id

        features = {
            'flow_id_tuple': flow_id, # Keep for reference
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port, # This is the sorted source port from the tuple
            'dst_port': dst_port, # This is the sorted destination port from the tuple
            'protocol': proto, # This is protocol_name from packet_df
            'flow_duration': flow_duration,
            'num_packets': num_packets,
            'total_bytes': total_bytes,
            'packets_per_sec': packets_per_sec,
            'bytes_per_sec': bytes_per_sec,
            'avg_packet_size': avg_packet_size,
            'std_packet_size': std_packet_size,
            'min_packet_len': min_packet_len,
            'max_packet_len': max_packet_len,
            'num_unique_src_ports': num_unique_src_ports,
            'num_unique_dst_ports': num_unique_dst_ports,
            # Add more sophisticated features like TCP flag counts, entropy, etc.
        }
        flow_features_list.append(features)

    flows_df = pd.DataFrame(flow_features_list)
    app_logger.info(f"Extracted {len(flows_df)} flows.")
    return flows_df


if __name__ == '__main__':
    # Ensure datasets directory exists relative to project root
    datasets_dir = os.path.join(project_root, 'datasets')
    if not os.path.exists(datasets_dir):
        os.makedirs(datasets_dir)

    sample_pcap_path = os.path.join(datasets_dir, "sample.pcap")

    # The packet_parser.py __main__ block generates sample.pcap
    # Ensure packet_parser.py has been run directly or main.py has created it.
    if not os.path.exists(sample_pcap_path):
        app_logger.error(f"Sample PCAP file not found at {sample_pcap_path}. Please run packet_parser.py directly first (or main.py once) to create it.")
        # Create a basic sample pcap if it still doesn't exist for direct testing
        from scapy.all import Ether, IP, TCP, UDP
        temp_packets = [
            Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=10000, dport=80, flags="S"),
            Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=10000, dport=80, flags="A"),
            Ether()/IP(src="3.3.3.3", dst="4.4.4.4")/UDP(sport=20000, dport=53)
        ]
        wrpcap(sample_pcap_path, temp_packets)
        app_logger.info(f"Created a basic dummy PCAP at {sample_pcap_path} for immediate testing.")

    raw_packets = parse_pcap_file(sample_pcap_path)
    if raw_packets:
        packet_features_df = extract_packet_features(raw_packets)
        app_logger.info("\n--- Packet Features DataFrame (first 5 rows): ---")
        app_logger.info(packet_features_df.head().to_string()) # Use .to_string() for better console output

        flow_features_df = extract_flow_features(packet_features_df.copy())
        app_logger.info("\n--- Flow Features DataFrame (first 5 rows): ---")
        if not flow_features_df.empty:
            app_logger.info(flow_features_df.head().to_string())
        else:
            app_logger.info("No flow features extracted.")
