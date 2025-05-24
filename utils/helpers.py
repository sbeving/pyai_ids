# --- IMPORTANT: Add this block to any file in a subdirectory if you run it directly ---
import sys
import os

# Get the path to the project root (pyai_ids directory)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# --- END IMPORTANT BLOCK ---

import numpy as np # NEW: Import numpy for type checking
import pandas as pd # NEW: Import pandas for type checking (e.g. pd.isna)


def get_flow_key(packet_series):
    """
    Generates a unique key for a flow based on 5-tuple.
    Uses sorted (src_ip, dst_ip) for bi-directional flow grouping.
    Handles cases where port information might be missing (e.g., ICMP).
    """
    src_ip = packet_series.get("src_ip")
    dst_ip = packet_series.get("dst_ip")
    proto = packet_series.get("protocol_name", "UNKNOWN_PROTO")
    
    # Sort IPs to group bi-directional flows (e.g., A->B and B->A are part of the same flow)
    sorted_ips = tuple(sorted([src_ip, dst_ip]))

    # For TCP/UDP, ports are crucial. Sort ports as well for bi-directional.
    if proto in ["TCP", "UDP"]:
        src_port = packet_series.get("src_port")
        dst_port = packet_series.get("dst_port")
        sorted_ports = tuple(sorted([src_port, dst_port]))
        return (sorted_ips[0], sorted_ports[0], sorted_ips[1], sorted_ports[1], proto)
    else:
        # For ICMP or other protocols without ports, just use sorted IPs and protocol type
        return (sorted_ips[0], sorted_ips[1], proto)


def convert_numpy_types(obj):
    """
    Recursively converts numpy.int64, numpy.float64, numpy.bool_, and pandas.NaT
    objects within a dictionary or list to native Python int, float, bool, or None.
    """
    if isinstance(obj, dict):
        return {k: convert_numpy_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(elem) for elem in obj]
    elif isinstance(obj, (np.int64, np.int32, np.int16, np.int8)):
        return int(obj)
    elif isinstance(obj, (np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, np.bool_):
        return bool(obj)
    elif pd.isna(obj): # Handle Pandas NaNs, which can be different from np.nan
        return None
    elif isinstance(obj, np.ndarray): # Convert numpy arrays to lists
        return obj.tolist()
    else:
        return obj

# No __main__ block needed for this file, as it's purely utility.