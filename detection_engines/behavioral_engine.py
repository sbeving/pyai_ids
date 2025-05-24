# --- IMPORTANT: Add this block to any file in a subdirectory if you run it directly ---
import sys
import os

# Get the path to the project root (pyai_ids directory)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# --- END IMPORTANT BLOCK ---

import pandas as pd
from utils.logger import app_logger
import joblib
import numpy as np
import json
from data_collector.packet_parser import wrpcap, parse_pcap_file # For generating dummy pcaps
from preprocessor.feature_extractor import extract_packet_features, extract_flow_features # For generating dummy pcaps
from utils.helpers import convert_numpy_types # NEW: Import helper

class BehavioralEngine:
    def __init__(self, profile_data_path="models/behavioral_profiles.joblib"):
        self.profile_data_path = os.path.join(project_root, profile_data_path) if not os.path.isabs(profile_data_path) else profile_data_path
        self.entity_profiles = {}
        self._ensure_model_dir_exists() # Ensure models directory exists for saving
        self.load_profiles()
        app_logger.info("Behavioral engine initialized.")

    def _ensure_model_dir_exists(self):
        model_dir = os.path.dirname(self.profile_data_path)
        if model_dir and not os.path.exists(model_dir):
            os.makedirs(model_dir)
            app_logger.info(f"Created behavioral profiles directory: {model_dir}")

    def establish_baselines(self, flows_df):
        """
        Learns 'normal' behavioral profiles for entities (e.g., IPs) from flow data.
        Profiles are stored as mean and standard deviation of key metrics.
        """
        app_logger.info(f"Establishing behavioral baselines from {len(flows_df)} flows.")
        if flows_df.empty:
            app_logger.warning("No flows to establish baselines from.")
            return

        behavioral_features = [
            'flow_duration', 'num_packets', 'total_bytes',
            'packets_per_sec', 'bytes_per_sec', 'avg_packet_size',
            'std_packet_size', 'min_packet_len', 'max_packet_len'
        ]
        
        profile_df = flows_df[['src_ip'] + [f for f in behavioral_features if f in flows_df.columns]].copy()
        
        for col in profile_df.columns:
            if profile_df[col].dtype == 'object' and col != 'src_ip':
                app_logger.warning(f"BehavioralEngine: Column '{col}' is object type, skipping for profiling.")
                profile_df = profile_df.drop(columns=[col])
            elif profile_df[col].isnull().any():
                mean_val = profile_df[col].mean()
                profile_df[col].fillna(mean_val if pd.notna(mean_val) else 0, inplace=True)
        
        grouped_profiles = profile_df.groupby('src_ip').agg(
            mean_duration=('flow_duration', 'mean'),
            std_duration=('flow_duration', 'std'),
            mean_num_packets=('num_packets', 'mean'),
            std_num_packets=('num_packets', 'std'),
            mean_total_bytes=('total_bytes', 'mean'),
            std_total_bytes=('total_bytes', 'std'),
        ).replace([np.nan, np.inf, -np.inf], 0)

        for index, row in grouped_profiles.iterrows():
            ip = index
            self.entity_profiles[ip] = convert_numpy_types(row.to_dict()) # APPLY CONVERSION HERE
            self.entity_profiles[ip]['last_updated'] = pd.Timestamp.now().isoformat()
        
        self.save_profiles()
        app_logger.info(f"Established baselines for {len(self.entity_profiles)} entities and saved.")

    def save_profiles(self):
        """Saves the learned behavioral profiles to disk."""
        try:
            joblib.dump(self.entity_profiles, self.profile_data_path)
            app_logger.info(f"Behavioral profiles saved to {self.profile_data_path}")
        except Exception as e:
            app_logger.error(f"Error saving behavioral profiles to {self.profile_data_path}: {e}")

    def load_profiles(self):
        """Loads learned behavioral profiles from disk."""
        if os.path.exists(self.profile_data_path):
            try:
                self.entity_profiles = joblib.load(self.profile_data_path)
                app_logger.info(f"Behavioral profiles loaded from {self.profile_data_path}")
            except Exception as e:
                app_logger.error(f"Error loading behavioral profiles from {self.profile_data_path}: {e}")
                self.entity_profiles = {}
        else:
            app_logger.warning(f"Behavioral profiles file not found at {self.profile_data_path}. Starting with empty profiles.")
            self.entity_profiles = {}

    def analyze_flows(self, flows_df, threshold_std_dev=3):
        """
        Analyzes new flows against established behavioral baselines using Z-score method.
        """
        alerts = []
        if not self.entity_profiles:
            app_logger.warning("No behavioral baselines established/loaded. Skipping behavioral analysis.")
            return alerts
        if flows_df.empty:
            app_logger.info("No flows to analyze with behavioral engine.")
            return alerts

        app_logger.info(f"Analyzing {len(flows_df)} flows with behavioral engine (Z-score deviation).")

        for index, flow in flows_df.iterrows():
            src_ip = flow.get('src_ip')
            
            if src_ip and src_ip in self.entity_profiles:
                profile = self.entity_profiles[src_ip]
                deviation_reasons = []

                current_total_bytes = flow.get('total_bytes', 0)
                mean_total_bytes = profile.get('mean_total_bytes', 0)
                std_total_bytes = profile.get('std_total_bytes', 0)

                if std_total_bytes > 0:
                    z_score_bytes = abs((current_total_bytes - mean_total_bytes) / std_total_bytes)
                    if z_score_bytes > threshold_std_dev:
                        deviation_reasons.append(f"Unusual total bytes ({current_total_bytes:.2f} B) for {src_ip} (Z-score: {z_score_bytes:.2f}, Baseline: {mean_total_bytes:.2f} +/- {std_total_bytes:.2f} B)")
                elif current_total_bytes > mean_total_bytes * 5 and mean_total_bytes > 0:
                     deviation_reasons.append(f"Unusual total bytes ({current_total_bytes:.2f} B) for {src_ip} (Baseline: {mean_total_bytes:.2f}, no std_dev)")

                current_num_packets = flow.get('num_packets', 0)
                mean_num_packets = profile.get('mean_num_packets', 0)
                std_num_packets = profile.get('std_num_packets', 0)

                if std_num_packets > 0:
                    z_score_packets = abs((current_num_packets - mean_num_packets) / std_num_packets)
                    if z_score_packets > threshold_std_dev:
                        deviation_reasons.append(f"Unusual number of packets ({current_num_packets}) for {src_ip} (Z-score: {z_score_packets:.2f}, Baseline: {mean_num_packets:.2f} +/- {std_num_packets:.2f})")
                elif current_num_packets > mean_num_packets * 5 and mean_num_packets > 0:
                     deviation_reasons.append(f"Unusual number of packets ({current_num_packets}) for {src_ip} (Baseline: {mean_num_packets:.2f}, no std_dev)")

                if deviation_reasons:
                    alert = {
                        "engine": "BehavioralEngine",
                        "severity": "High",
                        "description": f"Significant behavioral deviation detected for source IP {src_ip}.",
                        "flow_details": flow.to_dict(), # This will have NumPy types
                        "profile_baseline": {k: v for k, v in profile.items() if not k.startswith('last_updated')},
                        "deviation_reasons": deviation_reasons
                    }
                    alerts.append(convert_numpy_types(alert)) # APPLY CONVERSION HERE
                    app_logger.warning(f"BEHAVIORAL ALERT: {src_ip} showed unusual activity. Reasons: {', '.join(deviation_reasons)}")
        
        app_logger.info(f"Behavioral engine analysis complete. Generated {len(alerts)} alerts.")
        return alerts

if __name__ == '__main__':
    datasets_dir = os.path.join(project_root, 'datasets')
    models_dir = os.path.join(project_root, 'models')
    if not os.path.exists(datasets_dir): os.makedirs(datasets_dir)
    if not os.path.exists(models_dir): os.makedirs(models_dir)

    normal_pcap_path = os.path.join(datasets_dir, "sample_normal_traffic.pcap")
    test_pcap_path = os.path.join(datasets_dir, "sample_test_traffic_with_anomalies.pcap")

    if not os.path.exists(normal_pcap_path):
        app_logger.error(f"Normal traffic PCAP not found at {normal_pcap_path}. Please run anomaly_engine.py directly first.")
        sys.exit(1)
    if not os.path.exists(test_pcap_path):
        app_logger.error(f"Test traffic PCAP not found at {test_pcap_path}. Please run anomaly_engine.py directly first.")
        sys.exit(1)

    # 1. Establish Baselines
    app_logger.info("--- STARTING BEHAVIORAL BASELINE ESTABLISHMENT ---")
    raw_normal_packets = parse_pcap_file(normal_pcap_path)
    if raw_normal_packets:
        normal_packet_df = extract_packet_features(raw_normal_packets)
        normal_flows_df = extract_flow_features(normal_packet_df.copy())
        
        behavior_engine = BehavioralEngine()
        behavior_engine.establish_baselines(normal_flows_df)
        app_logger.info("--- FINISHED BEHAVIORAL BASELINE ESTABLISHMENT ---")

        # 2. Analyze new flows
        app_logger.info("\n--- STARTING BEHAVIORAL ANALYSIS ON TEST TRAFFIC ---")
        raw_test_packets = parse_pcap_file(test_pcap_path)
        if raw_test_packets:
            test_packet_df = extract_packet_features(raw_test_packets)
            test_flows_df = extract_flow_features(test_packet_df.copy())
            
            behavioral_alerts = behavior_engine.analyze_flows(test_flows_df)
            if behavioral_alerts:
                print("\n--- BEHAVIORAL ALERTS ---")
                for alrt in behavioral_alerts:
                    print(json.dumps(alrt, indent=2))
            else:
                print("No behavioral anomalies detected.")
        app_logger.info("--- FINISHED BEHAVIORAL ANALYSIS ---")
    else:
        app_logger.error("Skipping behavioral engine test due to missing normal traffic PCAP.")