# --- IMPORTANT: Add this block to any file in a subdirectory if you run it directly ---
import sys
import os

# Get the path to the project root (pyai_ids directory)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# --- END IMPORTANT BLOCK ---

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import pandas as pd
import numpy as np
from utils.logger import app_logger
import configparser
import json
from data_collector.packet_parser import wrpcap # Still need wrpcap for creating sample pcaps
# NEW IMPORTS FOR __main__ BLOCK:
from data_collector.packet_parser import parse_pcap_file
from preprocessor.feature_extractor import extract_packet_features, extract_flow_features
from utils.helpers import convert_numpy_types

class AnomalyEngine:
    def __init__(self, config_path="configs/config.ini"):
        self.config = configparser.ConfigParser()
        self.config_path = os.path.join(project_root, config_path) if not os.path.isabs(config_path) else config_path
        
        if not os.path.exists(self.config_path):
            app_logger.error(f"AnomalyEngine: Configuration file not found at {self.config_path}.")
            self.model_path = os.path.join(project_root, 'models', 'isolation_forest_anomaly_model.joblib')
            self.scaler_path = os.path.join(project_root, 'models', 'scaler.joblib')
        else:
            self.config.read(self.config_path)
            self.model_path = self.config.get('Models', 'anomaly_model_path', fallback='models/isolation_forest_model.joblib')
            self.model_path = os.path.join(project_root, self.model_path)
            self.scaler_path = self.config.get('Models', 'scaler_path', fallback='models/scaler.joblib')
            self.scaler_path = os.path.join(project_root, self.scaler_path)

        self.model = None
        self.scaler = None
        self._ensure_model_dir_exists()
        self.load_model()

    def _ensure_model_dir_exists(self):
        model_dir = os.path.dirname(self.model_path)
        if model_dir and not os.path.exists(model_dir):
            os.makedirs(model_dir)
            app_logger.info(f"Created model directory: {model_dir}")

    def _get_numerical_features(self, flows_df):
        """
        Selects numerical features suitable for Isolation Forest.
        Handles potential NaN values and ensures numeric types.
        """
        numerical_feature_columns = [
            'flow_duration', 'num_packets', 'total_bytes',
            'packets_per_sec', 'bytes_per_sec', 'avg_packet_size',
            'std_packet_size', 'min_packet_len', 'max_packet_len',
            'num_unique_src_ports', 'num_unique_dst_ports'
        ]
        
        available_cols = [col for col in numerical_feature_columns if col in flows_df.columns]
        if not available_cols:
            app_logger.error("No numerical feature columns available for anomaly detection.")
            return pd.DataFrame(), []
            
        features = flows_df[available_cols].copy()

        for col in features.columns:
            if features[col].isnull().any():
                mean_val = features[col].mean()
                features[col].fillna(mean_val if pd.notna(mean_val) else 0, inplace=True)
        
        features.replace([np.inf, -np.inf], np.nan, inplace=True)
        for col in features.columns:
            if features[col].isnull().any():
                mean_val = features[col].mean()
                features[col].fillna(mean_val if pd.notna(mean_val) else 0, inplace=True)
        
        features = features.astype(float)
        
        return features, available_cols

    def train_model(self, normal_flows_df, contamination=0.01, n_estimators=100, random_state=42):
        """
        Trains an Isolation Forest model and a StandardScaler on a DataFrame of normal flow features.
        """
        app_logger.info(f"Starting training of Isolation Forest model with {len(normal_flows_df)} normal flows.")
        if normal_flows_df.empty:
            app_logger.error("Cannot train anomaly model: Normal flows DataFrame is empty.")
            return

        features_for_training, feature_columns = self._get_numerical_features(normal_flows_df)
        if features_for_training.empty:
            app_logger.error("No numerical features extracted from normal_flows_df for training.")
            return

        app_logger.info(f"Training on features: {feature_columns}")

        self.scaler = StandardScaler()
        scaled_features = self.scaler.fit_transform(features_for_training)
        joblib.dump(self.scaler, self.scaler_path)
        app_logger.info(f"StandardScaler trained and saved to {self.scaler_path}")

        self.model = IsolationForest(n_estimators=n_estimators,
                                     contamination=contamination,
                                     random_state=random_state,
                                     n_jobs=-1)
        try:
            self.model.fit(scaled_features)
            joblib.dump(self.model, self.model_path)
            app_logger.info(f"Isolation Forest model trained and saved to {self.model_path}")
        except Exception as e:
            app_logger.error(f"Error during model training or saving: {e}")
            self.model = None


    def load_model(self):
        model_loaded = False
        scaler_loaded = False

        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                app_logger.info(f"Isolation Forest model loaded from {self.model_path}")
                model_loaded = True
            except Exception as e:
                app_logger.error(f"Error loading model from {self.model_path}: {e}")
                self.model = None

        if os.path.exists(self.scaler_path):
            try:
                self.scaler = joblib.load(self.scaler_path)
                app_logger.info(f"StandardScaler loaded from {self.scaler_path}")
                scaler_loaded = True
            except Exception as e:
                app_logger.error(f"Error loading scaler from {self.scaler_path}: {e}")
                self.scaler = None
        
        if not model_loaded or not scaler_loaded:
            app_logger.warning("Anomaly model or scaler not fully loaded. Please ensure training was successful.")
            self.model = None
            self.scaler = None

    def analyze_flows(self, flows_df):
        """
        Analyzes a DataFrame of flow features using the trained Isolation Forest model.
        Returns a list of alerts for anomalous flows.
        """
        alerts = []
        if self.model is None or self.scaler is None:
            app_logger.warning("Anomaly model or scaler is not loaded. Cannot analyze flows.")
            return alerts
        
        if flows_df.empty:
            app_logger.info("No flows to analyze with anomaly engine.")
            return alerts

        app_logger.info(f"Analyzing {len(flows_df)} flows with anomaly engine.")
        
        features_for_prediction, feature_names_used = self._get_numerical_features(flows_df)
        if features_for_prediction.empty:
            app_logger.warning("No numerical features to analyze in anomaly engine after preprocessing.")
            return alerts

        try:
            scaled_features = self.scaler.transform(features_for_prediction)
        except Exception as e:
            app_logger.error(f"Error scaling features for prediction: {e}")
            return alerts

        try:
            predictions = self.model.predict(scaled_features)
            anomaly_scores = self.model.decision_function(scaled_features)

            anomalous_indices = np.where(predictions == -1)[0]

            for idx in anomalous_indices:
                original_flow_data = flows_df.iloc[idx]
                alert = {
                    "engine": "AnomalyEngine (IsolationForest)",
                    "severity": "Medium",
                    "description": "Anomalous network flow detected.",
                    "flow_details": {
                        "flow_id_tuple": original_flow_data.get('flow_id_tuple'),
                        "src_ip": original_flow_data.get('src_ip'),
                        "dst_ip": original_flow_data.get('dst_ip'),
                        "src_port": original_flow_data.get('src_port'),
                        "dst_port": original_flow_data.get('dst_port'),
                        "protocol": original_flow_data.get('protocol'),
                        "flow_duration": original_flow_data.get('flow_duration'),
                        "num_packets": original_flow_data.get('num_packets'),
                        "total_bytes": original_flow_data.get('total_bytes'),
                    },
                    "anomaly_score": float(anomaly_scores[idx]),
                    "full_flow_features_used_for_detection": original_flow_data[feature_names_used].to_dict()
                }
                alerts.append(convert_numpy_types(alert))
                app_logger.warning(f"ANOMALY ALERT: Flow {original_flow_data.get('flow_id_tuple')} flagged. Score: {anomaly_scores[idx]:.4f}")
        except Exception as e:
            app_logger.error(f"Error during anomaly prediction: {e}")

        app_logger.info(f"Anomaly engine analysis complete. Generated {len(alerts)} alerts.")
        return alerts

if __name__ == '__main__':
    # Ensure datasets and models directories exist relative to project root
    datasets_dir = os.path.join(project_root, 'datasets')
    models_dir = os.path.join(project_root, 'models')
    configs_dir = os.path.join(project_root, 'configs')
    if not os.path.exists(datasets_dir): os.makedirs(datasets_dir)
    if not os.path.exists(models_dir): os.makedirs(models_dir)
    if not os.path.exists(configs_dir): os.makedirs(configs_dir)

    normal_pcap_path = os.path.join(datasets_dir, "sample_normal_traffic.pcap")
    test_pcap_path = os.path.join(datasets_dir, "sample_test_traffic_with_anomalies.pcap")
    config_path = os.path.join(configs_dir, "config.ini")

    if not os.path.exists(config_path):
        app_logger.warning(f"Config file not found at {config_path}. Creating a dummy one.")
        config = configparser.ConfigParser()
        config['General'] = {'log_level': 'INFO'}
        config['Models'] = {
            'anomaly_model_path': 'models/isolation_forest_anomaly_model.joblib',
            'scaler_path': 'models/scaler.joblib'
        }
        config['RuleEngine'] = {'rules_file': 'configs/rules.json'}
        with open(config_path, 'w') as f:
            config.write(f)

    # --- Create dummy pcap files for testing if they don't exist ---
    if not os.path.exists(normal_pcap_path):
        app_logger.info(f"Creating a dummy normal traffic PCAP at {normal_pcap_path}.")
        from scapy.all import Ether, IP, TCP, UDP
        normal_pkts = []
        for i in range(100):
            normal_pkts.append(Ether()/IP(src=f"192.168.1.{i%20+1}", dst=f"10.0.0.{i%5+1}")/TCP(sport=10000+i, dport=80, flags="PA"))
            normal_pkts.append(Ether()/IP(src=f"192.168.1.{i%20+50}", dst=f"10.0.0.{i%5+10}")/UDP(sport=20000+i, dport=53))
        wrpcap(normal_pcap_path, normal_pkts)
        app_logger.info(f"Dummy normal traffic PCAP created: {normal_pcap_path}")

    if not os.path.exists(test_pcap_path):
        app_logger.info(f"Creating a dummy test traffic PCAP at {test_pcap_path} with anomalies.")
        from scapy.all import Ether, IP, TCP, ICMP as SCAPY_ICMP, Raw
        test_pkts = []
        for i in range(10):
            test_pkts.append(Ether()/IP(src=f"192.168.2.{i+1}", dst="10.0.1.1")/TCP(sport=30000+i, dport=443))
        test_pkts.append(Ether()/IP(src="172.16.0.1", dst="172.16.0.2")/TCP(sport=12345, dport=60000)/Raw(load="X"*10000))
        test_pkts.append(Ether()/IP(src="172.16.0.1", dst="172.16.0.2")/TCP(sport=12345, dport=60000)/Raw(load="Y"*5000))
        [test_pkts.append(Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/SCAPY_ICMP()) for _ in range(20)]
        test_pkts.append(Ether()/IP(src="1.0.0.1", dst="9.9.9.9")/UDP(sport=100, dport=101))
        test_pkts.append(Ether()/IP(src="10.10.10.10", dst="192.168.1.1")/TCP(sport=1234, dport=80))

        wrpcap(test_pcap_path, test_pkts)
        app_logger.info(f"Dummy test traffic PCAP created: {test_pcap_path}")


    app_logger.info("--- STARTING ANOMALY ENGINE TRAINING ---")
    raw_normal_packets = parse_pcap_file(normal_pcap_path) # THIS WAS THE MISSING IMPORT
    if raw_normal_packets:
        normal_packet_df = extract_packet_features(raw_normal_packets) # THIS WAS THE MISSING IMPORT
        normal_flows_df = extract_flow_features(normal_packet_df.copy()) # THIS WAS THE MISSING IMPORT

        if not normal_flows_df.empty:
            anomaly_detector = AnomalyEngine(config_path=config_path)
            anomaly_detector.train_model(normal_flows_df, contamination=0.01)
        else:
            app_logger.error("No normal flows extracted for training.")
    else:
        app_logger.error(f"Could not parse normal traffic pcap: {normal_pcap_path}")
    app_logger.info("--- FINISHED ANOMALY ENGINE TRAINING ---")


    app_logger.info("\n--- STARTING ANOMALY DETECTION ON TEST TRAFFIC ---")
    raw_test_packets = parse_pcap_file(test_pcap_path)
    if raw_test_packets:
        test_packet_df = extract_packet_features(raw_test_packets)
        test_flows_df = extract_flow_features(test_packet_df.copy())

        if not test_flows_df.empty:
            anomaly_detector_for_pred = AnomalyEngine(config_path=config_path)
            if anomaly_detector_for_pred.model and anomaly_detector_for_pred.scaler:
                anomaly_alerts = anomaly_detector_for_pred.analyze_flows(test_flows_df)
                if anomaly_alerts:
                    print("\n--- ANOMALY ALERTS ---")
                    for alrt in anomaly_alerts:
                        print(json.dumps(alrt, indent=2))
                else:
                    print("No anomalies detected by the anomaly engine.")
            else:
                app_logger.error("Anomaly model or scaler not available for prediction. Please train first.")
        else:
            app_logger.error("No flows extracted from test traffic.")
    else:
        app_logger.error(f"Could not parse test traffic pcap: {test_pcap_path}")