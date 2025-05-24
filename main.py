import argparse
import os
import configparser
import json 

from utils.logger import app_logger
from data_collector.packet_parser import parse_pcap_file
from preprocessor.feature_extractor import extract_packet_features, extract_flow_features
from detection_engines.rule_based_engine import RuleBasedEngine
from detection_engines.anomaly_engine import AnomalyEngine
from detection_engines.behavioral_engine import BehavioralEngine
from alerting.notifier import dispatch_alert
from threat_intelligence.feed_manager import ThreatIntelligenceManager
from explainability.xai_insights import XAIInsights
from data_collector.packet_parser import wrpcap # for dummy pcap creation
from utils.helpers import convert_numpy_types # NEW: Import helper
import pandas as pd # NEW: For handling potential pd.Series in XAI context

def main():
    parser = argparse.ArgumentParser(description="PyAI-IDS: Advanced Python Intrusion Detection System")
    parser.add_argument("--pcap", type=str, help="Path to the PCAP file to analyze for detection.")
    parser.add_argument("--config", type=str, default="configs/config.ini", help="Path to the configuration file.")
    parser.add_argument("--train-anomaly", type=str, metavar="NORMAL_PCAP_PATH",
                        help="Path to a PCAP file containing ONLY normal traffic to train the anomaly detection model.")
    parser.add_argument("--train-behavioral", type=str, metavar="NORMAL_PCAP_PATH",
                        help="Path to a PCAP file containing ONLY normal traffic to train the behavioral detection model.")
    args = parser.parse_args()

    # Load configuration
    config = configparser.ConfigParser()
    if not os.path.exists(args.config):
        app_logger.error(f"Configuration file not found: {args.config}")
        return
    config.read(args.config)
    
    app_logger.info("PyAI-IDS starting...")

    # --- Training Mode for Anomaly Engine ---
    if args.train_anomaly:
        if not os.path.exists(args.train_anomaly):
            app_logger.error(f"Normal traffic PCAP for anomaly training not found: {args.train_anomaly}")
            return

        app_logger.info(f"--- Anomaly Detection Model Training Mode ---")
        app_logger.info(f"Parsing normal traffic from: {args.train_anomaly}")
        raw_normal_packets = parse_pcap_file(args.train_anomaly)
        if not raw_normal_packets:
            app_logger.error("No packets parsed from normal traffic PCAP for anomaly training. Training aborted.")
            return

        normal_packet_df = extract_packet_features(raw_normal_packets)
        normal_flows_df = extract_flow_features(normal_packet_df.copy())

        if normal_flows_df.empty:
            app_logger.error("No flow features extracted from normal traffic for anomaly training. Training aborted.")
            return
        
        anomaly_engine_trainer = AnomalyEngine(config_path=args.config)
        anomaly_engine_trainer.train_model(normal_flows_df) 
        app_logger.info("--- Anomaly detection model training complete. Exiting. ---")
        return # Exit after training

    # --- Training Mode for Behavioral Engine ---
    if args.train_behavioral:
        if not os.path.exists(args.train_behavioral):
            app_logger.error(f"Normal traffic PCAP for behavioral training not found: {args.train_behavioral}")
            return

        app_logger.info(f"--- Behavioral Engine Baseline Establishment Mode ---")
        app_logger.info(f"Parsing normal traffic from: {args.train_behavioral}")
        raw_normal_packets = parse_pcap_file(args.train_behavioral)
        if not raw_normal_packets:
            app_logger.error("No packets parsed from normal traffic PCAP for behavioral training. Training aborted.")
            return

        normal_packet_df = extract_packet_features(raw_normal_packets)
        normal_flows_df = extract_flow_features(normal_packet_df.copy())

        if normal_flows_df.empty:
            app_logger.error("No flow features extracted from normal traffic for behavioral training. Training aborted.")
            return
        
        behavioral_engine_trainer = BehavioralEngine() 
        behavioral_engine_trainer.establish_baselines(normal_flows_df) 
        app_logger.info("--- Behavioral engine baseline establishment complete. Exiting. ---")
        return # Exit after training

    # --- Detection Mode ---
    if not args.pcap:
        app_logger.error("No input PCAP specified for detection. Use --pcap <file_path> or a training argument.")
        parser.print_help()
        return

    if not os.path.exists(args.pcap):
        app_logger.error(f"PCAP file for detection not found: {args.pcap}")
        return

    all_alerts = []
    app_logger.info(f"--- Detection Mode ---")
    app_logger.info(f"Processing PCAP file: {args.pcap}")
    
    # Initialize Threat Intelligence Manager once for the session
    ti_manager = ThreatIntelligenceManager() 

    # 1. Data Collection
    raw_packets = parse_pcap_file(args.pcap)
    if not raw_packets:
        app_logger.error("No packets were parsed. Exiting.")
        return

    # 2. Preprocessing & Feature Extraction
    packet_features_df = extract_packet_features(raw_packets)
    flows_df = extract_flow_features(packet_features_df.copy()) 

    # 3. Detection Engines
    # Rule-Based Engine (uses packet_features_df and ti_manager)
    rules_file = config.get('RuleEngine', 'rules_file', fallback='configs/rules.json')
    rule_engine = RuleBasedEngine(rules_file_path=rules_file, ti_manager=ti_manager)
    if not packet_features_df.empty:
        rule_alerts = rule_engine.analyze_packets(packet_features_df)
        all_alerts.extend(rule_alerts)
    else:
        app_logger.warning("Packet features DataFrame is empty, skipping rule-based engine.")

    # Anomaly Engine (uses flows_df and provides data for XAI)
    if not flows_df.empty:
        anomaly_engine = AnomalyEngine(config_path=args.config)
        if anomaly_engine.model and anomaly_engine.scaler: 
            anomaly_alerts = anomaly_engine.analyze_flows(flows_df)
            
            # --- XAI Integration for Anomaly Alerts ---
            normal_pcap_path_for_xai = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'datasets', 'sample_normal_traffic.pcap')
            xai_normal_scaled_data_sample = None
            if os.path.exists(normal_pcap_path_for_xai):
                raw_normal_xai_packets = parse_pcap_file(normal_pcap_path_for_xai)
                if raw_normal_xai_packets:
                    normal_xai_packet_df = extract_packet_features(raw_normal_xai_packets)
                    normal_xai_flows_df = extract_flow_features(normal_xai_packet_df.copy())
                    if not normal_xai_flows_df.empty:
                        xai_normal_features, _ = anomaly_engine._get_numerical_features(normal_xai_flows_df)
                        if not xai_normal_features.empty and anomaly_engine.scaler:
                            xai_normal_scaled_data_sample = anomaly_engine.scaler.transform(xai_normal_features)
                        else:
                            app_logger.warning("XAI: Could not extract/scale numerical features from normal traffic for background data.")
                    else:
                        app_logger.warning("XAI: No flow features extracted from normal traffic for background data.")
                else:
                    app_logger.warning("XAI: Could not parse normal traffic PCAP for background data.")
            else:
                app_logger.warning(f"XAI: Normal traffic PCAP for background data not found at {normal_pcap_path_for_xai}.")
            
            if anomaly_alerts and xai_normal_scaled_data_sample is not None:
                _, xai_feature_names = anomaly_engine._get_numerical_features(flows_df) # Use flows_df to get feature names in correct order
                
                if not xai_feature_names:
                    app_logger.warning("XAI: No feature names available for XAI insights.")
                else:
                    xai_insights_module = XAIInsights(
                        model=anomaly_engine.model, 
                        feature_names=xai_feature_names,
                        normal_data_sample=xai_normal_scaled_data_sample
                    )
                    
                    for alert in anomaly_alerts:
                        # Find the original flow data (Pandas Series) corresponding to this alert
                        flow_id_to_explain = alert.get('flow_details', {}).get('flow_id_tuple')
                        if flow_id_to_explain:
                            original_flow_data_for_xai = flows_df[flows_df['flow_id_tuple'] == flow_id_to_explain].iloc[0]
                            # Prepare scaled features for this specific instance for XAI
                            instance_features_df, _ = anomaly_engine._get_numerical_features(pd.DataFrame([original_flow_data_for_xai]))
                            if not instance_features_df.empty:
                                instance_scaled_features_for_xai = anomaly_engine.scaler.transform(instance_features_df)
                                explanation = xai_insights_module.explain_anomaly_prediction(instance_scaled_features_for_xai, original_flow_data_for_xai)
                                alert['xai_explanation'] = explanation
                            else:
                                app_logger.warning(f"XAI: Could not prepare features for flow {flow_id_to_explain} for explanation.")
                        else:
                            app_logger.warning("XAI: Flow ID missing in anomaly alert for explanation.")
            else:
                app_logger.warning("XAI explanations for anomaly alerts are skipped due to missing model/scaler, normal data sample, or no anomaly alerts generated.")
            # --- End XAI Integration ---

            all_alerts.extend(anomaly_alerts)
        else:
            app_logger.warning("Anomaly engine model or scaler not loaded, skipping anomaly detection.")
    else:
        app_logger.warning("Flows DataFrame is empty, skipping anomaly engine.")

    # Behavioral Engine (uses flows_df)
    if not flows_df.empty:
        behavioral_engine = BehavioralEngine()
        if behavioral_engine.entity_profiles:
            behavioral_alerts = behavioral_engine.analyze_flows(flows_df)
            all_alerts.extend(behavioral_alerts)
        else:
            app_logger.warning("Behavioral engine has no baselines loaded. Skipping behavioral analysis.")
    else:
        app_logger.warning("Flows DataFrame is empty, skipping behavioral engine.")

    # 4. Alerting
    if all_alerts:
        app_logger.info(f"Total alerts generated: {len(all_alerts)}")
        for alert_data in all_alerts:
            # Example: Enriching an anomaly alert with TI info if IPs involved are blacklisted
            if alert_data.get('engine') == 'AnomalyEngine (IsolationForest)':
                src_ip = alert_data.get('flow_details', {}).get('src_ip')
                dst_ip = alert_data.get('flow_details', {}).get('dst_ip')
                
                if src_ip and ti_manager.is_ip_blacklisted(src_ip):
                    alert_data['threat_intel_context_src'] = "Source IP is blacklisted (from Anomaly Engine)."
                    alert_data['severity'] = "Critical"
                if dst_ip and ti_manager.is_ip_blacklisted(dst_ip):
                    alert_data['threat_intel_context_dst'] = "Destination IP is blacklisted (from Anomaly Engine)."
                    alert_data['severity'] = "Critical"
            
            # Ensure the final alert is fully converted before dispatch
            dispatch_alert(convert_numpy_types(alert_data), method="console") # APPLY CONVERSION HERE
    else:
        app_logger.info("No alerts generated from any detection engine.")

    app_logger.info("PyAI-IDS run finished.")

if __name__ == "__main__":
    if not os.path.exists("datasets"): os.makedirs("datasets")
    if not os.path.exists("models"): os.makedirs("models")
    if not os.path.exists("configs"): os.makedirs("configs")
    
    config_file = "configs/config.ini"
    ti_feeds_file = "configs/ti_feeds.json"
    rules_file = "configs/rules.json"

    if not os.path.exists(config_file):
        print(f"Creating default config.ini at {config_file}")
        config = configparser.ConfigParser()
        config['General'] = {'log_level': 'INFO'}
        config['Models'] = {
            'anomaly_model_path': 'models/isolation_forest_anomaly_model.joblib',
            'scaler_path': 'models/scaler.joblib',
            'behavioral_profile_path': 'models/behavioral_profiles.joblib'
        }
        config['RuleEngine'] = {
            'rules_file': 'configs/rules.json'
        }
        with open(config_file, 'w') as f:
            config.write(f)

    if not os.path.exists(ti_feeds_file):
        print(f"Creating default ti_feeds.json at {ti_feeds_file}")
        dummy_ti_config = {
            "ip_feeds": [
                "file://" + os.path.join(os.path.abspath(os.path.dirname(__file__)), "configs", "dummy_ip_blacklist.txt")
            ],
            "domain_feeds": [
                 "file://" + os.path.join(os.path.abspath(os.path.dirname(__file__)), "configs", "dummy_domain_blacklist.txt")
            ],
            "hash_feeds": []
        }
        with open(ti_feeds_file, 'w') as f:
            json.dump(dummy_ti_config, f, indent=4)
        
        with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), "configs", "dummy_ip_blacklist.txt"), 'w') as f:
            f.write("1.1.1.1\n8.8.8.8\n10.10.10.10\n")
        with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), "configs", "dummy_domain_blacklist.txt"), 'w') as f:
            f.write("malicious.com\nbad-domain.net\n")
        
        print("Dummy TI feed config and local blacklist files created.")

    if not os.path.exists(rules_file):
        print(f"Creating default rules.json at {rules_file}.")
        default_rules = [
            {
                "rule_id": "RULE001",
                "name": "Potential ICMP Flood (High ICMP Count from Source)",
                "description": "Detects if a source IP sends more than 10 ICMP packets within the analyzed window.",
                "conditions": [
                    {"field": "protocol_name", "operator": "equals", "value": "ICMP"}
                ],
                "aggregation": {
                    "group_by": "src_ip",
                    "count_threshold": 10
                },
                "severity": "Medium"
            },
            {
                "rule_id": "RULE002",
                "name": "Suspicious Outbound Connection to Known Bad Port",
                "description": "Detects outbound TCP connections to common C2/malware ports (e.g., 6667, 6697 for IRC bots, 31337 for Back Orifice).",
                "conditions": [
                    {"field": "protocol_name", "operator": "equals", "value": "TCP"},
                    {"field": "dst_port", "operator": "in", "value": [6667, 6697, 31337]},
                    {"field": "dst_ip", "operator": "not_starts_with", "value": "192.168."}
                ],
                "severity": "High"
            },
            {
                "rule_id": "RULE003",
                "name": "Non-Standard HTTP Source Port",
                "description": "Detects TCP traffic to destination port 80 where the source port is unusually low (<1024), which can indicate a non-standard client or misconfiguration.",
                "conditions": [
                    {"field": "protocol_name", "operator": "equals", "value": "TCP"},
                    {"field": "dst_port", "operator": "equals", "value": 80},
                    {"field": "src_port", "operator": "less_than", "value": 1024}
                ],
                "severity": "Low"
            },
            {
                "rule_id": "RULE004",
                "name": "Blacklisted IP Communication (Source)",
                "description": "Detects communication originating from a known blacklisted IP address.",
                "conditions": [
                    {"field": "src_ip", "operator": "in_blacklist", "value": "ip"}
                ],
                "severity": "Critical"
            },
            {
                "rule_id": "RULE005",
                "name": "Blacklisted IP Communication (Destination)",
                "description": "Detects communication to a known blacklisted IP address.",
                "conditions": [
                    {"field": "dst_ip", "operator": "in_blacklist", "value": "ip"}
                ],
                "severity": "Critical"
            }
        ]
        with open(rules_file, 'w') as f:
            json.dump(default_rules, f, indent=4)
        print("Default rules.json created.")


    normal_pcap_path = os.path.join("datasets", "sample_normal_traffic.pcap")
    test_pcap_path = os.path.join("datasets", "sample_test_traffic_with_anomalies.pcap")
    sample_pcap_default = os.path.join("datasets", "sample.pcap")

    if not os.path.exists(normal_pcap_path):
        print(f"INFO: {normal_pcap_path} not found. Consider running `python detection_engines/anomaly_engine.py` once to create it and train models.")
    if not os.path.exists(test_pcap_path):
        print(f"INFO: {test_pcap_path} not found. Consider running `python detection_engines/anomaly_engine.py` once to create it.")
    if not os.path.exists(sample_pcap_default):
        print(f"INFO: {sample_pcap_default} not found. Consider running `python data_collector/packet_parser.py` once to create it.")
    
    main()