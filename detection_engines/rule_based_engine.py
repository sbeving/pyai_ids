# --- IMPORTANT: Add this block to any file in a subdirectory if you run it directly ---
import sys
import os

# Get the path to the project root (pyai_ids directory)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# --- END IMPORTANT BLOCK ---

import json
from utils.logger import app_logger
import pandas as pd
import re # For regex operator
from threat_intelligence.feed_manager import ThreatIntelligenceManager
from utils.helpers import convert_numpy_types # NEW: Import helper
# import os # Already imported by project_root setup

class RuleBasedEngine:
    def __init__(self, rules_file_path="configs/rules.json", ti_manager=None):
        self.rules_file_path = os.path.join(project_root, rules_file_path) if not os.path.isabs(rules_file_path) else rules_file_path
        self.rules = self._load_rules(self.rules_file_path)
        self.ti_manager = ti_manager
        if self.ti_manager:
            app_logger.info("Rule-based engine initialized with Threat Intelligence integration.")
        else:
            app_logger.warning("Rule-based engine initialized WITHOUT Threat Intelligence integration (no TI Manager provided).")
        app_logger.info(f"Rule-based engine loaded {len(self.rules)} rules from {self.rules_file_path}.")


    def _load_rules(self, file_path):
        try:
            with open(file_path, 'r') as f:
                rules = json.load(f)
            return rules
        except FileNotFoundError:
            app_logger.error(f"Rules file not found: {file_path}")
            return []
        except json.JSONDecodeError as e:
            app_logger.error(f"Error decoding JSON from rules file {file_path}: {e}")
            return []
        except Exception as e:
            app_logger.error(f"An unexpected error occurred loading rules from {file_path}: {e}")
            return []

    def _check_condition(self, packet_feature_series, condition):
        field = condition.get("field")
        operator = condition.get("operator")
        value = condition.get("value")

        if not field or not operator:
            app_logger.debug(f"Malformed condition: {condition}. Skipping.")
            return False

        if operator == "in_blacklist":
            if not self.ti_manager:
                app_logger.debug(f"TI Manager not available for in_blacklist operator. Rule skipped.")
                return False
            
            item_to_check = packet_feature_series.get(field)
            if item_to_check is None:
                return False

            if value == "ip":
                return self.ti_manager.is_ip_blacklisted(item_to_check)
            elif value == "domain":
                return self.ti_manager.is_domain_blacklisted(item_to_check)
            elif value == "hash":
                return self.ti_manager.is_hash_blacklisted(item_to_check)
            else:
                app_logger.debug(f"Unsupported 'value' for in_blacklist operator: {value} in condition: {condition}")
                return False

        if field not in packet_feature_series or pd.isna(packet_feature_series[field]):
            return False 

        packet_value = packet_feature_series[field]

        try:
            if operator == "equals":
                return str(packet_value) == str(value)
            elif operator == "not_equals":
                return str(packet_value) != str(value)
            elif operator == "greater_than":
                return float(packet_value) > float(value)
            elif operator == "less_than":
                return float(packet_value) < float(value)
            elif operator == "in":
                return packet_value in value
            elif operator == "not_in":
                return packet_value not in value
            elif operator == "contains":
                return isinstance(packet_value, str) and value in packet_value
            elif operator == "starts_with":
                return isinstance(packet_value, str) and packet_value.startswith(value)
            elif operator == "regex_match":
                return isinstance(packet_value, str) and re.search(value, packet_value) is not None
            else:
                app_logger.debug(f"Unknown operator: {operator} in condition: {condition}")
                return False
        except (ValueError, TypeError) as e:
            app_logger.debug(f"Type error in condition check {condition} for value {packet_value}: {e}")
            return False
        except Exception as e:
            app_logger.error(f"Unexpected error in _check_condition for {condition}: {e}")
            return False

    def analyze_packets(self, features_df):
        """
        Analyzes a DataFrame of packet features against the loaded rules.
        Returns a list of alerts.
        """
        alerts = []
        if features_df.empty:
            app_logger.info("No features to analyze in rule-based engine.")
            return alerts

        app_logger.info(f"Analyzing {len(features_df)} packets with rule-based engine.")

        for rule in self.rules:
            rule_id = rule.get('rule_id', 'UNKNOWN_RULE')
            rule_name = rule.get('name', rule_id)
            app_logger.debug(f"Applying rule: {rule_name} ({rule_id})")
            
            # Handle aggregation rules
            if "aggregation" in rule:
                aggregation_config = rule["aggregation"]
                group_by_field = aggregation_config.get("group_by")
                count_threshold = aggregation_config.get("count_threshold")
                
                if not group_by_field or count_threshold is None:
                    app_logger.error(f"Malformed aggregation config for rule {rule_id}: {aggregation_config}. Skipping.")
                    continue
                
                if group_by_field not in features_df.columns:
                    app_logger.debug(f"Aggregation field '{group_by_field}' not found in features_df for rule {rule_id}. Skipping.")
                    continue

                filtered_df = features_df.copy()
                conditions_met_mask = pd.Series(True, index=filtered_df.index)
                for condition in rule["conditions"]:
                    current_condition_mask = filtered_df.apply(lambda row: self._check_condition(row, condition), axis=1)
                    conditions_met_mask = conditions_met_mask & current_condition_mask
                
                filtered_df = filtered_df[conditions_met_mask]
                
                if not filtered_df.empty:
                    grouped_counts = filtered_df.groupby(group_by_field).size()
                    for group_val, count in grouped_counts.items():
                        if count >= count_threshold:
                            example_packet_series = filtered_df[filtered_df[group_by_field] == group_val].iloc[0]
                            alert = {
                                "engine": "RuleBasedEngine",
                                "rule_id": rule_id,
                                "rule_name": rule_name,
                                "severity": rule.get("severity", "Unknown"),
                                "description": rule.get("description", "No description provided."),
                                "aggregation_field": str(group_by_field), # Ensure string
                                "aggregation_value": str(group_val), # Ensure string
                                "count": int(count), # Convert to native int
                                "threshold": int(count_threshold), # Ensure native int
                                "example_packet_id": int(example_packet_series.get("id")) if pd.notna(example_packet_series.get("id")) else None, # Convert to native int
                                "example_timestamp": float(example_packet_series.get("timestamp")) if pd.notna(example_packet_series.get("timestamp")) else None, # Convert to native float
                                "details": f"Aggregated count {count} for {group_by_field}={group_val} exceeded threshold {count_threshold}."
                            }
                            alerts.append(convert_numpy_types(alert)) # APPLY CONVERSION HERE
                            app_logger.warning(f"ALERT (Aggregation Rule '{rule_name}'): Triggered for {group_by_field}={group_val} (Count: {count})")
            
            # Handle per-packet rules
            else:
                for index, packet_series in features_df.iterrows():
                    all_conditions_met = True
                    for condition in rule["conditions"]:
                        if not self._check_condition(packet_series, condition):
                            all_conditions_met = False
                            break
                    if all_conditions_met:
                        alert = {
                            "engine": "RuleBasedEngine",
                            "rule_id": rule_id,
                            "rule_name": rule_name,
                            "severity": rule.get("severity", "Unknown"),
                            "description": rule.get("description", "No description provided."),
                            "packet_id": int(packet_series.get("id")) if pd.notna(packet_series.get("id")) else None, # Convert to native int
                            "timestamp": float(packet_series.get("timestamp")) if pd.notna(packet_series.get("timestamp")) else None, # Convert to native float
                            "src_ip": str(packet_series.get("src_ip")), # Ensure string
                            "dst_ip": str(packet_series.get("dst_ip")), # Ensure string
                            "src_port": int(packet_series.get("src_port")) if pd.notna(packet_series.get("src_port")) else None, # Convert to native int
                            "dst_port": int(packet_series.get("dst_port")) if pd.notna(packet_series.get("dst_port")) else None, # Convert to native int
                            "protocol_name": str(packet_series.get("protocol_name")) if pd.notna(packet_series.get("protocol_name")) else None, # Ensure string
                            "details": f"Matched on packet: ID={packet_series.get('id')}, Src={packet_series.get('src_ip')}, Dst={packet_series.get('dst_ip')}"
                        }
                        alerts.append(convert_numpy_types(alert)) # APPLY CONVERSION HERE
                        app_logger.warning(f"ALERT (Per-Packet Rule '{rule_name}'): Triggered for packet ID {packet_series.get('id', index)}")
        
        app_logger.info(f"Rule-based analysis complete. Generated {len(alerts)} alerts.")
        return alerts

if __name__ == '__main__':
    from data_collector.packet_parser import parse_pcap_file
    from preprocessor.feature_extractor import extract_packet_features
    from threat_intelligence.feed_manager import ThreatIntelligenceManager
    
    datasets_dir = os.path.join(project_root, 'datasets')
    configs_dir = os.path.join(project_root, 'configs')
    if not os.path.exists(datasets_dir): os.makedirs(datasets_dir)
    if not os.path.exists(configs_dir): os.makedirs(configs_dir)

    sample_pcap = os.path.join(datasets_dir, "sample.pcap")
    rules_file = os.path.join(configs_dir, "rules.json")
    ti_feeds_file = os.path.join(configs_dir, "ti_feeds.json")

    # Ensure sample.pcap exists (generated by packet_parser's __main__ or main.py's __main__)
    if not os.path.exists(sample_pcap):
        app_logger.error(f"Sample PCAP not found at {sample_pcap}. Please run `python {os.path.join(os.path.dirname(__file__), '..', 'data_collector', 'packet_parser.py')}` to create it.")
        sys.exit(1) # Exit if essential data is missing
    
    # Ensure ti_feeds.json and dummy blacklists exist (generated by threat_intelligence.feed_manager's __main__ or main.py's __main__)
    if not os.path.exists(ti_feeds_file):
        app_logger.error(f"TI feeds config not found at {ti_feeds_file}. Please run `python {os.path.join(os.path.dirname(__file__), '..', 'threat_intelligence', 'feed_manager.py')}` to create it.")
        sys.exit(1) # Exit if essential config is missing

    # Create dummy rules.json if it doesn't exist
    if not os.path.exists(rules_file):
        app_logger.info(f"Creating a default rules.json at {rules_file}.")
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
        app_logger.info("Default rules.json created.")

    ti_manager = ThreatIntelligenceManager(feeds_config_path=ti_feeds_file, update_interval_hours=0) # Update immediately
    
    # Only proceed if essential files exist
    if os.path.exists(sample_pcap) and os.path.exists(ti_feeds_file) and os.path.exists(rules_file):
        raw_packets = parse_pcap_file(sample_pcap)
        if raw_packets:
            packet_features = extract_packet_features(raw_packets)
            engine = RuleBasedEngine(rules_file_path=rules_file, ti_manager=ti_manager)
            detected_alerts = engine.analyze_packets(packet_features)
            if detected_alerts:
                print("\n--- DETECTED ALERTS (Rule-Based) ---")
                for alrt in detected_alerts:
                    print(json.dumps(alrt, indent=2))
            else:
                print("\nNo alerts generated by rule-based engine for the sample pcap.")
        else:
            app_logger.error("No packets parsed from sample PCAP.")
    else:
        app_logger.error("Missing essential files for rule-based engine test. Please check logs for details.")