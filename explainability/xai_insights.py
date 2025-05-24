# --- IMPORTANT: Add this block to any file in a subdirectory if you run it directly ---
import sys
import os

# Get the path to the project root (pyai_ids directory)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# --- END IMPORTANT BLOCK ---

from utils.logger import app_logger
import pandas as pd
import numpy as np
from utils.helpers import convert_numpy_types # NEW: Import helper
# Conditional imports for LIME/SHAP - these libraries might not be installed
try:
    import lime
    import lime.lime_tabular
    LIME_AVAILABLE = True
except ImportError:
    LIME_AVAILABLE = False
    app_logger.warning("LIME library not found. XAI explanations will be limited. Install with 'pip install lime'.")

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    app_logger.warning("SHAP library not found. XAI explanations will be limited. Install with 'pip install shap'.")

import configparser
import json

class XAIInsights:
    def __init__(self, model=None, feature_names=None, normal_data_sample=None):
        """
        :param model: The trained ML model (e.g., IsolationForest instance).
        :param feature_names: List of feature names used by the model (e.g., from _get_numerical_features).
        :param normal_data_sample: A small, representative sample of normal data (scaled) for LIME/SHAP background.
        """
        self.model = model
        self.feature_names = feature_names
        self.normal_data_sample = normal_data_sample
        app_logger.info("Explainable AI Insights module initialized.")

        if not LIME_AVAILABLE and not SHAP_AVAILABLE:
            app_logger.error("Neither LIME nor SHAP are available. XAI module will only provide basic feature display.")


    def _predict_score_wrapper(self, instances):
        """
        Wrapper function for IsolationForest's decision_function for LIME.
        """
        if self.model is None:
            raise ValueError("Model not set for XAI prediction wrapper.")
        
        decision_scores = self.model.decision_function(instances)
        
        anomaly_probs = 1 / (1 + np.exp(decision_scores))
        normal_probs = 1 - anomaly_probs
        
        return np.column_stack((normal_probs, anomaly_probs))


    def explain_anomaly_prediction(self, instance_scaled_features, original_flow_data):
        """
        Generates an explanation for a single anomalous prediction using LIME or SHAP (if available).
        :param instance_scaled_features: The numerical features (scaled) for the specific anomalous instance (2D array: 1 row, N features).
        :param original_flow_data: The original DataFrame row for the anomalous flow, for human-readable context.
        """
        # Convert original_flow_data to native Python types for clean JSON output
        original_flow_data_native = convert_numpy_types(original_flow_data.to_dict())

        explanation_str = "Explanation for Anomaly:\n"
        explanation_str += f"  Flow ID: {original_flow_data_native.get('flow_id_tuple')}\n"
        explanation_str += f"  Source IP: {original_flow_data_native.get('src_ip')}, Destination IP: {original_flow_data_native.get('dst_ip')}\n"
        explanation_str += f"  Protocol: {original_flow_data_native.get('protocol')}\n"
        explanation_str += f"  Anomaly Score: {original_flow_data_native.get('anomaly_score', 'N/A'):.4f}\n"

        if self.model is None or self.feature_names is None or self.normal_data_sample is None:
            explanation_str += "  XAI module not fully configured (missing model, feature names, or normal data sample).\n"
            explanation_str += "  Cannot provide detailed LIME/SHAP explanation.\n"
            explanation_str += "  Raw features for this flow:\n"
            # Show original numerical features, also converted
            raw_features_for_display = convert_numpy_types(original_flow_data[self.feature_names].to_dict()) if self.feature_names else original_flow_data_native
            for feature_name, value in raw_features_for_display.items():
                explanation_str += f"    - {feature_name}: {value}\n"
            return explanation_str

        if instance_scaled_features.ndim == 1:
            instance_scaled_features = instance_scaled_features.reshape(1, -1)

        # LIME Explanation
        if LIME_AVAILABLE:
            try:
                app_logger.debug("Attempting LIME explanation.")
                explainer = lime.lime_tabular.LimeTabularExplainer(
                    training_data=self.normal_data_sample,
                    feature_names=self.feature_names,
                    class_names=['Normal', 'Anomaly'],
                    mode='classification',
                )
                
                explanation = explainer.explain_instance(
                    data_row=instance_scaled_features[0],
                    predict_fn=self._predict_score_wrapper,
                    num_features=5,
                    top_labels=1
                )
                
                explanation_str += "\n--- LIME Explanation (Top 5 Features Contributing to Anomaly) ---\n"
                for feature, weight in explanation.as_list():
                    explanation_str += f"  - {feature}: {weight:.4f}\n"
                explanation_str += "(Note: Higher positive weight indicates more contribution to 'Anomaly' class.)\n"
            except Exception as e:
                explanation_str += f"\n--- LIME Explanation (Error) ---\n  Error generating LIME explanation: {e}\n"
                app_logger.error(f"Error during LIME explanation: {e}")
        else:
            explanation_str += "\n--- LIME Explanation (Not Available) ---\n"

        # SHAP Explanation
        if SHAP_AVAILABLE:
            try:
                app_logger.debug("Attempting SHAP explanation.")
                explainer = shap.TreeExplainer(self.model)
                shap_values = explainer.shap_values(instance_scaled_features)
                
                if isinstance(shap_values, list) and len(shap_values) == 1:
                    feature_contributions = shap_values[0][0]
                elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 2 and shap_values.shape[0] == 1:
                    feature_contributions = shap_values[0]
                else:
                    feature_contributions = shap_values

                explanation_str += "\n--- SHAP Explanation (Top 5 Features Contributing to Anomaly) ---\n"
                
                sorted_feature_indices = np.argsort(feature_contributions)
                
                top_anomaly_features = []
                for idx in sorted_feature_indices:
                    if feature_contributions[idx] < 0 and len(top_anomaly_features) < 5:
                        top_anomaly_features.append((self.feature_names[idx], feature_contributions[idx]))
                
                if not top_anomaly_features:
                    explanation_str += "  No strong negative SHAP contributions detected that push towards anomaly.\n"
                    sorted_abs_feature_indices = np.argsort(np.abs(feature_contributions))[::-1]
                    for idx in sorted_abs_feature_indices[:5]:
                        top_anomaly_features.append((self.feature_names[idx], feature_contributions[idx]))
                    explanation_str += "(Showing top 5 absolute contributors as no strong negative ones found):\n"
                    for feature, weight in top_anomaly_features:
                        explanation_str += f"  - {feature}: {weight:.4f}\n"

                else:
                    for feature, weight in top_anomaly_features:
                        explanation_str += f"  - {feature}: {weight:.4f}\n"
                    explanation_str += "(Note: More negative SHAP value indicates stronger contribution to 'Anomaly'.)\n"


            except Exception as e:
                explanation_str += f"\n--- SHAP Explanation (Error) ---\n  Error generating SHAP explanation: {e}\n"
                app_logger.error(f"Error during SHAP explanation: {e}")
        else:
            explanation_str += "\n--- SHAP Explanation (Not Available) ---\n"
        
        explanation_str += "\n--------------------------------------------\n"
        return explanation_str

if __name__ == '__main__':
    from detection_engines.anomaly_engine import AnomalyEngine
    from preprocessor.feature_extractor import extract_packet_features, extract_flow_features
    from data_collector.packet_parser import parse_pcap_file
    
    datasets_dir = os.path.join(project_root, 'datasets')
    models_dir = os.path.join(project_root, 'models')
    configs_dir = os.path.join(project_root, 'configs')
    if not os.path.exists(datasets_dir): os.makedirs(datasets_dir)
    if not os.path.exists(models_dir): os.makedirs(models_dir)
    if not os.path.exists(configs_dir): os.makedirs(configs_dir)

    normal_pcap_path = os.path.join(datasets_dir, "sample_normal_traffic.pcap")
    test_pcap_path = os.path.join(datasets_dir, "sample_test_traffic_with_anomalies.pcap")
    config_path = os.path.join(configs_dir, "config.ini")

    if not os.path.exists(os.path.join(models_dir, 'isolation_forest_anomaly_model.joblib')):
        app_logger.error("Anomaly model not found. Please run anomaly_engine.py directly first to train it and generate sample data.")
        sys.exit(1)

    anomaly_engine = AnomalyEngine(config_path=config_path)
    
    if not anomaly_engine.model or not anomaly_engine.scaler:
        app_logger.error("Anomaly model or scaler could not be loaded. Cannot run XAI demo.")
        sys.exit(1)

    raw_normal_packets = parse_pcap_file(normal_pcap_path)
    normal_packet_df = extract_packet_features(raw_normal_packets)
    normal_flows_df = extract_flow_features(normal_packet_df.copy())
    
    normal_features_for_xai, _ = anomaly_engine._get_numerical_features(normal_flows_df)
    normal_scaled_data_sample = anomaly_engine.scaler.transform(normal_features_for_xai)
    
    raw_test_packets = parse_pcap_file(test_pcap_path)
    test_packet_df = extract_packet_features(raw_test_packets)
    test_flows_df = extract_flow_features(test_packet_df.copy())
    
    if not test_flows_df.empty:
        # Pick a flow that might be anomalous (e.g., largest total bytes)
        anomalous_candidate = test_flows_df.loc[test_flows_df['total_bytes'].idxmax()]
        
        instance_features_df, feature_names = anomaly_engine._get_numerical_features(pd.DataFrame([anomalous_candidate]))
        
        if not instance_features_df.empty:
            instance_scaled_features = anomaly_engine.scaler.transform(instance_features_df)
            
            xai_module = XAIInsights(
                model=anomaly_engine.model, 
                feature_names=feature_names,
                normal_data_sample=normal_scaled_data_sample
            )
            explanation = xai_module.explain_anomaly_prediction(instance_scaled_features, anomalous_candidate)
            print("\n--- XAI Explanation for an Anomalous Flow ---")
            print(explanation)
        else:
            app_logger.warning("Could not prepare features for XAI.")
    else:
        app_logger.warning("No test flows to pick an anomaly from for XAI demo.")