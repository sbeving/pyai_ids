# PyAI-IDS: Advanced Python-based Intrusion Detection System

## 🌟 Project Overview - VIBE CODED - 4FUN

The contemporary digital landscape faces a relentless escalation in the sophistication, frequency, and dynamism of cyber threats. Traditional Intrusion Detection Systems (IDS), often reliant on signature-based detection, struggle to identify zero-day exploits and novel malware variants. This project proposes and implements a prototype of an **Advanced Python-based Intrusion Detection System (PyAI-IDS)**, designed to provide a more intelligent, adaptive, and trustworthy layer of cybersecurity.

PyAI-IDS moves beyond singular detection mechanisms, embracing a multifaceted approach by synergistically combining:
-   **Signature-based detection** for known threats.
-   **Machine Learning (ML)-driven anomaly detection** for identifying deviations from normal behavior.
-   **AI-powered behavioral analysis** to discern complex patterns and suspicious sequences of actions.
-   **Threat Intelligence integration** for correlating internal events with global threat knowledge.
-   **Explainable AI (XAI)** to provide transparency and justification for AI-driven alerts.

This system aims to be a robust platform for research and development in next-generation network security, demonstrating proficiency in Python, cybersecurity principles, data analysis, and ML/DL implementation.

## ✨ Key Features

*   **Hybrid Detection Strategy:** Combines signature-based, anomaly-based, and behavioral detection for comprehensive threat coverage.
*   **Data Collection Layer:** Gathers raw network traffic (PCAP, NetFlow) and host-based logs for a holistic view.
*   **Advanced Feature Engineering:** Transforms raw data into rich, informative features suitable for AI models.
*   **Machine Learning-Driven Anomaly Detection:** Utilizes unsupervised ML (e.g., Isolation Forest) to detect novel and unknown threats by identifying deviations from learned baselines.
*   **AI-Powered Behavioral Analysis:** Establishes and monitors baselines for entity (e.g., IP) behavior, flagging suspicious changes over time.
*   **Threat Intelligence Integration:** Automatically ingests and correlates Indicators of Compromise (IOCs) from external feeds (e.g., blacklisted IPs/domains) with observed network events.
*   **Explainable AI (XAI):** (Partial implementation) Provides insights into why an AI model made a specific detection, enhancing trust and enabling faster analysis (using concepts from LIME/SHAP).
*   **Modular Architecture:** Designed for extensibility, maintainability, and easy integration of new detection techniques or data sources.
*   **Python-based:** Leverages Python's rich ecosystem for rapid development and access to cutting-edge data science and network programming libraries.

## 🚀 Getting Started

Follow these steps to set up and run the PyAI-IDS project.

### Prerequisites

*   Python 3.9+ installed on your system.
*   `pip` (Python package installer).
*   `git` (for cloning the repository).

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/sbeving/pyai_ids.git
    cd pyai_ids
    ```

2.  **Create a Python virtual environment:**
    ```bash
    python -m venv venv
    ```

3.  **Activate the virtual environment:**
    *   **On Windows:**
        ```bash
        .\venv\Scripts\activate
        ```
    *   **On Linux/macOS:**
        ```bash
        source venv/bin/activate
        ```

4.  **Install project dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Create `.gitkeep` files (optional, but recommended):**
    ```powershell
    # On Windows PowerShell:
    New-Item -ItemType File -Path "models\.gitkeep"
    New-Item -ItemType File -Path "datasets\.gitkeep"
    New-Item -ItemType File -Path "logs\.gitkeep"
    ```
    ```bash
    # On Linux/macOS (Bash/Zsh):
    touch models/.gitkeep
    touch datasets/.gitkeep
    touch logs/.gitkeep
    ```

### Usage

The project supports training models and running detection.

#### 1. Generate Sample Data & Train Models

First, generate the necessary dummy PCAP files and train the anomaly and behavioral models. This creates `datasets/sample_normal_traffic.pcap`, `datasets/sample_test_traffic_with_anomalies.pcap`, and saves trained models/profiles in `models/`.

```bash
# Generate sample PCAP files and train the anomaly detection model
# This also creates config.ini, rules.json, ti_feeds.json if they don't exist
python detection_engines/anomaly_engine.py

# Train the behavioral detection model using the generated normal traffic
python main.py --train-behavioral datasets/sample_normal_traffic.pcap
```

#### 2. Run Intrusion Detection

After the models are trained, you can run the IDS in detection mode on a sample PCAP file.

```bash
python main.py --pcap datasets/sample_test_traffic_with_anomalies.pcap
```

You will see log messages and intrusion alerts printed to the console, including details from the rule-based, anomaly, and behavioral engines, and XAI explanations for anomaly alerts (if LIME/SHAP are properly set up).

#### Command-Line Arguments

*   `--pcap <file_path>`: Specifies the PCAP file to analyze for intrusion detection.
*   `--config <file_path>`: (Optional) Path to the configuration file. Defaults to `configs/config.ini`.
*   `--train-anomaly <normal_pcap_path>`: Trains the anomaly detection model using the specified PCAP file as normal traffic.
*   `--train-behavioral <normal_pcap_path>`: Establishes baselines for the behavioral detection engine using the specified PCAP file as normal traffic.

## ⚙️ Configuration

The system uses `configs/config.ini` for general settings and model paths, `configs/rules.json` for signature-based rules, and `configs/ti_feeds.json` for threat intelligence feed URLs. These files are automatically created with default content if they don't exist when you first run the training scripts.

*   **`configs/config.ini`**: Configures log levels, paths to saved ML models and behavioral profiles.
*   **`configs/rules.json`**: Defines signature-based and aggregation rules, including `in_blacklist` operators for TI integration.
*   **`configs/ti_feeds.json`**: Lists URLs for IP, domain, and hash blacklists. For testing, it points to local dummy blacklist files.

## 📊 Evaluation & Metrics

The project is designed to be evaluated using standard IDS performance metrics:

*   **Detection Effectiveness:** Accuracy, Precision, Recall (Detection Rate), F1-score, False Positive Rate (FPR), False Negative Rate (FNR), ROC-AUC / PR-AUC.
*   **Operational Efficiency:** Throughput, Latency, Resource Utilization (CPU, Memory).
*   **Explainability:** Faithfulness, Complexity, Robustness, Reliability (for XAI features).
*   **Resilience:** Adversarial Attack Success Rate (for future work).

## ⚠️ Challenges Addressed

*   **Minimizing False Positives & Negatives:** Employing hybrid detection, careful baseline tuning, and XAI.
*   **Handling Data Imbalance:** Utilizing appropriate ML techniques and evaluation metrics.
*   **Ensuring Model Interpretability & Trust:** Integration of XAI (LIME/SHAP) to provide clear explanations for AI-driven alerts.
*   **Maintaining Up-to-Date Threat Knowledge:** Automated ingestion of threat intelligence feeds and periodic model retraining.
*   **JSON Serialization:** Implemented a utility to convert NumPy/Pandas specific data types to native Python types for seamless JSON serialization in alerts.

## 🚀 Future Enhancements

*   **Live Traffic Capture:** Implement real-time packet sniffing from network interfaces (e.g., using Scapy's `sniff`).
*   **Automated Response (IPS Capabilities):** Integrate active countermeasures like dynamic firewall rule updates, connection termination, or host isolation.
*   **SIEM/SOAR Integration:** Forward alerts and relevant logs to centralized Security Information and Event Management (SIEM) and Security Orchestration, Automation and Response (SOAR) platforms.
*   **Deep Learning Models:** Implement CNNs for packet-level analysis and RNNs/LSTMs for temporal pattern recognition (e.g., APTs).
*   **Federated Learning:** Explore distributed model training for collaborative, privacy-preserving threat intelligence sharing.
*   **Reinforcement Learning:** Investigate dynamic policy adaptation for detection thresholds and automated responses.
*   **Web-based Management Interface:** Develop a user-friendly UI (e.g., using Flask or Django) for configuration, monitoring, and alert visualization.
*   **More Robust Logging:** Implement structured logging to facilitate easier parsing by SIEMs.

## 🤝 Contributing

This project is open for contributions and suggestions. Feel free to fork the repository, submit pull requests, or open issues.

