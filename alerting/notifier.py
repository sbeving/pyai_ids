# --- IMPORTANT: Add this block to any file in a subdirectory if you run it directly ---
import sys
import os

# Get the path to the project root (pyai_ids directory)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# --- END IMPORTANT BLOCK ---
from utils.logger import app_logger
import json

def console_alerter(alert):
    """
    Simple alerter that prints the alert to the console.
    In a real system, this could send emails, integrate with SIEMs, etc.
    """
    app_logger.warning(f"ALERT TRIGGERED from {alert.get('engine', 'Unknown Engine')}: {alert.get('rule_name', alert.get('description', 'No Description'))}")
    print("\n🚨 --- INTRUSION ALERT --- 🚨")
    print(json.dumps(alert, indent=2, sort_keys=True))
    print("---------------------------\n")

def dispatch_alert(alert, method="console"):
    """Dispatches the alert using the specified method."""
    if method == "console":
        console_alerter(alert)
    # Add other dispatch methods here (e.g., email, SIEM, HTTP POST to webhook)
    # elif method == "email":
    #     email_alerter(alert)
    else:
        app_logger.error(f"Unknown alert dispatch method: {method}")

if __name__ == '__main__':
    sample_alert_data = {
        "engine": "TestEngine",
        "rule_id": "TEST001",
        "rule_name": "Test Alert",
        "severity": "Critical",
        "description": "This is a test alert from the notifier module.",
        "timestamp": "2023-10-26T10:00:00Z",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.5",
        "details": "Some specific details about the test event."
    }
    dispatch_alert(sample_alert_data)
