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
import requests # For fetching from URLs, install: pip install requests
import time
import os # For path operations

class ThreatIntelligenceManager:
    def __init__(self, feeds_config_path="configs/ti_feeds.json", update_interval_hours=24):
        self.feeds_config_path = os.path.join(project_root, feeds_config_path) if not os.path.isabs(feeds_config_path) else feeds_config_path
        self.update_interval = update_interval_hours * 3600 # Convert hours to seconds
        self.last_update_time = 0
        self.blacklist_ips = set()
        self.blacklist_domains = set()
        self.blacklist_hashes = set() # For file hashes if you implement file analysis

        self._load_feeds_config()
        self.update_feeds() # Initial update on startup
        app_logger.info("Threat Intelligence Manager initialized.")

    def _load_feeds_config(self):
        """Loads configuration for TI feeds from a JSON file."""
        try:
            with open(self.feeds_config_path, 'r') as f:
                self.feeds_config = json.load(f)
            app_logger.info(f"Loaded TI feed configuration from {self.feeds_config_path}.")
        except FileNotFoundError:
            app_logger.error(f"TI feeds configuration file not found: {self.feeds_config_path}. Using empty config.")
            self.feeds_config = {"ip_feeds": [], "domain_feeds": [], "hash_feeds": []}
        except json.JSONDecodeError as e:
            app_logger.error(f"Error decoding JSON from TI feeds config file {self.feeds_config_path}: {e}. Using empty config.")
            self.feeds_config = {"ip_feeds": [], "domain_feeds": [], "hash_feeds": []}


    def update_feeds(self):
        """Fetches and updates threat intelligence feeds if interval has passed."""
        current_time = time.time()
        if (current_time - self.last_update_time) < self.update_interval:
            app_logger.info("Threat intelligence feeds are up to date (within interval).")
            return

        app_logger.info("Updating threat intelligence feeds...")
        new_blacklist_ips = set()
        new_blacklist_domains = set()
        new_blacklist_hashes = set()

        # IP Feeds
        for feed_url in self.feeds_config.get("ip_feeds", []):
            try:
                # Handle local file feeds
                if feed_url.startswith("file://"):
                    file_path = feed_url[len("file://"):]
                    # Ensure path is absolute and within project context if relative
                    if not os.path.isabs(file_path):
                        file_path = os.path.join(project_root, file_path)
                    
                    if not os.path.exists(file_path):
                        app_logger.error(f"Local file feed not found: {file_path}")
                        continue
                    
                    with open(file_path, 'r') as f:
                        content = f.read()
                else: # Assume HTTP/HTTPS for other URLs
                    response = requests.get(feed_url, timeout=10)
                    response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
                    content = response.text
                
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'): # Ignore comments and empty lines
                        new_blacklist_ips.add(line)
                app_logger.info(f"Successfully updated IP feed from {feed_url}")
            except requests.exceptions.RequestException as e:
                app_logger.error(f"Error fetching IP feed from {feed_url}: {e}")
            except Exception as e:
                app_logger.error(f"An unexpected error occurred processing IP feed {feed_url}: {e}")

        # Domain Feeds
        for feed_url in self.feeds_config.get("domain_feeds", []):
            try:
                if feed_url.startswith("file://"):
                    file_path = feed_url[len("file://"):]
                    if not os.path.isabs(file_path):
                        file_path = os.path.join(project_root, file_path)
                    if not os.path.exists(file_path):
                        app_logger.error(f"Local file feed not found: {file_path}")
                        continue
                    with open(file_path, 'r') as f:
                        content = f.read()
                else:
                    response = requests.get(feed_url, timeout=10)
                    response.raise_for_status()
                    content = response.text
                
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        new_blacklist_domains.add(line)
                app_logger.info(f"Successfully updated Domain feed from {feed_url}")
            except requests.exceptions.RequestException as e:
                app_logger.error(f"Error fetching Domain feed from {feed_url}: {e}")
            except Exception as e:
                app_logger.error(f"An unexpected error occurred processing Domain feed {feed_url}: {e}")

        # Hash Feeds
        for feed_url in self.feeds_config.get("hash_feeds", []):
            try:
                if feed_url.startswith("file://"):
                    file_path = feed_url[len("file://"):]
                    if not os.path.isabs(file_path):
                        file_path = os.path.join(project_root, file_path)
                    if not os.path.exists(file_path):
                        app_logger.error(f"Local file feed not found: {file_path}")
                        continue
                    with open(file_path, 'r') as f:
                        content = f.read()
                else:
                    response = requests.get(feed_url, timeout=10)
                    response.raise_for_status()
                    content = response.text
                
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        new_blacklist_hashes.add(line.lower()) # Store hashes in lowercase
                app_logger.info(f"Successfully updated Hash feed from {feed_url}")
            except requests.exceptions.RequestException as e:
                app_logger.error(f"Error fetching Hash feed from {feed_url}: {e}")
            except Exception as e:
                app_logger.error(f"An unexpected error occurred processing Hash feed {feed_url}: {e}")


        self.blacklist_ips = new_blacklist_ips
        self.blacklist_domains = new_blacklist_domains
        self.blacklist_hashes = new_blacklist_hashes
        self.last_update_time = current_time
        app_logger.info(f"Threat intelligence update complete. Loaded {len(self.blacklist_ips)} IPs, {len(self.blacklist_domains)} domains, {len(self.blacklist_hashes)} hashes.")

    def is_ip_blacklisted(self, ip_address):
        return ip_address in self.blacklist_ips

    def is_domain_blacklisted(self, domain_name):
        return domain_name in self.blacklist_domains

    def is_hash_blacklisted(self, file_hash):
        return file_hash.lower() in self.blacklist_hashes

if __name__ == '__main__':
    # Create a dummy ti_feeds.json for testing
    config_dir = os.path.join(project_root, 'configs')
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
    ti_feeds_path = os.path.join(config_dir, "ti_feeds.json")
    
    if not os.path.exists(ti_feeds_path):
        app_logger.info(f"Creating a dummy TI feeds config at {ti_feeds_path}.")
        dummy_ti_config = {
            "ip_feeds": [
                # Example public blacklists (use with caution, ensure they are up-to-date and reputable)
                # "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", # Example, actual feed large
                # For testing, create a simple local dummy feed
                "file://" + os.path.join(config_dir, "dummy_ip_blacklist.txt") # Local dummy file
            ],
            "domain_feeds": [
                 "file://" + os.path.join(config_dir, "dummy_domain_blacklist.txt")
            ],
            "hash_feeds": []
        }
        with open(ti_feeds_path, 'w') as f:
            json.dump(dummy_ti_config, f, indent=4)
        
        # Create dummy local blacklist files
        with open(os.path.join(config_dir, "dummy_ip_blacklist.txt"), 'w') as f:
            f.write("1.1.1.1\n8.8.8.8\n10.10.10.10\n")
        with open(os.path.join(config_dir, "dummy_domain_blacklist.txt"), 'w') as f:
            f.write("malicious.com\nbad-domain.net\n")
        
        app_logger.info("Dummy TI feed config and local blacklist files created.")

    ti_manager = ThreatIntelligenceManager(feeds_config_path=ti_feeds_path, update_interval_hours=0) # Update immediately for test

    print("\n--- Threat Intelligence Checks ---")
    print(f"Is 1.1.1.1 blacklisted? {ti_manager.is_ip_blacklisted('1.1.1.1')}")
    print(f"Is 10.10.10.10 blacklisted? {ti_manager.is_ip_blacklisted('10.10.10.10')}") # This IP is in packet_parser.py's sample pcap
    print(f"Is 192.168.1.1 blacklisted? {ti_manager.is_ip_blacklisted('192.168.1.1')}")
    print(f"Is malicious.com blacklisted? {ti_manager.is_domain_blacklisted('malicious.com')}")
    print(f"Is google.com blacklisted? {ti_manager.is_domain_blacklisted('google.com')}")
    print(f"Is hash 'abcdef123456' blacklisted? (expected False) {ti_manager.is_hash_blacklisted('abcdef123456')}")
    
    # Test update interval
    time.sleep(2) # Wait 2 seconds
    app_logger.info("\nAttempting to update again after 2 seconds (should be skipped if interval > 0):")
    ti_manager.update_feeds()
