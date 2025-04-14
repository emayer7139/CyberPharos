#!/usr/bin/env python3
"""
threat_dashboard.py

This script generates visual dashboards from enriched threat intelligence data.
It reads NDJSON log data produced by the log_ingestion module, enriches it using 
the threat_intel module (e.g., querying VirusTotal), and uses Matplotlib to create 
charts displaying metrics such as IP reputation scores and analysis statistics.
"""
import sys
import os

project_root = os.path.join(os.path.dirname(__file__), "..")
if project_root not in sys.path:
    sys.path.append(project_root)

import logging
import matplotlib.pyplot as plt
from src.log_ingestion import parse_ndjson_log  # Ensure this function is in log_ingestion.py
from src.threat_intel import enrich_logs        # Ensure this function is in threat_intel.py

def plot_ip_reputations(data):
    """
    Plot a bar chart of IP reputation scores.

    Parameters:
        data (list of dict): Each dictionary should contain:
            - 'ip' (str): The IP address.
            - 'intel': A dictionary containing threat intelligence data,
                       where reputation is found under intel["data"]["attributes"]["reputation"].
    """
    ips = []
    reputations = []
    for entry in data:
        ip = entry.get("ip")
        intel = entry.get("intel")
        if intel and "data" in intel and "attributes" in intel["data"]:
            reputation = intel["data"]["attributes"].get("reputation", 0)
            ips.append(ip)
            reputations.append(reputation)
    if not ips:
        logging.warning("No IP reputation data available for plotting.")
        return
    plt.figure(figsize=(10, 6))
    plt.bar(ips, reputations)
    plt.title("IP Reputation Scores")
    plt.xlabel("IP Address")
    plt.ylabel("Reputation Score")
    plt.grid(True)
    plt.tight_layout()
    plt.show()

def plot_analysis_stats(data):
    """
    Plot separate bar charts for each analysis metric across different IP addresses.

    Parameters:
        data (list of dict): Each dictionary should contain:
            - 'ip' (str): The IP address.
            - 'intel': A dictionary with threat intelligence details, where analysis stats
                       can be found under intel["data"]["attributes"]["last_analysis_stats"].
    """
    for entry in data:
        ip = entry.get("ip")
        intel = entry.get("intel")
        if intel and "data" in intel and "attributes" in intel["data"]:
            stats = intel["data"]["attributes"].get("last_analysis_stats", {})
            if stats:
                metric_keys = list(stats.keys())
                plt.figure(figsize=(10, 6))
                values = [stats.get(metric, 0) for metric in metric_keys]
                plt.bar(metric_keys, values)
                plt.title(f"Analysis Stats for {ip}")
                plt.xlabel("Metrics")
                plt.ylabel("Count")
                plt.grid(True)
                plt.tight_layout()
                plt.show()

def get_live_data():
    """
    Reads NDJSON log data from a file using log_ingestion, enriches it with threat intelligence,
    and returns the enriched log entries.

    Returns:
        list of dict: List of enriched log entries. Each entry will have an 'ip' key added for plotting.
    """
    ndjson_file_path = "sample_logs.ndjson"  # Ensure this file exists with appropriate NDJSON logs
    logs = parse_ndjson_log(ndjson_file_path)
    
    vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not vt_api_key:
        logging.error("VirusTotal API key not set in environment variables.")
        return logs  # Return the parsed logs even if not enriched
    
    # Enrich logs with threat intelligence data
    enriched_logs = enrich_logs(logs, vt_api_key)
    
    # For consistency in visualization, map 'host' to 'ip'
    for log in enriched_logs:
        log["ip"] = log.get("host")
    return enriched_logs

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Get live enriched data from NDJSON logs via the log_ingestion module
    data = get_live_data()
    
    # Plot the IP reputation scores from the enriched data
    plot_ip_reputations(data)
    
    # Plot the analysis statistics for each IP
    plot_analysis_stats(data)

if __name__ == "__main__":
    main()
