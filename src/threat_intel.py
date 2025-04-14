#!/usr/bin/env python3
"""
threat_intel.py

This module integrates with VirusTotal to enrich log data with threat intelligence.
It contains functions to fetch intelligence for a given IP and to enrich log entries.
"""

import os
import requests
import logging

def fetch_virustotal_intel(ip_address, api_key):
    """
    Fetch threat intelligence data for the specified IP address using VirusTotal's API.
    
    Parameters:
        ip_address (str): The IP address to look up.
        api_key (str): Your VirusTotal API key.
        
    Returns:
        dict or None: The JSON response from VirusTotal, or None if an error occurs.
    """
    base_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(base_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error("Error fetching VirusTotal data for IP %s: %s", ip_address, e)
        return None

def enrich_log(log, api_key):
    """
    Enrich a single log dictionary using threat intelligence.
    The log is expected to have a 'host' key containing an IP address.
    
    Parameters:
        log (dict): A log entry.
        api_key (str): VirusTotal API key.
        
    Returns:
        dict: The original log with an additional 'intel' key for enrichment data.
    """
    ip = log.get("host", "")
    # Basic IP address check: if the host consists of parts separated by '.' and each part is numeric.
    if ip and all(part.isdigit() for part in ip.split('.')):
        intel = fetch_virustotal_intel(ip, api_key)
        log["intel"] = intel
    else:
        log["intel"] = None
    return log

def enrich_logs(logs, api_key):
    """
    Enrich a list of log dictionaries.
    
    Parameters:
        logs (list): List of log dictionaries.
        api_key (str): VirusTotal API key.
        
    Returns:
        list: The list of enriched logs.
    """
    return [enrich_log(log, api_key) for log in logs]
