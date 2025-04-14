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
        dict or None: A dictionary containing the threat intelligence data if successful; 
                      None if an error occurred.
    """
    # VirusTotal API endpoint for IP address lookup (v3)
    base_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    
    headers = {
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(base_url, headers=headers, timeout=10)
        response.raise_for_status()  # This raises an error for HTTP error codes
        intel_data = response.json()  # Convert response to JSON
        return intel_data
    except requests.RequestException as e:
        logging.error("Error fetching VirusTotal data for IP %s: %s", ip_address, e)
        return None
    except ValueError as e:
        # Handle JSON decoding error
        logging.error("Error decoding VirusTotal response for IP %s: %s", ip_address, e)
        return None

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Example IP address. You can change it as needed.
    sample_ip = "8.8.8.8"
    
    # Retrieve API key from environment or hardcode for testing
    vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY", "YOUR_ACTUAL_VIRUSTOTAL_API_KEY")
    
    if vt_api_key is None or vt_api_key == "YOUR_ACTUAL_VIRUSTOTAL_API_KEY":
        logging.error("VirusTotal API key not properly set. Please set the VIRUSTOTAL_API_KEY environment variable or update your code.")
    else:
        intel = fetch_virustotal_intel(sample_ip, vt_api_key)
        if intel:
            logging.info("VirusTotal data for %s: %s", sample_ip, intel)
        else:
            logging.info("No data retrieved for IP %s", sample_ip)
