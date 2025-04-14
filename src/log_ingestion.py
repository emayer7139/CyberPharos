#!/usr/bin/env python3
"""
log_ingestion.py

A module for ingesting and parsing logs from multiple formats:
- Syslog lines
- JSON-formatted logs
- CSV logs

This file contains functions to parse each log format and a helper function 
to process an entire file. All error handling is performed via logging.
"""

import json
import csv
import logging

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def parse_syslog_line(line):
    """
    Parse a syslog line into its components.
    
    Expected format: "Jan 12 06:25:34 hostname process[pid]: message"
    
    Returns:
        dict: Contains 'timestamp', 'host', and 'message' if parsing is successful.
        None: If the line cannot be parsed properly.
    """
    parts = line.strip().split()
    if len(parts) < 5:
        logging.warning("Syslog line does not have enough parts to parse: %s", line)
        return None
    timestamp = " ".join(parts[:3])
    host = parts[3]
    message = " ".join(parts[4:])
    return {"timestamp": timestamp, "host": host, "message": message}

def parse_json_log(json_line):
    """
    Parse a log line in JSON format.
    
    Returns:
        dict: The parsed JSON as a dictionary if successful.
        None: If JSON decoding fails.
    """
    try:
        return json.loads(json_line)
    except json.JSONDecodeError as e:
        logging.error("JSON decoding error: %s. Line: %s", e, json_line)
        return None

def parse_csv_log(csv_file_path):
    """
    Parse a CSV file containing logs.
    
    The CSV is assumed to have a header row with columns: timestamp, host, message.
    
    Parameters:
        csv_file_path (str): The path to the CSV file.
    
    Returns:
        list: A list of dictionaries, each representing a log entry.
    """
    logs = []
    try:
        with open(csv_file_path, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                logs.append(row)
    except Exception as e:
        logging.error("Error reading CSV file: %s", e)
    return logs

def parse_logs_from_file(file_path, format):
    """
    Parse logs from a file given the file path and format.
    
    Parameters:
        file_path (str): Path to the log file.
        format (str): The format of the logs ('syslog', 'json', or 'csv').
        
    Returns:
        list: A list of parsed log entries.
    """
    parsed_logs = []
    try:
        if format.lower() == 'csv':
            return parse_csv_log(file_path)
        with open(file_path, 'r', encoding='utf-8') as file:
            if format.lower() == 'json':
                # Each line in the file is a JSON formatted log
                for line in file:
                    parsed = parse_json_log(line)
                    if parsed:
                        parsed_logs.append(parsed)
            elif format.lower() == 'syslog':
                # Each line in the file is a syslog formatted log
                for line in file:
                    parsed = parse_syslog_line(line)
                    if parsed:
                        parsed_logs.append(parsed)
            else:
                logging.error("Unknown log format specified: %s", format)
    except Exception as e:
        logging.error("Error opening file %s: %s", file_path, e)
    return parsed_logs
