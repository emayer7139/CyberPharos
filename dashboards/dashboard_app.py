#!/usr/bin/env python3
"""
dashboard_app.py

A comprehensive web dashboard for CyberPharos built with Plotly Dash.
This dashboard reads NDJSON log data, enriches it using threat intelligence data
from VirusTotal, and displays the results in various tabs. Users can refresh data,
view summary statistics, detailed charts (IP reputations and analysis statistics),
raw data, and even trigger the enrichment process.
"""

import os
import sys
import logging
import json

from dash import Dash, dcc, html, Input, Output
import dash_bootstrap_components as dbc
import plotly.express as px
from dotenv import load_dotenv

# Set the project root directory (assumes file structure where 'sample_logs.ndjson' and 'src' are in project root)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Load environment variables from the .env file in the project root
dotenv_path = os.path.join(PROJECT_ROOT, ".env")
load_dotenv(dotenv_path=dotenv_path)

# Import our local modules
from src.log_ingestion import parse_ndjson_log
from src.threat_intel import enrich_logs

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def get_live_data():
    """
    Reads NDJSON log data from file, enriches it with threat intelligence, and returns the enriched entries.
    """
    ndjson_file_path = os.path.join(PROJECT_ROOT, "sample_logs.ndjson")
    logs = parse_ndjson_log(ndjson_file_path)
    
    vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not vt_api_key:
        logging.error("VirusTotal API key not set in environment variables.")
        return logs  # Return logs un-enriched if key is missing

    enriched_logs = enrich_logs(logs, vt_api_key)
    for log in enriched_logs:
        log["ip"] = log.get("host")
    return enriched_logs


def generate_ip_reputation_figure(data):
    """
    Generate a bar chart of IP reputation scores from the enriched data.
    """
    reputations = []
    for entry in data:
        ip = entry.get("ip")
        intel = entry.get("intel", {})
        reputation = intel.get("data", {}).get("attributes", {}).get("reputation", None)
        if ip and reputation is not None:
            reputations.append({"ip": ip, "reputation": reputation})
    if not reputations:
        return {}
    fig = px.bar(
        reputations, 
        x="ip", 
        y="reputation", 
        title="IP Reputation Scores",
        labels={"ip": "IP Address", "reputation": "Reputation Score"}
    )
    return fig


def generate_analysis_stats_figures(data):
    """
    For each log entry that has analysis statistics, generate a bar chart.
    Returns a dictionary mapping IP addresses to their respective figures.
    """
    figures = {}
    for entry in data:
        ip = entry.get("ip")
        intel = entry.get("intel", {})
        stats = intel.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if stats and ip:
            stats_data = [{"metric": k, "count": v} for k, v in stats.items()]
            fig = px.bar(
                stats_data, 
                x="metric", 
                y="count",
                title=f"Analysis Stats for {ip}",
                labels={"metric": "Metric", "count": "Count"}
            )
            figures[ip] = fig
    return figures


# Initialize Dash app and enable suppress_callback_exceptions to support dynamic layouts
app = Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP],
           suppress_callback_exceptions=True)
server = app.server  # For deployment with WSGI servers

# Define the Dash app layout
app.layout = dbc.Container(
    [
        html.H1("CyberPharos Dashboard"),
        html.P("A comprehensive visualization dashboard for threat intelligence data."),
        dbc.Button("Refresh Data", id="refresh-button", color="primary", className="mb-2"),
        dcc.Tabs(
            id="tabs",
            value="tab-overview",
            children=[
                dcc.Tab(label="Overview", value="tab-overview"),
                dcc.Tab(label="IP Reputation", value="tab-ip"),
                dcc.Tab(label="Analysis Stats", value="tab-analysis"),
                dcc.Tab(label="Raw Data", value="tab-raw"),
                dcc.Tab(label="Run Program", value="tab-run")
            ]
        ),
        html.Div(id="tabs-content", style={"marginTop": 20})
    ],
    fluid=True,
)


@app.callback(
    Output("tabs-content", "children"),
    [Input("tabs", "value"),
     Input("refresh-button", "n_clicks")]
)
def render_tab_content(tab_value, n_clicks):
    # Each time the refresh button is pressed or the tab is switched, reload the data.
    data = get_live_data()

    if tab_value == "tab-overview":
        total_logs = len(data)
        unique_ips = len(set(entry.get("ip") for entry in data if entry.get("ip")))
        overview_text = f"Total log entries: {total_logs}, Unique IPs: {unique_ips}."
        fig = generate_ip_reputation_figure(data)
        return html.Div([
            html.H3("Overview"),
            html.P(overview_text),
            dcc.Graph(figure=fig)
        ])

    elif tab_value == "tab-ip":
        fig = generate_ip_reputation_figure(data)
        return html.Div([
            html.H3("IP Reputation"),
            dcc.Graph(figure=fig)
        ])

    elif tab_value == "tab-analysis":
        figs = generate_analysis_stats_figures(data)
        content = []
        for ip, fig in figs.items():
            content.append(html.H4(f"Analysis Stats for {ip}"))
            content.append(dcc.Graph(figure=fig))
        return html.Div(content)

    elif tab_value == "tab-raw":
        return html.Div([
            html.H3("Raw Data"),
            dcc.Textarea(
                id="raw-data-text",
                value=json.dumps(data, indent=2),
                style={"width": "100%", "height": 400},
            )
        ])

    elif tab_value == "tab-run":
        return html.Div([
            html.H3("Run Program"),
            html.P("Click the button below to trigger the threat intelligence enrichment process."),
            dbc.Button("Run Enrichment", id="run-enrichment-button", color="secondary", className="mb-2"),
            html.Div(id="run-output")
        ])

    else:
        return html.Div("Unknown tab selected.")


@app.callback(
    Output("run-output", "children"),
    Input("run-enrichment-button", "n_clicks")
)
def run_enrichment_process(n_clicks):
    if n_clicks:
        # Trigger enrichment by reloading the data.
        data = get_live_data()
        return html.P("Threat intelligence enrichment process completed successfully.")
    return ""


if __name__ == "__main__":
    app.run(debug=True)
