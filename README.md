# CyberPharos

CyberPharos is a comprehensive cybersecurity analytics and incident response platform designed to demonstrate your skills in threat hunting, log ingestion, threat intelligence integration, and data visualization. This project simulates a real-world scenario by ingesting NDJSON-formatted logs, enriching them with threat intelligence (using the VirusTotal API), and displaying key metrics via visual dashboards built with Matplotlib. Additionally, CyberPharos includes containerization using Docker and documentation for incident response playbooks.

## Features

- **Log Ingestion:**  
  Supports multiple log formats including syslog, JSON, CSV, and NDJSON. The primary focus is on NDJSON logs, commonly used in large-scale environments.

- **Threat Intelligence Integration:**  
  Queries the VirusTotal API to enrich log entries with information such as IP reputation scores, associated domains, and analysis statistics.

- **Data Visualization:**  
  Generates visual dashboards using Matplotlib to display IP reputation scores and analysis statistics in intuitive bar charts.

- **Incident Response Playbooks:**  
  Contains documented playbooks (in Markdown) detailing standardized procedures for responding to detected threats.

- **Docker Containerization:**  
  The project can be containerized using Docker, ensuring portability and ease of deployment across different environments.

## Project Structure




## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/CyberPharos.git
   cd CyberPharos

2. **Set Up a Virtual Environment**
python -m venv venv
### Activate the virtual environment
### Windows:
venv\Scripts\activate
### Linux/Mac:
source venv/bin/activate

3. **Install Dependencies**
pip install --upgrade pip
pip install -r requirements.txt

4. **Configure Environment Variables**
Create a .env file (or set environment variables directly) with your VirusTotal API key:
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
If you are using python-dotenv, ensure you load the environment in your entry scripts.

