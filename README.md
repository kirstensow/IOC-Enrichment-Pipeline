# IOC Enrichment Pipeline

A Python tool that reads CSV files containing IOCs and queries them against VirusTotal and AbuseIPDB to extract threat intelligence, assign risk ratings. 
Enriched results are exported to a CSV file.

## Features
- Processes all IOCs in 'iocs.csv' file
- Queries each IOC using VirusTotal and AbuseIPDB API calls
- Extracts:
    - VT Malicious Score
    - AbuseIPDB Score
    - Country
    - Owner    
- Assigns a risk rating (HIGH, MEDIUM, LOW) by comparing against threshold 
- Exports enriched IOC to CSV 'results.csv'


## How to Use
Run with default files (iocs.csv and results.csv):
python3 main.py

Or specify custom input/output files:
python3 main.py --input my_iocs.csv --output my_results.csv

For help:
python3 main.py --help

## Setup
1. Sign up for free API keys:
   - VirusTotal: https://www.virustotal.com
   - AbuseIPDB: https://www.abuseipdb.com

2. Create a `.env` file in the project folder:
    VT_API_KEY=your_virustotal_key_here
    ABUSEIPDB_API_KEY=your_abuseipdb_key_here
   
3. Install dependencies:
   pip install requests python-dotenv
     
4. Add your IOCs to `iocs.csv` and run:
```bash
python3 main.py
```
5. Results are printed to terminal and exported to `results.csv`

## Example Output
IOC:  8.8.8.8
Malicious detections: 0/91
Suspicious detections: 0/91
US
Google LLC
Abuse Confidence Score:  0
Total Reports:  104
Country Code:  US
Risk Rating: LOW


## Built With
- Python 3
- os (built-in)
- time (built-in)
- csv (built-in)
- requests 
- dotenv

## Requirements
pip install requests python-dotenv
