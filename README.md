# IOC - Enrichment- Pipeline

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
1. Place your IOCs in 'iocs.csv' file
2. Run the script:
```bash
python3 main.py
```
3. Results are printed to terminal and exported to `results.csv`

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
