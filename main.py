from dotenv import load_dotenv
import os
import requests
import json
import time

load_dotenv()
vt_key = os.getenv('VT_API_KEY')
abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')


def risk_score(malicious, abuse_confidence_score):
	if abuse_confidence_score > 80 or malicious > 5:
		return 'HIGH'
	elif abuse_confidence_score > 50 or malicious > 2:
		return 'MEDIUM'
	else:
		return 'LOW'

ioc_list = ['8.8.8.8', '1.1.1.1', '185.220.101.1 ']

for test_ip in ioc_list:
	# VirusTotal API call
	url = f'https://www.virustotal.com/api/v3/ip_addresses/{test_ip}'
	headers = {'x-apikey': vt_key}

	#AbuseIPDB API call
	abuse_url = f'https://api.abuseipdb.com/api/v2/check'
	abuse_headers  = {'Key': abuseipdb_key, 'Accept': 'application/json'}

	params = {'ipAddress': test_ip, 'maxAgeInDays': 90}

	#VT Response
	response = requests.get(url, headers=headers)
	print(f'IOC:  {test_ip}')
	if response.status_code == 200:
		data = response.json()
		stats = data['data']['attributes']['last_analysis_stats']
		malicious = stats['malicious']
		suspicious = stats['suspicious']
		total = sum(stats.values())



		print(f'Malicious detections: {malicious}/{total}')
		print(f'Suspicious detections: {suspicious}/{total}')

		country = datacountry = data['data']['attributes'].get('country', 'Unknown')
		print(country)

		as_owner = data['data']['attributes'].get('as_owner', 'Unknown')
		print(as_owner)

	else:
		print(f'VT lookup failed for {test_ip}: {response.status_code}')


	#AbuseIPDB Response
	abuse_response = requests.get(url= abuse_url, headers=abuse_headers, params=params)
	if abuse_response.status_code == 200:
		abuse_data = abuse_response.json()
		abuse_confidence_score = abuse_data['data']['abuseConfidenceScore']
		print('Abuse Confidence Score: ', abuse_confidence_score)

		total_reports = abuse_data['data']['totalReports']
		print('Total Reports: ', total_reports)

		country_code = abuse_data['data']['countryCode']
		print('Country Code: ', country_code)

	else:
		print(f'AbuseOPDB lookup failed for {test_ip}: {abuse_response.status_code}')

	time.sleep(15)






	risk = risk_score (malicious, abuse_confidence_score)
	print(f'Risk Rating: {risk}')

