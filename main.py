from dotenv import load_dotenv
import os
import requests
import time
import csv

load_dotenv()
vt_key = os.getenv('VT_API_KEY')
abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')


def risk_score(malicious, abuse_confidence_score):     #Assigns risk score by using threshold
	if abuse_confidence_score > 80 or malicious > 5:
		return 'HIGH'
	elif abuse_confidence_score > 50 or malicious > 2:
		return 'MEDIUM'
	else:
		return 'LOW'


def export(results):   #Exports results
	with open('results.csv', 'w', newline='') as file:
		writer = csv.writer(file)

		# Write header row
		writer.writerow(['IP', 'VT Malicious', 'VT Total', 'Abuse Score', 'Country', 'Owner', 'Risk Rating'])

		# Write each result as a row
		for row in results:
			writer.writerow(row)

results = [] #Empty results list

with open ('iocs.csv', 'r' , newline='') as file: #Opens and reads csv file with IOCs
	reader = csv.reader(file)
	next(reader) #Skips header row
	for row in reader:
		test_ip = row[0] #Extracts data from row as a string

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
			stats = data['data']['attributes']['last_analysis_stats'] #Accesses last_analysis_stats in json
			malicious = stats['malicious']
			suspicious = stats['suspicious']
			total = sum(stats.values()) #Adds up all the values in the last_analysis_stats dictionary (92)



			print(f'Malicious detections: {malicious}/{total}')
			print(f'Suspicious detections: {suspicious}/{total}')

			country = data['data']['attributes'].get('country', 'Unknown') #Error handing, prints country or unknown if not found
			print(country)

			as_owner = data['data']['attributes'].get('as_owner', 'Unknown') #Error handing, prints owner or unknown if not found
			print(as_owner)



		else:
			print(f'VT lookup failed for {test_ip}: {response.status_code}')


		#AbuseIPDB Response
		abuse_response = requests.get(url= abuse_url, headers=abuse_headers, params=params)
		if abuse_response.status_code == 200:
			abuse_data = abuse_response.json() 
			abuse_confidence_score = abuse_data['data']['abuseConfidenceScore'] #Access confidence score
			print('Abuse Confidence Score: ', abuse_confidence_score)

			total_reports = abuse_data['data']['totalReports'] #Access total reports
			print('Total Reports: ', total_reports)

			country_code = abuse_data['data']['countryCode'] #Access country code
			print('Country Code: ', country_code)

		else:
			print(f'AbuseOPDB lookup failed for {test_ip}: {abuse_response.status_code}')

		risk = risk_score(malicious, abuse_confidence_score)
		print(f'Risk Rating: {risk}')
		results.append([test_ip, malicious, total, abuse_confidence_score, country, as_owner, risk]) #Appends to results list
		time.sleep(15) #Query every 15 seconds








export (results)

