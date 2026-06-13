from dotenv import load_dotenv
import os
import requests
import time
import csv
from datetime import datetime
import re
import argparse
import json

load_dotenv()
vt_key = os.getenv('VT_API_KEY') #Load VirusTotal API Key
abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY') #Load Abuseipdb key

parser = argparse.ArgumentParser()
parser.add_argument('--input', default="iocs.csv", help="Input csv file")
parser.add_argument('--output', default="results.csv", help="Output csv file")
args = parser.parse_args()

results = [] #Empty list to store results

fieldnames = ['ioc', 'type', 'malicious', 'suspicious', 'total',
              'abuse_score', 'country', 'owner', 'registrar',
              'creation_date', 'last_dns_record', 'meaningful_name',
              'type description', 'size', 'risk']

def defang_cleaner(test_domain):
	test_domain = re.sub(r'\[.\]', '.', test_domain)
	test_domain = test_domain.replace('..', '.')  # Fix double dots
	return test_domain

def risk_score(malicious, abuse_confidence_score):
	if abuse_confidence_score > 80 or malicious > 5:
		return 'HIGH'
	elif abuse_confidence_score > 50 or malicious > 2:
		return 'MEDIUM'
	else:
		return 'LOW'


def export(results):
	with open(args.output, 'w', newline='') as file: #Create csv 'results.csv'
		writer = csv.DictWriter(file, fieldnames=fieldnames, restval='N/A') #Write to file

		# Write header row
		writer.writeheader()

		# Write each result as a row
		for row in results:
			writer.writerow(row)

def ip_api_call (test_ip):
	# VirusTotal API call
		url = f'https://www.virustotal.com/api/v3/ip_addresses/{test_ip}' #Lookup test IP
		headers = {'x-apikey': vt_key}

	#VT Response
		response = requests.get(url, headers=headers) #Get VT response
		print(f'\nIOC:  {test_ip}\n')
		if response.status_code == 200: #If request successful parse response as json
			data = response.json() #Store json
			stats = data['data']['attributes']['last_analysis_stats'] #Get stats
			malicious = stats['malicious'] #Get malicious stats
			suspicious = stats['suspicious'] #Get suspicious stats
			total = sum(stats.values()) #Add total of malicious and suspicious stats



			print(f'Malicious detections: {malicious}/{total}') #Print malicious stats out of total
			print(f'Suspicious detections: {suspicious}/{total}') #Print suspicious stats out of total

			country = data['data']['attributes'].get('country', 'Unknown') #Error Handling, prints country or unknown if not found
			print(country)

			as_owner = data['data']['attributes'].get('as_owner', 'Unknown') #Error handling, prints owner or unknown if not found
			print(as_owner)



		else:
			print(f'VT lookup failed for {test_ip}: {response.status_code}') #Error handling output for lookup failure

	#AbuseIPDB API call
		abuse_url = f'https://api.abuseipdb.com/api/v2/check'
		abuse_headers  = {'Key': abuseipdb_key, 'Accept': 'application/json'}

		params = {'ipAddress': test_ip, 'maxAgeInDays': 90} #lookup test ip

		#AbuseIPDB Response
		abuse_response = requests.get(url= abuse_url, headers=abuse_headers, params=params) #Get AbuseIBDP response
		if abuse_response.status_code == 200: #If request successful parse response as json
			abuse_data = abuse_response.json() #Store json
			abuse_confidence_score = abuse_data['data']['abuseConfidenceScore'] #Get confidence score
			print('Abuse Confidence Score: ', abuse_confidence_score)

			total_reports = abuse_data['data']['totalReports'] #Get total reports
			print('Total Reports: ', total_reports)

			country_code = abuse_data['data']['countryCode'] #Get country code
			print('Country Code: ', country_code)



		else:
			print(f'AbuseOPDB lookup failed for {test_ip}: {abuse_response.status_code}') #Error handling, print status code if get request failed


		risk = risk_score(malicious, abuse_confidence_score)  # Pass data to risk score function
		print(f'Risk Rating: {risk}')  # Print risk score

		results.append({ #Append to results list
						'ioc': test_ip,
						'type': 'IP',
						'malicious': malicious,
						'total': total_reports,
						'abuse_score': abuse_confidence_score,
						'country': country,
						'owner': as_owner,
						'risk': risk
					})






def hash_api_call (test_hash):
	# VirusTotal API call
		hash_url = f'https://www.virustotal.com/api/v3/files/{test_hash}'
		headers = {'x-apikey': vt_key}
		response = requests.get(hash_url, headers=headers)  # Get VT response
		print(f'\nIOC:  {test_hash} \n')
		if response.status_code == 200:
			data = response.json()
			hash_stats = data['data']['attributes']['last_analysis_stats']
			malicious = hash_stats['malicious']
			suspicious = hash_stats['suspicious']
			total = sum(hash_stats.values())
			print(f'Malicious detections: {malicious}/{total}')
			print(f'Suspicious detections: {suspicious}/{total}')

			meaningful_name = data['data'] ['attributes'].get('meaningful_name', 'Unknown')
			print(f'Meaningful name: {meaningful_name}')

			type_description = data['data']['attributes'].get('file_type', 'Unknown')
			print(f'Type: {type_description}')

			size = data['data']['attributes']['size']
			print(f'Size: {size}')

			risk = risk_score(malicious, 0)  # No AbuseIPDB so we pass 0
			print(f'Risk: {risk}')

			results.append({ 'ioc': test_hash,
							 'type': 'Hash',
							 'malicious': malicious,
							 'meaningful_name': meaningful_name,
							 'size': size,
						   'risk': risk})
		else:
			print(f'Hash lookup failed for {test_hash}: {response.status_code}')





		
def domain_api_call (test_domain):
		# VirusTotal API call
			domain_url = f'https://www.virustotal.com/api/v3/domains/{test_domain}'
			headers = {'x-apikey': vt_key}


			response = requests.get(domain_url, headers=headers)  # Get VT response
			print(f'\n IOC:  {test_domain} \n')
			if response.status_code == 200:  # If request successful parse response as json
				data = response.json()  # Store json
				domain_stats = data['data']['attributes']['last_analysis_stats']
				malicious = domain_stats['malicious']
				suspicious = domain_stats['suspicious']
				total = sum(domain_stats.values())
				print(f'Malicious detections: {malicious}/{total}')
				print(f'Suspicious detections: {suspicious}/{total}')

				registrar = data['data']['attributes'].get ('registrar', 'Unknown')
				print(f'Registrar: {registrar}')

				creation_date = data['data']['attributes'].get('creation_date')
				if creation_date:
					readable_creation_date = datetime.fromtimestamp(int(creation_date)).strftime('%Y-%m-%d')
				else:
					readable_creation_date = 'Unknown'
				print(f'Creation Date: {readable_creation_date}')

				last_dns_record = data['data']['attributes'].get('last_update_date')
				if last_dns_record:
					readable_date = datetime.fromtimestamp(int(last_dns_record)).strftime('%Y-%m-%d')
				else:
					readable_date = 'Unknown'
				print(f'Last Modification Date: {readable_date}')

				risk = risk_score(malicious,0) #No AbuseIPDB so we pass 0
				print(f'Risk: {risk}')

				results.append({ 'ioc': test_domain,
								 'type': 'Domain',
								 'malicious': malicious,
								 'registrar': registrar,
								 'creation_date': readable_date,
								'last_dns_record': last_dns_record,
							   	'risk': risk })
			else:
				print(f'Domain lookup failed for {test_domain}: {response.status_code}')



with open(args.input, 'r', newline='') as file:  # Open IOCs csv to read from
		reader = csv.reader(file)
		next(reader)  # Skip header row
		for ip, hashes, domain in reader:
			test_ip = ip

			test_hash = hashes
			test_domain = domain
			test_domain = defang_cleaner(test_domain)

			ip_api_call (test_ip)
			hash_api_call (test_hash)
			domain_api_call (test_domain)

			time.sleep(15)  # Lookup  15 seconds apart








export (results) #Pass results to export function

