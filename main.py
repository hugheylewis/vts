import csv
import requests
import re
import time

with open('query_data.csv') as qdata:
    data = csv.reader(qdata, delimiter=',')
    next(data, None)  # skips the header
    for row in data:
        url = f"https://www.virustotal.com/api/v3/domains/{row[0]}"

        headers = {
            "accept": "application/json",
            "x-apikey": "API_KEY_HERE"
        }

        response = requests.get(url, headers=headers)
        pattern = r'"malicious"\s*:\s*(\d+)'
        response_data = response.text
        match = re.search(pattern, response_data)

        if match:
            print(f"VirusTotal score for {row[0]}: {match.group(1)}")
        time.sleep(15)


