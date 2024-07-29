#!/usr/bin/python3
import requests
import json
import re
import time
from base64 import b64decode

# GitHub repository details
REPO_OWNER = "trickest"
REPO_NAME = "cve"
GITHUB_API_BASE = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}"

CVE_list = []
# We only want 2024 and 2023
years = ['2024', '2023']

def clean_text(description):
    description_lines = description.split('\n')
    description_lines = [line.lstrip('- ') for line in description_lines]
    description_lines = [re.sub(r'(https?:\/\/[^\s]+)', r'<a target="_blank" href="\1">\1</a>', line) for line in description_lines]
    description = '<br/>'.join(description_lines)
    return description

def extract_shield_data(content):
    shields = re.findall(r'!\[.*?\]\((.*?)\)', content)
    data = {}
    for shield in shields:
        parts = shield.split('&')
        for part in parts:
            if 'label=' in part and 'message=' in part:
                label = part.split('label=')[1].split('&')[0]
                message = part.split('message=')[1].split('&')[0]
                data[label] = message.replace('%20', ' ')
    return data

def print_progress(current, total, year):
    percent = (current / total) * 100
    bar_length = 50
    filled_length = int(bar_length * current // total)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    print(f'\rProcessing {year}: [{bar}] {percent:.1f}% ({current}/{total})', end='')

def get_file_content(path):
    url = f"{GITHUB_API_BASE}/contents/{path}"
    response = requests.get(url)
    if response.status_code == 200:
        content = response.json()['content']
        return b64decode(content).decode('utf-8')
    elif response.status_code == 403 and 'rate limit' in response.json().get('message', '').lower():
        reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
        sleep_time = max(reset_time - time.time(), 0) + 1
        print(f"Rate limit hit. Waiting for {sleep_time:.0f} seconds...")
        time.sleep(sleep_time)
        return get_file_content(path)  # Retry after waiting
    else:
        print(f"Failed to fetch file: {path}")
        return None

def get_directory_contents(path):
    url = f"{GITHUB_API_BASE}/contents/{path}"
    response = requests.get(url)
    if response.status_code == 200:
        return [item['name'] for item in response.json() if item['type'] == 'file' and item['name'].endswith('.md')]
    else:
        print(f"Failed to fetch directory contents: {path}")
        return []

print("Starting CVE processing...")
start_time = time.time()

for year in years:
    yearDir = year
    cve_files = get_directory_contents(yearDir)
    if not cve_files:
        print(f"\nNo CVE files found for year {year}. Skipping.")
        continue
    
    total_files = len(cve_files)
    print(f"\nFound {total_files} CVE files for {year}")

    for i, CVE_filename in enumerate(cve_files, 1):
        CVE_file_content = get_file_content(f"{yearDir}/{CVE_filename}")
        if CVE_file_content is None:
            continue

        CVE_description = CVE_file_content.split('### Description')[1].split('###')[0].strip()
        CVE_references = CVE_file_content.split('### Reference')[1].split('###')[0].strip()
        CVE_github = CVE_file_content.split('### Github')[1].split('###')[0].strip()
        shield_data = extract_shield_data(CVE_file_content)
        CVE_Name = CVE_filename.split('.')[0]

        thisCVE = {
            "year": year,
            "CVE_Name": CVE_Name,
            "CVE_description": clean_text(CVE_description),
            "CVE_github": clean_text(CVE_github),
            "CVE_references": clean_text(CVE_references),
            "Product": shield_data.get('Product', ''),
            "Version": shield_data.get('Version', ''),
            "Vulnerability": shield_data.get('Vulnerability', '')
        }
        CVE_list.append(thisCVE)
        print_progress(i, total_files, year)

print("\n\nSaving CVE list to JSON file...")
with open('CVE_list.json', 'w') as outfile:
    json.dump(CVE_list, outfile, indent=2)

end_time = time.time()
processing_time = end_time - start_time
print(f"\nProcessing complete!")
print(f"Processed {len(CVE_list)} CVEs from years 2024 and 2023.")
print(f"Total processing time: {processing_time:.2f} seconds")