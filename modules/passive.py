# RedShadow/modules/passive.py

import httpx
import os
import json
from tqdm import tqdm

def passive_recon(input_file, output_file):
    if not os.path.exists(input_file):
        print(f"[!] Subdomain list not found: {input_file}")
        return

    print("[+] Starting passive reconnaissance...")
    with open(input_file, 'r') as f:
        subdomains = [line.strip() for line in f if line.strip()]

    results = []
    for subdomain in tqdm(subdomains, desc="Checking subdomains"):
        for scheme in ['http://', 'https://']:
            url = scheme + subdomain
            try:
                response = httpx.get(url, timeout=5, follow_redirects=True)

                tech_matches = []
                server_header = response.headers.get('server', '')
                powered_by = response.headers.get('x-powered-by', '')

                if server_header:
                    tech_matches.append({'tech': server_header, 'cves': []})
                if powered_by:
                    tech_matches.append({'tech': powered_by, 'cves': []})

                results.append({
                    'url': url,
                    'status': response.status_code,
                    'title': extract_title(response.text),
                    'tech_matches': tech_matches,
                    'headers': dict(response.headers)
                })
                break  # Stop after first success (http or https)
            except Exception:
                continue  # Try next protocol

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        with open(output_file, 'w', encoding='utf-8') as out:
            json.dump(results, out, indent=2)
        print(f"[✓] Passive reconnaissance complete. Results saved to {output_file}")
    except Exception as error:
        print(f"[!] Could not write output file: {error}")

def extract_title(html):
    start = html.find("<title>")
    end = html.find("</title>")
    if start != -1 and end != -1:
        return html[start + 7:end].strip()
    return "N/A"
