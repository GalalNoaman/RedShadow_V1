# Developed by Galal Noaman – RedShadow_V1
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.


# RedShadow_v1/modules/domain.py

import requests
import time
import os

def enumerate_subdomains(domain, output_file):
    print(f"[+] Enumerating subdomains for: {domain}")
    crtsh_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()

    # ────────── Try crt.sh first ──────────
    try:
        for attempt in range(2):
            try:
                response = requests.get(crtsh_url, timeout=20)
                response.raise_for_status()
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for sub in name_value.splitlines():
                        if domain in sub:
                            subdomains.add(sub.strip())
                break
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as error:
                print(f"[!] crt.sh attempt {attempt + 1} failed: {error}")
                if attempt == 1:
                    raise
                time.sleep(3)

    except Exception as crtsh_error:
        print(f"[!] crt.sh failed. Attempting backup API...")

        # ────────── Fallback: dns.bufferover.run ──────────
        try:
            alt_url = f"https://dns.bufferover.run/dns?q=.{domain}"
            alt_response = requests.get(alt_url, timeout=10)
            alt_response.raise_for_status()

            alt_data = alt_response.json()
            if 'FDNS_A' in alt_data:
                for entry in alt_data['FDNS_A']:
                    parts = entry.split(',')
                    if len(parts) == 2 and domain in parts[1]:
                        subdomains.add(parts[1].strip())

        except Exception as backup_error:
            print(f"[!] Backup API also failed: {backup_error}")

    # ────────── Save Results ──────────
    if subdomains:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            for sub in sorted(subdomains):
                f.write(sub + '\n')
        print(f"[✓] Found {len(subdomains)} subdomains. Saved to {output_file}")
    else:
        print("[!] No subdomains found.")
