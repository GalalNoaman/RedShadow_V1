# Developed by Galal Noaman – RedShadow_V1
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v1/modules/domain.py

import requests
import time
import os
import re
import yaml

class SubdomainEnumerationError(Exception):
    pass

def load_config():
    default_config = {
        "timeout": 20,
        "retries": 2,
        "delay": 0,
        "headers": {
            "User-Agent": "RedShadowBot/1.0"
        }
    }
    config_path = "config.yaml"
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as file:
                user_config = yaml.safe_load(file)
                default_config.update(user_config.get("domain", {}))
        except Exception as e:
            print(f"[!] Failed to load config.yaml: {e}")
    return default_config

def validate_domain(domain):
    return re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain) is not None

def enumerate_subdomains(domain, output_file):
    config = load_config()

    if not validate_domain(domain):
        raise ValueError(f"[!] Invalid domain format: {domain}")

    print(f"[+] Enumerating subdomains for: {domain}")
    crtsh_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()

    headers = config.get("headers", {})
    timeout = config.get("timeout", 20)
    retries = config.get("retries", 2)
    delay = config.get("delay", 0)

    # ────────── Try crt.sh ──────────
    for attempt in range(retries):
        try:
            response = requests.get(crtsh_url, timeout=timeout, headers=headers)
            response.raise_for_status()
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value', '')
                for sub in name_value.splitlines():
                    if domain in sub:
                        subdomains.add(sub.strip())
            break
        except (requests.RequestException, ValueError) as error:
            print(f"[!] crt.sh attempt {attempt + 1} failed: {error}")
            time.sleep(delay)
    else:
        print("[!] crt.sh failed. Trying backup API...")

        # ────────── Fallback: dns.bufferover.run ──────────
        try:
            alt_url = f"https://dns.bufferover.run/dns?q=.{domain}"
            alt_response = requests.get(alt_url, timeout=10, headers=headers)
            alt_response.raise_for_status()
            alt_data = alt_response.json()
            if 'FDNS_A' in alt_data:
                for entry in alt_data['FDNS_A']:
                    parts = entry.split(',')
                    if len(parts) == 2 and domain in parts[1]:
                        subdomains.add(parts[1].strip())
        except Exception as backup_error:
            print(f"[!] Backup API also failed: {backup_error}")
            raise SubdomainEnumerationError("All subdomain enumeration methods failed.")

    # ────────── Save Results ──────────
    if subdomains:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            for sub in sorted(subdomains):
                f.write(sub + '\n')
        print(f"[✓] Found {len(subdomains)} subdomains. Saved to {output_file}")
    else:
        print("[!] No subdomains found.")
