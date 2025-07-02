# Developed by Galal Noaman – RedShadow_V1
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v1/modules/passive.py

import httpx
import os
import json
import time
from tqdm import tqdm
from modules.utils import load_config

class PassiveReconError(Exception):
    pass

def extract_title(html):
    start = html.lower().find("<title>")
    end = html.lower().find("</title>")
    if start != -1 and end != -1 and end > start:
        return html[start + 7:end].strip()
    return "N/A"

def passive_recon(input_file, output_file, insecure=False):
    if not os.path.exists(input_file):
        print(f"[!] Subdomain list not found: {input_file}")
        return

    config = load_config()
    passive_cfg = config.get("passive", {})
    delay = passive_cfg.get("delay", 1)
    verify_ssl = not insecure and passive_cfg.get("verify_ssl", True)

    print("[+] Starting passive reconnaissance...")
    with open(input_file, 'r', encoding='utf-8') as f:
        subdomains = [line.strip() for line in f if line.strip()]

    results = []
    for subdomain in tqdm(subdomains, desc="Checking subdomains"):
        for scheme in ['http://', 'https://']:
            url = scheme + subdomain
            try:
                response = httpx.get(
                    url,
                    timeout=10,
                    follow_redirects=True,
                    verify=verify_ssl
                )

                server = response.headers.get('server', '').strip()
                powered_by = response.headers.get('x-powered-by', '').strip()
                tech_matches = []

                if server:
                    tech_matches.append({'tech': server, 'cves': []})
                if powered_by:
                    tech_matches.append({'tech': powered_by, 'cves': []})

                results.append({
                    'url': url,
                    'ip': response.extensions.get("httpx.original_ip", "N/A"),
                    'hostname': subdomain,
                    'status': response.status_code,
                    'title': extract_title(response.text),
                    'tech_matches': tech_matches,
                    'headers': dict(response.headers)
                })

                time.sleep(delay)
                break  # Exit loop after first successful scheme (http/https)

            except httpx.ConnectTimeout:
                print(f"[!] Timeout for {url}")
            except httpx.RequestError as e:
                print(f"[!] Connection error for {url}: {e}")
            except Exception as e:
                print(f"[!] Error processing {url}: {e}")

    if not results:
        print("[!] No reachable subdomains found.")
        return

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        with open(output_file, 'w', encoding='utf-8') as out:
            json.dump(results, out, indent=2)
        print(f"[✓] Passive reconnaissance complete. {len(results)} results saved to {output_file}")
    except Exception as error:
        raise PassiveReconError(f"[!] Could not write output file: {error}")
