# Developed by Galal Noaman – RedShadow_V1
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v1/modules/analyse.py

import json
import os
import re
from termcolor import cprint
from modules.utils import load_config

# Load config
config = load_config()
cve_path = config.get("analyse", {}).get("cve_source", "data/cve_map.json")

def load_cve_map(path=cve_path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Failed to load CVE map: {e}")
        return {}

def analyse_scan_results(input_file, output_file="outputs/analysis_results.json"):
    if not os.path.exists(input_file):
        print(f"[!] Input file not found: {input_file}")
        return

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as error:
        print(f"[!] Failed to parse input JSON: {error}")
        return
    except Exception as error:
        print(f"[!] Error reading input file: {error}")
        return

    cve_map = load_cve_map()
    analysed = []

    for domain, info in data.items():
        tech_matches = []

        for proto, ports in info.get("protocols", {}).items():
            for port, port_data in ports.items():
                service = port_data.get("service", "")
                product = port_data.get("product", "")
                name = f"{product} {service}".strip().lower()

                for tech_fp, cves in cve_map.items():
                    if tech_fp.lower() in name:
                        tech_matches.append({
                            'tech': tech_fp,
                            'port': port,
                            'cves': cves
                        })

        if tech_matches:
            analysed.append({
                'url': domain,
                'ip': info.get("ip", "N/A"),
                'hostname': info.get("hostname", "N/A"),
                'tech_matches': tech_matches
            })

    if not analysed:
        print("[!] No vulnerable technologies detected.")
    else:
        print(f"\n[✓] Found {len(analysed)} potentially vulnerable targets:\n")
        for entry in analysed:
            cprint(f"[→] {entry['url']} ({entry['ip']})", "cyan")
            for match in entry['tech_matches']:
                for cve in match['cves']:
                    cve_id = cve.get("cve", "N/A")
                    cvss = cve.get("cvss", "?")
                    url = cve.get("url", "")
                    cprint(f"    - {match['tech']} on port {match['port']} → CVE: {cve_id} (CVSS: {cvss})", "yellow")
                    if url:
                        print(f"      {url}")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        with open(output_file, 'w', encoding='utf-8') as out:
            json.dump(analysed, out, indent=2)
        print(f"[✓] Analysis saved to {output_file}")
    except Exception as error:
        print(f"[!] Failed to write analysis output: {error}")
