# Developed by Galal Noaman – RedShadow_V1
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v1/modules/analyse.py

import json
import os
import re
from termcolor import cprint

# Load external CVE map from JSON file
def load_cve_map(path="data/cve_map.json"):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load CVE map: {e}")
        return {}

def analyse_scan_results(input_file, output_file="outputs/analysis_results.json"):
    if not os.path.exists(input_file):
        print(f"[!] Input file not found: {input_file}")
        return

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as error:
        print(f"[!] Failed to read or parse input file: {error}")
        return

    cve_map = load_cve_map()
    analysed = []

    for domain, info in data.items():
        matched_tech = []

        for proto, ports in info.get("protocols", {}).items():
            for port, port_data in ports.items():
                service = port_data.get("service", "")
                product = port_data.get("product", "")
                name_to_check = f"{product} {service}".strip().lower()

                for fingerprint, cve_entries in cve_map.items():
                    if fingerprint.lower() in name_to_check:
                        matched_tech.append({
                            'tech': fingerprint,
                            'port': port,
                            'cves': cve_entries
                        })

        if matched_tech:
            analysed.append({
                'url': domain,
                'ip': info.get("ip", "N/A"),
                'hostname': info.get("hostname", "N/A"),
                'tech_matches': matched_tech
            })

    if not analysed:
        print("[!] No vulnerable technologies detected.")
    else:
        print(f"\n[✓] Found {len(analysed)} potentially vulnerable targets:\n")
        for item in analysed:
            cprint(f"[→] {item['url']} ({item['ip']})", "cyan")
            for tech in item['tech_matches']:
                for cve_entry in tech['cves']:
                    cve = cve_entry.get("cve", "N/A")
                    cvss = cve_entry.get("cvss", "?")
                    url = cve_entry.get("url", "")
                    cprint(f"    - {tech['tech']} on port {tech['port']} → CVE: {cve} (CVSS: {cvss})", "yellow")
                    if url:
                        print(f"      {url}")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        with open(output_file, 'w', encoding='utf-8') as out:
            json.dump(analysed, out, indent=2)
        print(f"[✓] Analysis saved to {output_file}")
    except Exception as error:
        print(f"[!] Failed to write analysis output: {error}")
