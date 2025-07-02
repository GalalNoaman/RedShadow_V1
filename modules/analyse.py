# Developed by Galal Noaman – RedShadow_V1
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v1/modules/analyse.py

import json
import os
from termcolor import cprint

# Fingerprint to CVE map (expand as needed)
CVE_MAP = {
    'Apache': ['CVE-2021-41773', 'CVE-2021-42013'],
    'nginx': ['CVE-2019-20372'],
    'PHP': ['CVE-2019-11043'],
    'Express': ['CVE-2020-7699'],
    'WordPress': ['CVE-2022-21664'],
    'IIS': ['CVE-2017-7269'],
    'tcpwrapped': ['CVE-2022-1990'],
    'Varnish': ['CVE-2022-38150'],
}

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

    analysed = []

    for domain, info in data.items():
        matches = []

        for proto, ports in info.get("protocols", {}).items():
            for port, port_data in ports.items():
                service = port_data.get("service", "")
                product = port_data.get("product", "")
                version = port_data.get("version", "")

                name_to_check = f"{product} {version}".strip()

                for fingerprint, cves in CVE_MAP.items():
                    if fingerprint.lower() in name_to_check.lower() or fingerprint.lower() in product.lower():
                        matches.append({
                            "tech": fingerprint,
                            "port": port,
                            "service": service,
                            "product": product,
                            "version": version,
                            "cves": cves
                        })

        if matches:
            analysed.append({
                "url": domain,
                "ip": info.get("ip", "N/A"),
                "hostname": info.get("hostname", "N/A"),
                "tech_matches": matches
            })

    if not analysed:
        print("[!] No vulnerable technologies detected.")
    else:
        print(f"\n[✓] Found {len(analysed)} potentially vulnerable targets:\n")
        for item in analysed:
            cprint(f"[→] {item['url']} ({item['ip']})", "cyan")
            for tech in item['tech_matches']:
                cprint(
                    f"    - {tech['tech']} on port {tech['port']} "
                    f"({tech['service']} {tech['product']} {tech['version']}) → "
                    f"CVEs: {', '.join(tech['cves'])}",
                    "yellow"
                )

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        with open(output_file, 'w', encoding='utf-8') as out:
            json.dump(analysed, out, indent=2)
        print(f"[✓] Analysis saved to {output_file}")
    except Exception as error:
        print(f"[!] Failed to write analysis output: {error}")
