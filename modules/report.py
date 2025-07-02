# Developed by Galal Noaman – RedShadow_V1
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v1/modules/report.py

import json
import os

def generate_report(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as error:
        print(f"[!] Failed to read input file: {error}")
        return

    if not isinstance(data, list):
        print("[!] Invalid input format – expected a list of analysis results.")
        return

    report_lines = [
        "# 🛡️ RedShadow Reconnaissance Report",
        "",
        f"**Input File:** `{input_file}`",
        f"**Report Generated:** `{output_file}`",
        ""
    ]

    for entry in data:
        url = entry.get("url", "N/A")
        ip = entry.get("ip", "N/A")
        hostname = entry.get("hostname", "N/A")
        tech_matches = entry.get("tech_matches", [])

        report_lines.append(f"---\n## 🔗 {url}")
        report_lines.append(f"- **IP Address:** `{ip}`")
        report_lines.append(f"- **Hostname:** `{hostname}`")

        if tech_matches:
            report_lines.append("- **Detected Technologies & CVEs:**")
            for match in tech_matches:
                tech = match.get("tech", "Unknown")
                port = match.get("port", "N/A")
                cves = match.get("cves", [])
                report_lines.append(f"  - `{tech}` on port `{port}`")
                if cves:
                    for cve in cves:
                        cve_id = cve.get("cve", "Unknown")
                        cvss = cve.get("cvss", "N/A")
                        url = cve.get("url", "")
                        report_lines.append(f"    - [CVE: {cve_id}]({url}) (CVSS: {cvss})")
                else:
                    report_lines.append("    - No CVEs found.")
        else:
            report_lines.append("- No known vulnerable technologies detected.")

        report_lines.append("")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(report_lines))
        print(f"[✓] Report created for {len(data)} target(s): {output_file}")
    except Exception as error:
        print(f"[!] Could not write to output file: {error}")
