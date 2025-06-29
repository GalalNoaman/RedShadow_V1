# RedShadow/modules/report.py

import json
import os

def generate_report(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as error:
        print(f"[!] Failed to read input file: {error}")
        return

    report_lines = [
        "# 🛡️ RedShadow Reconnaissance Report",
        "",
        f"**Input file:** `{input_file}`",
        f"**Generated report:** `{output_file}`",
        ""
    ]

    if not isinstance(data, list):
        print("[!] Invalid format: expected a list of passive recon entries")
        return

    for entry in data:
        url = entry.get("url", "N/A")
        title = entry.get("title", "N/A")
        tech_matches = entry.get("tech_matches", [])

        report_lines.append(f"---\n## 🔗 {url}")
        report_lines.append(f"**Page Title:** `{title}`")

        if tech_matches:
            for item in tech_matches:
                tech = item.get("tech", "Unknown")
                cves = item.get("cves", [])
                report_lines.append(f"- **Technology Detected:** `{tech}`")
                if cves:
                    for cve in cves:
                        report_lines.append(f"  - [CVE: {cve}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve})")
                else:
                    report_lines.append("  - No associated CVEs")
        else:
            report_lines.append("- No known technologies matched.")

        report_lines.append("")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(report_lines))
        print(f"[✓] Report created: {output_file}")
    except Exception as error:
        print(f"[!] Could not write to output file: {error}")
