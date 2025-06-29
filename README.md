RedShadow V1 – Reconnaissance and Analysis Tool

**RedShadow V1** is a red team automation tool for passive reconnaissance, port scanning, and CVE analysis. It’s built for bug bounty hunters and internal security testers who need to quickly fingerprint domains, detect technologies, and identify known vulnerabilities.
⚠️ This version performs scanning and analysis only. No payloads, shells, or real exploitation are included in V1.

📦 Features
•	✅ Subdomain enumeration from `crt.sh`
•	✅ Passive recon (HTTP headers, titles, and tech stack)
•	✅ Port scanning via Nmap
•	✅ CVE detection from service + version matching
•	✅ Markdown report generation

🛠️ Requirements
Install system dependencies:
sudo apt update
sudo apt install nmap python3-venv -y
Create and activate a virtual environment:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
Or use the setup script:
chmod +x setup.sh
./setup.sh

🚀 Usage
1.	1. Subdomain Enumeration
python3 main.py domain --target tesla.com --output outputs/subdomains.txt
2.	2. Passive Recon
python3 main.py passive --input outputs/subdomains.txt --output outputs/passive_results.json
3.	3. Port Scan (Nmap)
python3 main.py scan --input outputs/subdomains.txt --output outputs/scan_results.json
4.	4. CVE Analysis
python3 main.py analyse --input outputs/scan_results.json --output outputs/analysis_results.json
5.	5. Markdown Report
python3 main.py report --input outputs/analysis_results.json --output outputs/redshadow_report.md

📁 Project Structure

RedShadow_V1/
├── .gitignore
├── LICENSE.txt
├── README.md
├── SECURITY.md
├── main.py
├── requirements.txt
├── setup.sh
├── modules/
│   ├── __init__.py
│   ├── analyse.py
│   ├── domain.py
│   ├── passive.py
│   ├── report.py
│   ├── scan.py
│  
├── outputs/
│   ├── subdomains.txt
│   ├── scan_results.json
│   ├── passive_results.json
│   ├── analysis_results.json
│   └── redshadow_report.md

🧠 Notes
•	All scanning is non-invasive (no exploit traffic)
•	Uses DNS over Google/Cloudflare for domain resolution
•	Works best with public-facing targets during bug bounty testing

📌 License
This project is released for educational and non-commercial use only.

You are not permitted to:

Use or modify the tool for commercial gain

Rebrand or redistribute it under another name

Resell any part of the code or project

Remove author attribution

All rights reserved © 2025 Galal Noaman.
For commercial or research use, contact: Jalalnoaman@gmail.com

The author accepts no liability for misuse.
