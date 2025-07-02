# 🕵️‍♂️ RedShadow V1 – Reconnaissance and CVE Analysis Tool

**RedShadow V1** is a red team automation tool for passive reconnaissance, port scanning, and CVE analysis. Built for bug bounty hunters and internal testers, it fingerprints domains, detects technologies, and maps them to known vulnerabilities.

> ⚠️ V1 focuses on scanning and analysis only. No exploitation or payloads are included.

---

## 📦 Features

- ✅ Subdomain enumeration via `crt.sh`
- ✅ Passive HTTP recon (headers, title, tech stack)
- ✅ Nmap-based port scanning
- ✅ CVE detection via service/version matching
- ✅ Markdown report generation

---

## 🛠️ Requirements

Install system dependencies:
```bash
sudo apt update
sudo apt install nmap python3-venv -y

```

## Create and activate a virtual environment:

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

## Or use the setup script:

chmod +x setup.sh
./setup.sh

## 🚀 Usage
1- Subdomain Enumeration:
python3 main.py domain --target tesla.com --output outputs/subdomains.txt

2- Passive Recon:
python3 main.py passive --input outputs/subdomains.txt --output outputs/passive_results.json

3- Port Scan:
python3 main.py scan --input outputs/subdomains.txt --output outputs/scan_results.json

4- CVE Analysis:
python3 main.py analyse --input outputs/scan_results.json --output outputs/analysis_results.json

5- Markdown Report:
python3 main.py report --input outputs/analysis_results.json --output outputs/redshadow_report.md

## 📁 Project Structure
RedShadow_V1/
├── .git/                        
├── .gitignore                  
├── LICENSE.txt                 
├── README.md                   
├── SECURITY.md                 
├── config.yaml                
├── main.py                     
├── requirements.txt            
├── setup.sh                    
├── data/
│   └── cve_map.json            
├── modules/
│   ├── __init__.py             
│   ├── analyse.py              
│   ├── domain.py               
│   ├── passive.py              
│   ├── report.py               
│   ├── scan.py                 
│   └── utils.py                
├── outputs/
│   ├── subdomains.txt          
│   ├── passive_results.json    
│   ├── scan_results.json       
│   ├── analysis_results.json   
│   └── redshadow_report.md     
├── venv/                       



## 🧠 Notes
Passive-only: no exploitation or shell generation

Uses DNS resolution via Google/Cloudflare

Designed for public bug bounty targets

## 📌 License
This project is for educational and non-commercial use only.

You are not allowed to:

Use or modify the code for commercial gain

Rebrand, resell, or redistribute any part of this project

Remove author credit

All rights reserved © 2025 Galal Noaman
Contact: Jalalnoaman@gmail.com for research or licensing requests.