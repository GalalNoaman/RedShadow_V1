# Developed by Galal Noaman – RedShadow_V1
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v1/main.py

import argparse
import re
import sys
import os
from termcolor import cprint

def is_valid_domain(domain):
    return re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain) is not None

def is_safe_path(path):
    return not (".." in path or path.startswith("/") or path.startswith("\\"))

def main():
    parser = argparse.ArgumentParser(
        description="🛡️ RedShadow_V1 – Red Team Reconnaissance and CVE Analysis Tool"
    )
    parser.add_argument('-v', '--version', action='version', version='RedShadow_V1.0')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')

    subparsers = parser.add_subparsers(dest='command', required=True)

    # ─────── scan ───────
    scan_parser = subparsers.add_parser('scan', help='Run Nmap port scan on targets')
    scan_parser.add_argument('--input', required=True, help='Input file with domains')
    scan_parser.add_argument('--output', default='outputs/scan_results.json', help='Output path for scan results')

    # ─────── domain ───────
    domain_parser = subparsers.add_parser('domain', help='Enumerate subdomains using crt.sh and backup APIs')
    domain_parser.add_argument('--target', required=True, help='Target root domain')
    domain_parser.add_argument('--output', default='outputs/subdomains.txt', help='Output path for subdomains list')

    # ─────── passive ───────
    passive_parser = subparsers.add_parser('passive', help='Perform passive recon (headers, HTML, SSL)')
    passive_parser.add_argument('--input', default='outputs/subdomains.txt', help='Input subdomains file')
    passive_parser.add_argument('--output', default='outputs/passive_results.json', help='Output path for passive recon')
    passive_parser.add_argument('--insecure', action='store_true', help='Disable TLS verification')
    passive_parser.add_argument('--verbose', action='store_true', help='Show verbose error details')

    # ─────── analyse ───────
    analyse_parser = subparsers.add_parser('analyse', help='Analyse scan results and match known CVEs')
    analyse_parser.add_argument('--input', default='outputs/scan_results.json', help='Input file for analysis')
    analyse_parser.add_argument('--output', default='outputs/analysis_results.json', help='Output path for analysis')

    # ─────── report ───────
    report_parser = subparsers.add_parser('report', help='Generate Markdown report from analysis results')
    report_parser.add_argument('--input', default='outputs/analysis_results.json', help='Input analysis file')
    report_parser.add_argument('--output', default='outputs/redshadow_report.md', help='Output report path')

    args = parser.parse_args()

    try:
        if hasattr(args, 'output') and not is_safe_path(args.output):
            raise ValueError(f"[!] Unsafe output path detected: {args.output}")

        if args.command == 'scan':
            from modules import scan
            scan.run_scan(args.input, args.output)

        elif args.command == 'domain':
            if not is_valid_domain(args.target):
                raise ValueError(f"[!] Invalid domain format: {args.target}")
            from modules import domain
            domain.enumerate_subdomains(args.target, args.output)

        elif args.command == 'passive':
            from modules import passive
            passive.passive_recon(
                input_file=args.input,
                output_file=args.output,
                insecure=args.insecure,
                verbose=args.verbose
            )

        elif args.command == 'analyse':
            from modules import analyse
            analyse.analyse_scan_results(args.input, args.output)

        elif args.command == 'report':
            from modules import report
            report.generate_report(args.input, args.output)

    except Exception as e:
        cprint(f"[!] An error occurred: {e}", "red")
        sys.exit(1)

if __name__ == "__main__":
    main()


