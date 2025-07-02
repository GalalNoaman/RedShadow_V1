# Developed by Galal Noaman – RedShadow_V1
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v1/main.py

import argparse
import re
import sys

def is_valid_domain(domain):
    return re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain)

def main():
    parser = argparse.ArgumentParser(
        description="RedShadow_V1 – Red Team Reconnaissance and Analysis Tool"
    )
    parser.add_argument('-v', '--version', action='version', version='RedShadow_V1.0')

    subparsers = parser.add_subparsers(dest='command', required=True)

    # ─────── SCAN ───────
    scan_parser = subparsers.add_parser('scan', help='Run port scan')
    scan_parser.add_argument('--input', required=True, help='Path to input targets file (.txt)')
    scan_parser.add_argument('--output', default='outputs/scan_results.json', help='Path to save scan results')

    # ─────── DOMAIN ENUM ───────
    domain_parser = subparsers.add_parser('domain', help='Enumerate subdomains')
    domain_parser.add_argument('--target', required=True, help='Domain to enumerate')
    domain_parser.add_argument('--output', default='outputs/subdomains.txt', help='Path to save subdomains')

    # ─────── PASSIVE RECON ───────
    passive_parser = subparsers.add_parser('passive', help='Perform passive recon')
    passive_parser.add_argument('--input', default='outputs/subdomains.txt', help='Input file with subdomains')
    passive_parser.add_argument('--output', default='outputs/passive_results.json', help='Path to save passive output')

    # ─────── ANALYSE ───────
    analyse_parser = subparsers.add_parser('analyse', help='Analyse recon output and match CVEs')
    analyse_parser.add_argument('--input', default='outputs/passive_results.json', help='Input JSON file')
    analyse_parser.add_argument('--output', default='outputs/analysis_results.json', help='Path to save analysis output')

    # ─────── REPORT ───────
    report_parser = subparsers.add_parser('report', help='Generate markdown report')
    report_parser.add_argument('--input', default='outputs/analysis_results.json', help='Input analysis JSON file')
    report_parser.add_argument('--output', default='outputs/redshadow_report.md', help='Path to save markdown report')

    args = parser.parse_args()

    try:
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
            passive.passive_recon(args.input, args.output)

        elif args.command == 'analyse':
            from modules import analyse
            analyse.analyse_scan_results(args.input, args.output)

        elif args.command == 'report':
            from modules import report
            report.generate_report(args.input, args.output)

    except Exception as e:
        print(f"[!] An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
