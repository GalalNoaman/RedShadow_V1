# Developed by Galal Noaman – RedShadow_V1
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.


# RedShadow_v1/main.py

import argparse

def main():
    parser = argparse.ArgumentParser(
        description='RedShadow V1 – Red Team Reconnaissance and Analysis Tool'
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # SCAN
    scan_parser = subparsers.add_parser('scan', help='Run port scan')
    scan_parser.add_argument('--input', required=True)
    scan_parser.add_argument('--output', default='outputs/scan_results.json')

    # DOMAIN ENUM
    domain_parser = subparsers.add_parser('domain', help='Enumerate subdomains')
    domain_parser.add_argument('--target', required=True)
    domain_parser.add_argument('--output', default='outputs/subdomains.txt')

    # PASSIVE
    passive_parser = subparsers.add_parser('passive', help='Passive recon')
    passive_parser.add_argument('--input', default='outputs/subdomains.txt')
    passive_parser.add_argument('--output', default='outputs/passive_results.json')

    # ANALYSE – now supports --output
    analyse_parser = subparsers.add_parser('analyse', help='Analyse results')
    analyse_parser.add_argument('--input', default='outputs/passive_results.json')
    analyse_parser.add_argument('--output', default='outputs/analysis_results.json')

    # REPORT
    report_parser = subparsers.add_parser('report', help='Generate markdown report')
    report_parser.add_argument('--input', default='outputs/analysis_results.json')
    report_parser.add_argument('--output', default='outputs/redshadow_report.md')

    args = parser.parse_args()

    if args.command == 'scan':
        from modules import scan
        scan.run_scan(args.input, args.output)

    elif args.command == 'domain':
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

if __name__ == "__main__":
    main()
