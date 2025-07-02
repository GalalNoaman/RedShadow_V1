# Developed by Galal Noaman – RedShadow_V1
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v1/modules/scan.py

import nmap
import json
import os
import sys
import socket
import dns.resolver
import re
from multiprocessing.dummy import Pool as ThreadPool
from modules.utils import load_config

# Custom exceptions
class ScanError(Exception): pass
class DNSResolutionError(Exception): pass

# Load config
try:
    config = load_config()
    scan_cfg = config.get("scan", {})
    default_ports = scan_cfg.get("nmap_ports", "21,22,80,443,8080")
    max_threads = int(scan_cfg.get("max_threads", 10))
    dns_servers = scan_cfg.get("dns_servers", ["8.8.8.8", "1.1.1.1"])
except Exception as err:
    print(f"[!] Failed to load config: {err}")
    sys.exit(1)

# DNS setup
resolver = dns.resolver.Resolver()
resolver.nameservers = dns_servers
resolver.timeout = 3
resolver.lifetime = 5

def resolve_domain(domain):
    try:
        answer = resolver.resolve(domain, 'A')
        return domain, answer[0].to_text()
    except Exception:
        return domain, None

def scan_target(args):
    domain, ip = args
    scanner = nmap.PortScanner()
    try:
        scanner.scan(
            hosts=ip,
            arguments=f'-sS -sV -T4 -Pn -n -p {default_ports}'
        )
    except Exception as error:
        return {domain: {'ip': ip, 'error': f'Scan failed: {error}'}}

    for host in scanner.all_hosts():
        protocols = {}
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto]
            protocols[proto] = {}
            for port in ports:
                port_data = ports[port]
                protocols[proto][port] = {
                    'state': port_data.get('state'),
                    'service': port_data.get('name'),
                    'product': port_data.get('product'),
                    'version': port_data.get('version'),
                    'extrainfo': port_data.get('extrainfo'),
                }

        return {
            domain: {
                'ip': ip,
                'hostname': scanner[host].hostname() or domain,
                'state': scanner[host].state(),
                'protocols': protocols
            }
        }

    return {domain: {'ip': ip, 'note': 'No open ports found'}}

def is_valid_domain(domain):
    return re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain)

def run_scan(input_file, output_file):
    print(f"[+] Reading targets from {input_file}")
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_targets = list(set(
                line.strip().lower() for line in f
                if line.strip() and not line.startswith("*.") and not line.startswith("#")
            ))
    except Exception as error:
        print(f"[!] Failed to read input file: {error}")
        return

    filtered_targets = [d for d in raw_targets if is_valid_domain(d)]
    if not filtered_targets:
        print("[!] No valid domains to scan.")
        return

    print("[+] Resolving DNS...")
    with ThreadPool(max_threads) as pool:
        resolved = pool.map(resolve_domain, filtered_targets)

    targets = [(d, ip) for d, ip in resolved if ip]
    for d, ip in resolved:
        if not ip:
            print(f"[!] Skipping {d} - DNS resolution failed")

    if not targets:
        print("[!] No live targets to scan.")
        return

    print(f"[+] Starting Nmap scans on {len(targets)} target(s)")
    with ThreadPool(max_threads) as pool:
        results = pool.map(scan_target, targets)

    final_output = {}
    for entry in results:
        if isinstance(entry, dict):
            final_output.update(entry)

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_output, f, indent=2)
        print(f"[✓] Scan complete. Results saved to {output_file}")
    except Exception as error:
        print(f"[!] Failed to write output: {error}")

# CLI entry
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 scan.py <input_file.txt> <output_file.json>")
    else:
        run_scan(sys.argv[1], sys.argv[2])
