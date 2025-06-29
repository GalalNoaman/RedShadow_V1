# RedShadow/modules/scan.py

import nmap
import json
import os
import sys
import socket
import dns.resolver
from multiprocessing.dummy import Pool as ThreadPool

# Use Google + Cloudflare DNS
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '1.1.1.1']
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
            arguments='-sS -sV -T4 -Pn -n -p 21,22,23,25,53,80,110,139,143,443,445,587,993,995,1723,3306,3389,5900,8080,8443'
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

def run_scan(input_file, output_file, threads=20):
    print(f"[+] Reading targets from {input_file}")
    try:
        with open(input_file, 'r') as f:
            raw_targets = list(set(
                line.strip().lower() for line in f
                if line.strip() and not line.startswith("*.") and not line.startswith("#")
            ))
    except Exception as error:
        print(f"[!] Failed to read input file: {error}")
        return

    print("[+] Resolving DNS...")
    with ThreadPool(threads) as pool:
        resolved = pool.map(resolve_domain, raw_targets)

    targets = [(d, ip) for d, ip in resolved if ip]
    for d, ip in resolved:
        if not ip:
            print(f"[!] Skipping {d} - DNS resolution failed")

    print(f"[+] Starting Nmap scans on {len(targets)} targets")
    with ThreadPool(threads) as pool:
        results = pool.map(scan_target, targets)

    final_output = {}
    for entry in results:
        if isinstance(entry, dict):
            final_output.update(entry)

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        with open(output_file, 'w') as f:
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