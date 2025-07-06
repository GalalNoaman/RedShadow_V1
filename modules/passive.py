# Developed by Galal Noaman – RedShadow_V1
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v1/modules/passive.py

import httpx
import os
import json
import time
from tqdm import tqdm
from modules.utils import load_config

class PassiveReconError(Exception):
    pass

def extract_title(html):
    start = html.lower().find("<title>")
    end = html.lower().find("</title>")
    if start != -1 and end != -1 and end > start:
        return html[start + 7:end].strip()
    return "N/A"

def detect_technologies(html, headers):
    tech = []
    html_lower = html.lower()

    # HTML-based detection
    if "wp-content" in html_lower or "wordpress" in html_lower:
        tech.append("WordPress")
    if "/_next/" in html_lower:
        tech.append("Next.js")
    if "drupal.settings" in html_lower:
        tech.append("Drupal")
    if "joomla" in html_lower or "com_content" in html_lower:
        tech.append("Joomla")
    if "<meta name=\"generator\" content=\"shopify" in html_lower:
        tech.append("Shopify")
    if "magento" in html_lower:
        tech.append("Magento")

    # Header-based detection
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    aspnet = headers.get("x-aspnet-version", "")
    aws = headers.get("x-amz-bucket-region", "")

    if server:
        tech.append(server)
    if powered_by:
        tech.append(powered_by)
    if aspnet:
        tech.append("ASP.NET")
    if aws:
        tech.append("AWS S3")

    return list(set(tech))

def passive_recon(input_file, output_file, insecure=False, verbose=False):
    if not os.path.exists(input_file):
        print(f"[!] Subdomain list not found: {input_file}")
        return

    config = load_config(section="passive")
    delay = config.get("delay", 1)
    verify_ssl = not insecure and config.get("verify_ssl", True)

    print("[+] Starting passive reconnaissance...")
    with open(input_file, 'r', encoding='utf-8') as f:
        subdomains = [line.strip() for line in f if line.strip()]

    results = []
    for subdomain in tqdm(subdomains, desc="Checking subdomains"):
        for scheme in ['http://', 'https://']:
            url = scheme + subdomain
            try:
                response = httpx.get(
                    url,
                    timeout=10,
                    follow_redirects=True,
                    verify=verify_ssl
                )

                tech_matches = [
                    {"tech": t, "cves": []}
                    for t in detect_technologies(response.text, response.headers)
                ]

                results.append({
                    'url': url,
                    'ip': response.extensions.get("httpx.original_ip", "N/A"),
                    'hostname': subdomain,
                    'status': response.status_code,
                    'title': extract_title(response.text),
                    'tech_matches': tech_matches,
                    'headers': dict(response.headers)
                })

                time.sleep(delay)
                break  # Skip https if http worked (or vice versa)

            except httpx.ConnectTimeout:
                if verbose:
                    print(f"[!] Timeout: {url}")
            except httpx.RequestError as e:
                if verbose:
                    print(f"[!] Connection error: {url} → {e}")
            except Exception as e:
                if verbose:
                    print(f"[!] Unexpected error: {url} → {e}")

    if not results:
        print("[!] No reachable subdomains found.")
        return

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    try:
        with open(output_file, 'w', encoding='utf-8') as out:
            json.dump(results, out, indent=2)
        print(f"[✓] Passive reconnaissance complete. {len(results)} reachable hosts saved to {output_file}")
    except Exception as error:
        raise PassiveReconError(f"[!] Could not write output file: {error}")
