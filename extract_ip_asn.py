"""
Extracts sender IP addresses from email headers (X-Originating-IP and Received chain),
filters public IPv4 addresses, and performs ASN lookup using a GeoIP database.
"""

import argparse
import json
import re
import sys
from pathlib import Path
import geoip2.database
import geoip2.errors
import pandas as pd



PRIVATE_IP = re.compile(
    r'^('
    r'10\.'                           # Private IPv4 address range (RFC1918)
    r'|192\.168\.'                    # Private IPv4 address range (RFC1918)
    r'|172\.(1[6-9]|2[0-9]|3[01])\.'  # Private IPv4 address range (RFC1918)
    r'|127\.'                         # loopback
    r'|169\.254\.'                    # IPv4 link-local
    r')'
)

IPV4 = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def is_valid_public_ip(ip: str) -> bool:
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    if not IPV4.match(ip):
        return False
    if PRIVATE_IP.match(ip):
        return False
    try:
        parts = ip.split('.')
        for p in parts:
            value = int(p)
            if value < 0 or value > 255:
                return False
        return True
    except ValueError:
        return False


def clean_ip_string(raw: str) -> str:
    return re.sub(r'[\[\]\s]', '', str(raw)).strip()


def get_ip_from_xoriginating(email: dict) -> str:
    xip = email.get('x-originating-ip')
    if not xip:
        return ""

    if isinstance(xip, list):
        candidates = xip
    else:
        candidates = [xip]

    for candidate in candidates:
        ip = clean_ip_string(str(candidate))
        if is_valid_public_ip(ip):
            return ip

    return ""


def get_ip_from_hops(email: dict) -> tuple:
    received = email.get('received', [])
    if not isinstance(received, list) or not received:
        return "", ""

    try:
        sorted_hops = sorted(received, key=lambda h: int(h.get('hop', 999)))
    except (TypeError, ValueError):
        sorted_hops = received

    for hop in sorted_hops:
        from_val = hop.get('from', '')
        if not isinstance(from_val, str) or not from_val.strip():
            continue

        tokens = from_val.split()

        ip_candidates = []
        for token in tokens:
            cleaned = clean_ip_string(token)
            if IPV4.match(cleaned):
                ip_candidates.append(cleaned)

        for ip in reversed(ip_candidates):
            if is_valid_public_ip(ip):
                return ip, str(hop.get('hop', ''))

    return "", ""


def get_sender_ip(email: dict) -> tuple:
    ip = get_ip_from_xoriginating(email)
    if ip:
        return ip, "x-originating-ip"

    ip, hop_n = get_ip_from_hops(email)
    if ip:
        return ip, f"hop-{hop_n}"

    return "", "missing"


def lookup_asn(ip: str, reader: geoip2.database.Reader) -> dict:
    if not ip:
        return {'asn_number': None, 'asn_org': None}

    try:
        response = reader.asn(ip)
        return {
            'asn_number': response.autonomous_system_number,
            'asn_org': response.autonomous_system_organization,
        }
    except geoip2.errors.AddressNotFoundError:
        return {'asn_number': None, 'asn_org': None}
    except Exception:
        return {'asn_number': None, 'asn_org': None}



def load_emails(folder: str) -> list[dict]:
    folder_path = Path(folder)
    if not folder_path.exists() or not folder_path.is_dir():
        print(f"The folder '{folder}' does not exist.")
        sys.exit(1)

    json_files = list(folder_path.glob("*.json"))
    if not json_files:
        print(f"No JSON files found in '{folder}'.")
        sys.exit(1)

    emails = []
    for json_file in sorted(json_files):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, list):
                count = len(data)
                emails.extend(data)
            elif isinstance(data, dict):
                count = 1
                emails.append(data)
            else:
                print(f"Unknown format in {json_file.name}, ignored.")
                continue

            print(f"Loaded: {json_file.name} - {count} emails.")

        except json.JSONDecodeError as e:
            print(f"JSON error in {json_file.name}: {e}")
        except Exception as e:
            print(f"Error reading {json_file.name}: {e}")

    return emails


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--mmdb", required=True)
    args = parser.parse_args()

    mmdb_path = Path(args.mmdb)
    if not mmdb_path.exists():
        print(f"[ERROR] The mmdb file '{args.mmdb}' does not exist.")
        sys.exit(1)

    print(f"\nLoading emails from: {args.input}")
    emails = load_emails(args.input)
    print(f"\nTotal loaded emails: {len(emails)}")

    if not emails:
        print("No emails were loaded.")
        sys.exit(1)

    print(f"\nOpening ASN database: {args.mmdb}")
    print("Extracting IPs and performing ASN lookup...")

    records = []

    with geoip2.database.Reader(str(mmdb_path)) as reader:
        for email in emails:
            sender_ip, ip_source = get_sender_ip(email)
            asn_data = lookup_asn(sender_ip, reader)

            records.append({
                "sender_ip": sender_ip if sender_ip else None,
                "ip_source": ip_source,
                "asn_number": asn_data["asn_number"],
                "asn_org": asn_data["asn_org"],
            })

    df = pd.DataFrame(records)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)

    print(f"\nFeatures saved in: {output_path}")
    print(f"Dataset size: {df.shape[0]} emails x {df.shape[1]} columns")


if __name__ == "__main__":
    main()