"""
Extracts email routing features from Received headers and exports them to a CSV dataset.
"""

import argparse
import json
import math
import re
import sys
from pathlib import Path
import pandas as pd
import tldextract



def get_registered_domain(raw: str) -> str:
    if not raw or not isinstance(raw, str):
        return ""
    
    raw = raw.strip().lower()
    raw = re.sub(r'[\[\]\s]', '', raw)
    raw = re.sub(r':\d+$', '', raw)
    if '.' not in raw:
        return ""
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', raw):
        return ""
    
    ext = tldextract.extract(raw)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    
    parts = raw.split('.')
    if len(parts) >= 2:
        a, b = parts[-2], parts[-1]
        if re.search(r'[a-z]', a) and re.search(r'[a-z]', b):
            return f"{a}.{b}"
    return ""


SKIP_TOKENS = {
    'EHLO', 'HELO', 'WITH', 'BY', 'FROM', 'FOR', 'VIA',
    'ID', 'NONE', 'ESMTP', 'ESMTPS', 'ESMTPA', 'ESMTPSA',
    'TLS', 'UTF8', 'SMTPS', 'HTTP',
}


def extract_domains_from_field(text: str) -> set:
    if not text or not isinstance(text, str):
        return set()

    domains = set()
    for token in text.split():
        t = token.strip().lower()
        if t.upper() in SKIP_TOKENS:
            continue
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', t):
            continue
        if '.' in t and re.search(r'[a-z]', t):
            d = get_registered_domain(t)
            if d:
                domains.add(d)

    return domains


def extract_routing_features(email: dict) -> dict:
    received = email.get("received", [])

    if not isinstance(received, list) or len(received) == 0:
        return {
            "hop_count": None,
            "total_delay_sec": None,
            "total_delay_log": None,
            "chain_consistency_ratio": None
        }

    hop_count = len(received)

    try:
        sorted_hops = sorted(received, key=lambda h: int(h.get("hop", 999)))
    except (TypeError, ValueError):
        sorted_hops = received

    if hop_count < 2:
        total_delay_sec = None
        total_delay_log = None
    else:
        total_delay = 0.0
        for hop in sorted_hops:
            d = hop.get("delay")
            if d is not None:
                try:
                    total_delay += float(d)
                except (TypeError, ValueError):
                    pass
        total_delay_clipped = max(0.0, total_delay)
        total_delay_sec = round(total_delay_clipped, 3)
        total_delay_log = round(math.log1p(total_delay_clipped), 6)

    if hop_count < 2:
        chain_consistency_ratio = None
    else:
        verifiable_pairs = 0
        consistent_pairs = 0

        for i in range(len(sorted_hops) - 1):
            by_field = sorted_hops[i].get("by", "")
            from_field = sorted_hops[i + 1].get("from", "")

            by_domains = extract_domains_from_field(by_field)
            from_domains = extract_domains_from_field(from_field)

            if not by_domains or not from_domains:
                continue

            verifiable_pairs += 1
            if by_domains & from_domains:
                consistent_pairs += 1

        if verifiable_pairs == 0:
            chain_consistency_ratio = None
        else:
            chain_consistency_ratio = round(consistent_pairs / verifiable_pairs, 4)

    return {
        "hop_count": hop_count,
        "total_delay_sec": total_delay_sec,
        "total_delay_log": total_delay_log,
        "chain_consistency_ratio": chain_consistency_ratio
    }



def load_emails(folder: str) -> list:
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
    args = parser.parse_args()

    print(f"\nLoading emails from: {args.input}")
    emails = load_emails(args.input)
    print(f"\nTotal loaded emails: {len(emails)}")

    if not emails:
        print("No emails were loaded.")
        sys.exit(1)

    print("\nExtracting and encoding features...")
    records = []
    for e in emails:
        records.append(extract_routing_features(e))
    df = pd.DataFrame(records)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)


    print(f"\nFeatures saved in: {output_path}")
    print(f"Dataset size: {df.shape[0]} emails x {df.shape[1]} columns")


if __name__ == "__main__":
    main()