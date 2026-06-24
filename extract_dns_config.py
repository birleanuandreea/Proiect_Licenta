"""
This script extracts DNS-based security features from email data, including PTR, FCrDNS validation, and A/MX record checks for sender IPs and email domains.
"""
import argparse
import sys
import time
from pathlib import Path
import dns.exception
import dns.resolver
import dns.reversename
import pandas as pd
import tldextract
import re

DNS_TIMEOUT = 5
DELAY_PER_IP = 0.1


def get_registered_domain(raw: str) -> str:
    if not raw or not isinstance(raw, str):
        return ""
    raw = raw.strip().lower().rstrip('.')
    ext = tldextract.extract(raw)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    parts = raw.split('.')
    if len(parts) >= 2:
        a, b = parts[-2], parts[-1]
        if re.search(r'[a-z]', a) and re.search(r'[a-z]', b):
            return f"{a}.{b}"
    return ""


def ptr_lookup(ip: str) -> str | None:
    if not ip:
        return None
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, 'PTR', lifetime=DNS_TIMEOUT)
        return str(answers[0]).rstrip('.')
    except Exception:
        return None


def a_lookup(hostname: str) -> list:
    if not hostname:
        return []
    try:
        answers = dns.resolver.resolve(hostname.rstrip('.'), 'A', lifetime=DNS_TIMEOUT)
        result = []
        for r in answers:
            result.append(str(r))
        return result
    except Exception:
        return []


def has_a_record(domain: str) -> bool:
    if not domain:
        return False
    try:
        dns.resolver.resolve(domain, 'A', lifetime=DNS_TIMEOUT)
        return True
    except Exception:
        pass
    try:
        dns.resolver.resolve(domain, 'AAAA', lifetime=DNS_TIMEOUT)
        return True
    except Exception:
        return False


def has_mx_record(domain: str) -> bool:
    if not domain:
        return False
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=DNS_TIMEOUT)
        return len(answers) > 0
    except Exception:
        return False


def compute_ip_dns_features(ip: str, helo_domain: str) -> dict:
    ptr_hostname = ptr_lookup(ip)

    ptr_exists = 1 if ptr_hostname else 0

    if ptr_hostname:
        forward_ips = a_lookup(ptr_hostname)
        fcrdns_valid = 1 if ip in forward_ips else 0
        ptr_domain = get_registered_domain(ptr_hostname)
        helo_reg = get_registered_domain(helo_domain) if helo_domain else ""
        ptr_matches_helo = 1 if (ptr_domain and helo_reg and ptr_domain == helo_reg) else 0
    else:
        fcrdns_valid = 0
        ptr_matches_helo = 0

    return {
        "ptr_exists":       ptr_exists,
        "fcrdns_valid":     fcrdns_valid,
        "ptr_matches_helo": ptr_matches_helo,
    }


def compute_domain_dns_features(helo_domain: str, from_domain: str) -> dict:

    helo_resolves = 1 if has_a_record(helo_domain)  else 0
    helo_mx = 1 if has_mx_record(helo_domain) else 0
    from_mx = 1 if has_mx_record(from_domain) else 0

    return {
        "helo_domain_resolves": helo_resolves,
        "helo_has_mx": helo_mx,
        "from_domain_has_mx": from_mx
    }


def load_and_merge(input_path: str, lev_path: str) -> pd.DataFrame:
    df_ip  = pd.read_csv(input_path)
    df_lev = pd.read_csv(lev_path)

    if len(df_ip) != len(df_lev):
        print(f"Files have different sizes: {len(df_ip)} vs {len(df_lev)}")
        sys.exit(1)

    for col in ("sender_ip",):
        if col not in df_ip.columns:
            print(f"Column '{col}' is missing from {input_path}")
            sys.exit(1)

    for col in ("domain_helo", "domain_from"):
        if col not in df_lev.columns:
            print(f"Column '{col}' is missing from {lev_path}")
            sys.exit(1)

    df = pd.DataFrame({
        "sender_ip": df_ip["sender_ip"],
        "domain_helo": df_lev["domain_helo"],
        "domain_from": df_lev["domain_from"],
    })

    return df

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--lev", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    df = load_and_merge(args.input, args.lev)
    print(f"\nTotal loaded emails: {len(df)}")

    unique_ips = []
    for ip, helo in zip(df["sender_ip"], df["domain_helo"]):
        if isinstance(ip, str) and ip.strip():
            unique_ips.append((ip, helo))

    ip_to_helo = {}
    for ip, helo in unique_ips:
        if ip not in ip_to_helo:
            ip_to_helo[ip] = helo if isinstance(helo, str) else ""

    unique_ip_list = list(ip_to_helo.keys())
    print(f"Unique IPs to process: {len(unique_ip_list)}")

    domain_pairs = set()
    for _, row in df.iterrows():
        helo = row["domain_helo"] if isinstance(row["domain_helo"], str) else ""
        frm = row["domain_from"] if isinstance(row["domain_from"], str) else ""
        domain_pairs.add((helo, frm))

    print(f"\nDNS query for IPs (PTR / FCrDNS)...")
    ip_dns_cache = {}
    for i, ip in enumerate(unique_ip_list):
        helo = ip_to_helo[ip]
        if (i + 1) % 20 == 0:
            print(f" {i+1}/{len(unique_ip_list)} IPs processed...")
        ip_dns_cache[ip] = compute_ip_dns_features(ip, helo)
        time.sleep(DELAY_PER_IP)

    print(f"\nDNS query for domains (A / MX)...")
    domain_dns_cache = {}
    pairs_list = list(domain_pairs)
    for i, (helo, frm) in enumerate(pairs_list):
        if (i + 1) % 20 == 0:
            print(f"{i+1}/{len(pairs_list)} pairs processed...")
        domain_dns_cache[(helo, frm)] = compute_domain_dns_features(helo, frm)
        time.sleep(DELAY_PER_IP)

    records = []
    for _, row in df.iterrows():
        ip = row["sender_ip"]
        helo = row["domain_helo"] if isinstance(row["domain_helo"], str) else ""
        frm  = row["domain_from"]  if isinstance(row["domain_from"], str)  else ""

        if isinstance(ip, str) and ip.strip():
            ip_feats = ip_dns_cache.get(ip, {"ptr_exists": 0, "fcrdns_valid": 0, "ptr_matches_helo": 0})
        else:
            ip_feats = {"ptr_exists": 0, "fcrdns_valid": 0, "ptr_matches_helo": 0}

        dom_feats = domain_dns_cache.get((helo, frm), {"helo_domain_resolves": 0, "helo_has_mx": 0, "from_domain_has_mx": 0})

        records.append({
            "sender_ip":   ip,
            "domain_helo": helo if helo else None,
            "domain_from": frm  if frm  else None,
            **ip_feats,
            **dom_feats,
        })

    df_out = pd.DataFrame(records)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df_out.to_csv(output_path, index=False)

    print(f"\nFeatures saved in: {output_path}")
    print(f"Dataset size: {df_out.shape[0]} emails x {df_out.shape[1]} columns")


if __name__ == "__main__":
    main()