"""
This script processes email datasets and extracts security-related features from email headers, including sender, routing, and authentication signals (DKIM, HELO, return-path). It also computes domain-based similarity metrics for anomaly detection and phishing analysis.
"""
import argparse
import json
import re
import sys
from pathlib import Path
import pandas as pd
import tldextract
import Levenshtein

PRIVATE_IP = re.compile(
    r'^('
    r'10\.'                           # Private IPv4 address range (RFC1918)
    r'|192\.168\.'                    # Private IPv4 address range (RFC1918)
    r'|172\.(1[6-9]|2[0-9]|3[01])\.'  # Private IPv4 address range (RFC1918)
    r'|127\.'                         # loopback
    r'|169\.254\.'                    # IPv4 link-local
    r')'
)
SKIP_HOSTNAMES = {'localhost', 'unknown'}


def extract_registered_domain(raw: str) -> str:
    if not raw or not isinstance(raw, str):
        return ""

    raw = raw.strip().lower()
    if "@" in raw:
        raw = raw.split("@")[-1]

    raw = re.sub(r'[<>()\[\]"\'\s]', '', raw)
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
        seg_a = parts[-2]
        seg_b = parts[-1]
        if re.search(r'[a-z]', seg_a) and re.search(r'[a-z]', seg_b):
            return f"{seg_a}.{seg_b}"

    return ""


def get_from_domain(email: dict) -> str:
    from_field = email.get("from", [])
    if not isinstance(from_field, list):
        return ""
    for pair in from_field:
        if isinstance(pair, (list, tuple)) and len(pair) >= 2:
            addr = pair[1]
            if addr and "@" in str(addr):
                return extract_registered_domain(str(addr))
    return ""


def get_first_tuiasi_from_to(email: dict) -> str:
    to_field = email.get("to", [])
    
    if not isinstance(to_field, list):
        return ""
        
    for pair in to_field:
        if isinstance(pair, (list, tuple)) and len(pair) >= 2:
            addr = str(pair[1]).strip()  
            if addr and "@" in addr:
                if "tuiasi.ro" in addr.lower():
                    return addr               
    return ""


def get_return_path_domain(email: dict) -> str:
    rp = email.get("return-path", "")
    if not isinstance(rp, str) or not rp.strip():
        return ""
    return extract_registered_domain(rp)


def get_reply_to_domain(email: dict) -> str:
    rt = email.get("reply-to", [])
    if not isinstance(rt, list):
        return ""
    for pair in rt:
        if isinstance(pair, (list, tuple)) and len(pair) >= 2:
            addr = pair[1]
            if addr and "@" in str(addr):
                return extract_registered_domain(str(addr))
    return ""


def get_message_id_domain(email: dict) -> str:
    mid = email.get("message-id", "")
    if not isinstance(mid, str) or not mid.strip():
        return ""
    return extract_registered_domain(mid)


def get_dkim_domains(email: dict) -> list:
    dkim_raw = email.get("dkim-signature")
    if not dkim_raw:
        return []
    if isinstance(dkim_raw, str):
        signatures = [dkim_raw]
    elif isinstance(dkim_raw, list):
        signatures = []
        for s in dkim_raw:
            if isinstance(s, str):
                signatures.append(s)
    else:
        return []

    domains = []
    for sig in signatures:
        match = re.search(r'\bd=([a-zA-Z0-9.\-]+)', sig, re.IGNORECASE)
        if match:
            dom = extract_registered_domain(match.group(1))
            if dom:
                domains.append(dom)

    return domains


def get_helo_domain_from_hop_from(email: dict) -> tuple:

    received = email.get("received", [])
    if not isinstance(received, list) or not received:
        return "", ""

    try:
        sorted_hops = sorted(received, key=lambda h: int(h.get("hop", 999)))
    except (TypeError, ValueError):
        sorted_hops = received

    for hop in sorted_hops:
        from_val = hop.get("from", "")
        if not isinstance(from_val, str) or not from_val.strip():
            continue

        tokens = from_val.split()
        for token in tokens:
            token_lower = token.strip().lower()

            if '.' not in token_lower:
                continue

            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', token_lower):
                continue

            if PRIVATE_IP.match(token_lower):
                continue

            if token_lower in SKIP_HOSTNAMES:
                continue

            dom = extract_registered_domain(token_lower)
            if dom:
                return dom, token_lower
    return "", ""


def get_helo_domain(email: dict) -> tuple:
    received = email.get("received", [])
    if not isinstance(received, list) or not received:
        return "", ""

    try:
        sorted_hops = sorted(received, key=lambda h: int(h.get("hop", 999)))
    except (TypeError, ValueError):
        sorted_hops = received

    for hop in sorted_hops:
        from_val = hop.get("from", "")
        if not isinstance(from_val, str):
            continue

        ehlo_match = re.search(r'\bEHLO\s+([^\s]+)', from_val, re.IGNORECASE)
        if not ehlo_match:
            continue

        hostname = ehlo_match.group(1).strip()

        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
            continue

        dom = extract_registered_domain(hostname)
        if dom:
            return dom, hostname

    to_dom = get_first_tuiasi_from_to(email)
    
    if not to_dom:
        return get_helo_domain_from_hop_from(email)
    
    ext = tldextract.extract(to_dom)
    if ext.domain == 'tuiasi' and ext.suffix == 'ro':
        return get_helo_domain_from_hop_from(email)

    return "", ""


def levenshtein_similarity(a: str, b: str):
    if not a or not b:
        return None

    max_len = max(len(a), len(b))
    if max_len == 0:
        return 1.0

    distance = Levenshtein.distance(a, b)
    return round(1.0 - distance / max_len, 4)


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


def process_email(email: dict) -> dict:
    from_dom = get_from_domain(email)
    return_path_dom = get_return_path_domain(email)
    reply_to_dom = get_reply_to_domain(email)
    message_id_dom = get_message_id_domain(email)
    helo_dom, helo_full = get_helo_domain(email)
    dkim_domains = get_dkim_domains(email)


    dkim_signature_present = 1 if dkim_domains else 0

    dkim_dom_selected = ""
    dkim_from_sim = None

    if dkim_domains:
        if from_dom:
            best_sim = -1.0
            for d in dkim_domains:
                sim = levenshtein_similarity(from_dom, d)
                if sim is not None and sim > best_sim:
                    best_sim = sim
                    dkim_dom_selected = d
                    dkim_from_sim = sim
        else:
            dkim_dom_selected = dkim_domains[0]
            dkim_from_sim = None

    reply_to_present = 1 if reply_to_dom else 0
    if reply_to_dom:
        lev_from_replyto = levenshtein_similarity(from_dom, reply_to_dom)
        lev_returnpath_replyto = levenshtein_similarity(return_path_dom, reply_to_dom)
        if lev_from_replyto is None:
            lev_from_replyto = 0.0
        if lev_returnpath_replyto is None:
            lev_returnpath_replyto = 0.0
    else:
        lev_returnpath_replyto = 0.0
        lev_from_replyto = 0.0

    record = {
        "domain_from": from_dom if from_dom else None,
        "domain_return_path": return_path_dom if return_path_dom else None,
        "domain_reply_to": reply_to_dom if reply_to_dom else None,
        "domain_message_id": message_id_dom if message_id_dom else None,
        "domain_helo": helo_dom if helo_dom else None,
        "domain_helo_full": helo_full if helo_full else None,
        "domain_dkim": dkim_dom_selected if dkim_dom_selected else None,
        "lev_from_returnpath": levenshtein_similarity(from_dom, return_path_dom),
        "lev_from_dkim": dkim_from_sim,
        "lev_from_messageid": levenshtein_similarity(from_dom, message_id_dom),
        "lev_from_replyto":  lev_from_replyto,
        "lev_from_helo": levenshtein_similarity(from_dom, helo_dom),
        "lev_returnpath_helo": levenshtein_similarity(return_path_dom, helo_dom),
        "lev_helo_messageid": levenshtein_similarity(helo_dom, message_id_dom),
        "lev_returnpath_replyto": lev_returnpath_replyto,
        "dkim_signature_present": dkim_signature_present,
        "reply_to_present": reply_to_present,
    }

    return record


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
        records.append(process_email(e))
    df = pd.DataFrame(records)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)

    print(f"\nFeatures saved in: {output_path}")
    print(f"Dataset size: {df.shape[0]} emails x {df.shape[1]} columns")


if __name__ == "__main__":
    main()