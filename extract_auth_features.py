"""
Extracts authentication features (SPF, DKIM, DMARC, COMPAUTH) from JSON emails and encodes them into a CSV dataset.
"""

import argparse
import json
import re
import sys
from pathlib import Path
import pandas as pd



def to_str(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
        return "\n".join(parts)
    return ""


def is_hotmail_recipient(email: dict) -> bool:
    to_field = email.get("to", [])
    if not isinstance(to_field, list):
        return False
    for entry in to_field:
        if isinstance(entry, list) and len(entry) >= 2:
            address = str(entry[1]).lower()
            if "@hotmail.com" in address:
                return True
        elif isinstance(entry, str) and "@hotmail.com" in entry.lower():
            return True
    return False


def parse_spf(email: dict) -> str:
    auth = to_str(email.get("authentication-results"))
    if auth:
        match = re.search(r'\bspf=([a-zA-Z_]+)', auth, re.IGNORECASE)
        if match:
            return match.group(1).lower()

    received_spf = to_str(email.get("received-spf"))
    if received_spf:
        match = re.search(r'^([a-zA-Z_]+)', received_spf.strip(), re.IGNORECASE)
        if match:
            return match.group(1).lower()

    return "missing"


def parse_dkim_result(email: dict) -> str:
    auth = to_str(email.get("authentication-results"))
    if not auth:
        return "missing"

    matches = re.findall(r'\bdkim=([a-zA-Z_]+)', auth, re.IGNORECASE)
    if not matches:
        return "missing"

    normalized = []
    for m in matches:
        normalized.append(m.lower())

    if "pass" in normalized:
        return "pass"

    for val in normalized:
        if val == "dkim_pass":
            return "pass"

    return normalized[0]


def parse_dkim_algorithm(email: dict) -> str:
    dkim_raw = email.get("dkim-signature")
    if not dkim_raw:
        return "missing"

    dkim_str = to_str(dkim_raw)
    if not dkim_str:
        return "missing"

    match = re.search(r'\ba=([a-zA-Z0-9\-]+)', dkim_str, re.IGNORECASE)
    if match:
        return match.group(1).lower()

    return "missing"


def parse_dmarc_result(email: dict) -> str:
    auth = to_str(email.get("authentication-results"))
    if not auth:
        return "missing"

    match = re.search(r'\bdmarc=([a-zA-Z_]+)', auth, re.IGNORECASE)
    if match:
        return match.group(1).lower()

    return "missing"


def parse_dmarc_policy(email: dict) -> str:
    auth = to_str(email.get("authentication-results"))
    if not auth:
        return "missing"

    match = re.search(r'\bdmarc=[a-zA-Z_]+\s*\(\s*p=([A-Z]+)', auth, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    
    match_action = re.search(r'\bdmarc=[a-zA-Z_]+.*?action=([A-Z]+)', auth, re.IGNORECASE)
    if match_action:
        return match_action.group(1).lower()

    return "missing"


def parse_compauth(email: dict) -> str:
    if not is_hotmail_recipient(email):
        return "missing"

    auth = to_str(email.get("authentication-results"))
    if not auth:
        return "missing"

    match = re.search(r'\bcompauth=([a-zA-Z_]+)', auth, re.IGNORECASE)
    if match:
        return match.group(1).lower()

    return "missing"


SPF_ENCODING = {
    "pass":      2,
    "none":      1,
    "softfail":  1,
    "temperror": 1,
    "fail":      0,
}

DKIM_RESULT_ENCODING = {
    "pass":      2,
    "missing":   1,
    "unknown":   1,
    "none":      1,
    "timeout":   1,
    "perm_fail": 0,
    "fail":      0,
}

DKIM_ALGO_ENCODING = {
    "rsa-sha256": 2,
    "rsa-sha1":   1,
    "missing":    0
}

DMARC_RESULT_ENCODING = {
    "pass":          2,
    "bestguesspass": 2,
    "success":       2,
    "null":          1,
    "unknown":       1,
    "missing":       1,
    "none":          1,
    "fail":          0
}

DMARC_POLICY_ENCODING = {
    "reject":     2,
    "none":       1,
    "null":       1,
    "missing":    1,
    "quarantine": 0
}

COMPAUTH_ENCODING = {
    "pass":     2,
    "softpass": 1,
    "missing":  1,
    "fail":     0
}


def encode_spf(value: str) -> int:
    return SPF_ENCODING.get(value, 0)


def encode_dkim_result(value: str) -> int:
    return DKIM_RESULT_ENCODING.get(value, 0)


def encode_dkim_algorithm(value: str) -> int:
    return DKIM_ALGO_ENCODING.get(value, 0)


def encode_dmarc_result(value: str) -> int:
    return DMARC_RESULT_ENCODING.get(value, 0)


def encode_dmarc_policy(value: str) -> int:
    return DMARC_POLICY_ENCODING.get(value, 1)


def encode_compauth(value: str) -> int:
    return COMPAUTH_ENCODING.get(value, 0)


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


def extract_and_encode(emails: list[dict]) -> pd.DataFrame:
    records = []
    for email in emails:
        spf_raw          = parse_spf(email)
        dkim_result_raw  = parse_dkim_result(email)
        dkim_algo_raw    = parse_dkim_algorithm(email)
        dmarc_result_raw = parse_dmarc_result(email)
        dmarc_policy_raw = parse_dmarc_policy(email)
        compauth_raw     = parse_compauth(email)

        records.append({
            "spf_result_raw":      spf_raw,
            "dkim_result_raw":     dkim_result_raw,
            "dkim_algorithm_raw":  dkim_algo_raw,
            "dmarc_result_raw":    dmarc_result_raw,
            "dmarc_policy_raw":    dmarc_policy_raw,
            "compauth_raw":        compauth_raw,

            "spf_result":          encode_spf(spf_raw),
            "dkim_result":         encode_dkim_result(dkim_result_raw),
            "dkim_algorithm":      encode_dkim_algorithm(dkim_algo_raw),
            "dmarc_result":        encode_dmarc_result(dmarc_result_raw),
            "dmarc_policy":        encode_dmarc_policy(dmarc_policy_raw),
            "compauth":            encode_compauth(compauth_raw),
        })

    return pd.DataFrame(records)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    print(f"\nLoading emails from: {args.folder}")
    emails = load_emails(args.folder)
    print(f"\nTotal loaded emails: {len(emails)}")

    if not emails:
        print("No emails were loaded.")
        sys.exit(1)

    print("\nExtracting and encoding features...")
    df = extract_and_encode(emails)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)

    print(f"\nFeatures saved in: {output_path}")
    print(f"Dataset size: {df.shape[0]} emails x {df.shape[1]} columns")


if __name__ == "__main__":
    main()