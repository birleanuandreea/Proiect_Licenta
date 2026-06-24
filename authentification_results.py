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
            elif isinstance(item, list):
                pass
        return "\n".join(parts)
    return ""


def normalize_result(value: str) -> str:
    v = value.strip().lower()
    if v == "dkim_pass":
        return "pass"
    return v


def parse_spf(email: dict) -> str:
    auth = to_str(email.get("authentication-results"))
    if auth:
        match = re.search(r'\bspf=([a-zA-Z_]+)', auth, re.IGNORECASE)
        if match:
            return normalize_result(match.group(1))

    received_spf = to_str(email.get("received-spf"))
    if received_spf:
        match = re.search(r'^([a-zA-Z_]+)', received_spf.strip(), re.IGNORECASE)
        if match:
            return normalize_result(match.group(1))

    return "missing"


def parse_dkim_result(email: dict) -> str:

    auth = to_str(email.get("authentication-results"))
    if not auth:
        return "missing"

    matches = re.findall(r'\bdkim=([a-zA-Z_]+)', auth, re.IGNORECASE)
    if not matches:
        return "missing"

    normalized = [normalize_result(m) for m in matches]
    if "pass" in normalized:
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
        return normalize_result(match.group(1))

    return "missing"


def parse_dmarc_policy(email: dict) -> str:
    auth = to_str(email.get("authentication-results"))
    if not auth:
        return "missing"

    match = re.search(r'\bdmarc=[a-zA-Z_]+\s*\(\s*p=([A-Z]+)', auth, re.IGNORECASE)
    if match:
        return match.group(1).lower()

    return "missing"


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



def extract_features(emails: list[dict]) -> pd.DataFrame:
    records = []
    for email in emails:
        records.append({
            "spf_result":     parse_spf(email),
            "dkim_result":    parse_dkim_result(email),
            "dkim_algorithm": parse_dkim_algorithm(email),
            "dmarc_result":   parse_dmarc_result(email),
            "dmarc_policy":   parse_dmarc_policy(email),
            "has_auth":      bool(to_str(email.get("authentication-results")).strip()),
            "has_spf":       bool(to_str(email.get("received-spf")).strip()),
            "has_dkim_sig":  bool(to_str(email.get("dkim-signature")).strip()),
        })
    return pd.DataFrame(records)


def coverage_analysis(df: pd.DataFrame, label: str) -> None:
    n = len(df)
    has_ar = df["has_auth"].sum()
    has_spf = df["has_spf"].sum()
    has_dk = df["has_dkim_sig"].sum()
    has_all = (df["has_auth"] & df["has_spf"] & df["has_dkim_sig"]).sum()
    has_none = (~df["has_auth"] & ~df["has_spf"] & ~df["has_dkim_sig"]).sum()

    rows = [
        ("Authentication-Results", has_ar),
        ("Received-SPF", has_spf),
        ("DKIM-Signature", has_dk),
        ("All present", has_all),
        ("None present", has_none),
    ]

    print(f"\nCOVERAGE ANALYSIS - {label} (total: {n})")
    for name, val in rows:
        print(f"{name:<25} {val:>6} ({100*val/n:.1f}%)")


FEATURES = {
    "spf_result": "SPF Result",
    "dkim_result": "DKIM Result",
    "dkim_algorithm": "DKIM Algorithm",
    "dmarc_result": "DMARC Result",
    "dmarc_policy": "DMARC Policy",
}


def distribution_table(df: pd.DataFrame, feature: str, label: str) -> None:
    n = len(df)
    counts = df[feature].value_counts(dropna=False)

    print(f"\n{FEATURES[feature]} - {label}")
    for val, count in counts.items():
        print(f"  {val:<15} {count:>6} ({100*count/n:.1f}%)")


def unique_values_report(df: pd.DataFrame, label: str) -> None:
    print(f"\nUNIQUE VALUES - {label}")
    for feature, name in FEATURES.items():
        vals = sorted(df[feature].dropna().unique())
        print(f"{name}: {vals}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", required=True)
    parser.add_argument("--label", required=True)
    args = parser.parse_args()

    print(f"\nLoading emails from: {args.folder}")
    emails = load_emails(args.folder)

    if not emails:
        print("[ERROR] No emails loaded.")
        sys.exit(1)

    df = extract_features(emails)

    print("COVERAGE ANALYSIS\n")
    coverage_analysis(df, args.label)

    print("UNIQUE VALUES\n")
    unique_values_report(df, args.label)

    print("DISTRIBUTIONS\n")

    for feature in FEATURES:
        distribution_table(df, feature, args.label)


if __name__ == "__main__":
    main()