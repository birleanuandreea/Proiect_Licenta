"""
This script extracts email-based security and linguistic features, including display name similarity and SpamAssassin scores, to support phishing and spam detection analysis.
"""
import argparse
import html
import json
import re
import sys
import unicodedata
from pathlib import Path
import Levenshtein
import pandas as pd




def clean_display_name(raw: str) -> str:
    if not raw or not isinstance(raw, str):
        return ""

    decoded = html.unescape(raw)
    cleaned = ""
    for c in decoded:
        if unicodedata.category(c) not in ("Cf", "Cc"):
            cleaned += c

    return cleaned.strip().lower()


def levenshtein_similarity(a: str, b: str):
    if not a or not b:
        return None
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 1.0
    return round(1.0 - Levenshtein.distance(a, b) / max_len, 4)


def get_sld(domain: str) -> str:
    if not domain or '.' not in domain:
        return domain
    return domain.split('.')[0].lower()

def extract_display_name_features(email: dict) -> dict:
    from_field = email.get("from", [])

    if not isinstance(from_field, list) or not from_field:
        return {
            "lev_display_name_alignment": None,
            "display_name_missing": 1
        }

    pair = from_field[0]
    if not isinstance(pair, (list, tuple)) or len(pair) < 2:
        return {
            "lev_display_name_alignment": None,
            "display_name_missing": 1
        }

    name_raw = str(pair[0]) if pair[0] else ""
    addr_raw = str(pair[1]) if pair[1] else ""

    name_clean = clean_display_name(name_raw)
    display_name_missing = 1 if not name_clean else 0

    if not name_clean or '@' not in addr_raw:
        return {
            "lev_display_name_alignment": None,
            "display_name_missing": display_name_missing
        }

    local_part = addr_raw.split('@')[0].lower()
    domain = addr_raw.split('@')[1].lower()
    sld = get_sld(domain)

    sim_local = levenshtein_similarity(name_clean, local_part)
    sim_sld = levenshtein_similarity(name_clean, sld)

    candidates = []
    for v in [sim_local, sim_sld]:
        if v is not None:
            candidates.append(v)
    best_sim = max(candidates) if candidates else None

    return {
        "lev_display_name_alignment": best_sim,
        "display_name_missing": display_name_missing
    }


def extract_spamassassin_features(email: dict) -> dict:

    val = email.get('x-tuiasi-mailscanner-spamcheck', '')

    if not val or not isinstance(val, str):
        return {
            "spamassassin_score": None,
            "spamassassin_present": 0
        }

    match = re.search(r'score=([-\d.]+)', val)
    if not match:
        return {
            "spamassassin_score": None,
            "spamassassin_present": 0
        }

    try:
        score = float(match.group(1))
    except ValueError:
        return {
            "spamassassin_score":   None,
            "spamassassin_present": 0
        }

    return {
        "spamassassin_score": score,
        "spamassassin_present": 1
    }


def process_email(email: dict) -> dict:
    record = {}
    record.update(extract_display_name_features(email))
    record.update(extract_spamassassin_features(email))
    return record


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