"""
This script extracts IP and ASN-level features from the NERD API for a given email dataset.
"""


import argparse
import sys
import time
from pathlib import Path
import pandas as pd
import requests


BASE_URL = "https://nerd.cesnet.cz/nerd/api/v1"

# NERD allows 300 requests / 5 minutes for IP queries
# https://github.com/CESNET/NERD/wiki/Rate-limits
DELAY_IP = 0.3   # seconds between IP queries
DELAY_ASN = 0.5   # seconds between ASN queries


def query_ip(ip: str, token: str, session: requests.Session) -> dict:
    empty = {
        "ip_rep": None,
        "ip_fmp": None,
        "ip_geo_country": None,
        "ip_bl_count": None,
        "ip_events_total": None,
        "ip_in_nerd": 0
    }

    if not ip or not isinstance(ip, str):
        return empty

    url = f"{BASE_URL}/ip/{ip}"
    try:
        resp = session.get(
            url,
            headers={"Authorization": f"token {token}"},
            timeout=10
        )

        if resp.status_code == 404:
            empty["ip_in_nerd"] = 0
            return empty

        if resp.status_code != 200:
            print(f"Request failed: IP {ip}: HTTP {resp.status_code}")
            return empty

        data = resp.json()

        ip_rep = data.get("rep")

        fmp = data.get("fmp", {})
        if isinstance(fmp, dict):
            ip_fmp = fmp.get("general")
        else:
            ip_fmp = None

        geo = data.get("geo", {})
        if isinstance(geo, dict):
            ip_country = geo.get("ctry")
        else:
            ip_country = None

        bl_list = data.get("bl", [])
        ip_bl_cnt = 0
        if isinstance(bl_list, list):
            for entry in bl_list:
                if isinstance(entry, dict) and entry.get("last_result") is True:
                    ip_bl_cnt += 1

        events_meta = data.get("events_meta", {})
        ip_events_total = None
        if isinstance(events_meta, dict):
            ip_events_total = events_meta.get("total")

        return {
            "ip_rep": ip_rep,
            "ip_fmp": ip_fmp,
            "ip_geo_country": ip_country,
            "ip_bl_count": ip_bl_cnt,
            "ip_events_total": ip_events_total,
            "ip_in_nerd": 1
        }

    except requests.exceptions.Timeout:
        print(f"IP {ip}: timeout")
        return empty
    except Exception as e:
        print(f"IP {ip}: {e}")
        return empty


def query_asn_avg_rep(asn_number: int, token: str, session: requests.Session) -> dict:

    empty = {"asn_avg_rep": None, "asn_in_nerd": 0}

    if asn_number is None or pd.isna(asn_number):
        return empty

    try:
        asn_int = int(asn_number)
    except (ValueError, TypeError):
        return empty

    url = f"{BASE_URL}/search/ip/"
    params = {
        "asn": asn_int,
        "o": "short",
        "limit": 1000,
    }

    try:
        resp = session.get(
            url,
            headers={"Authorization": f"token {token}"},
            params=params,
            timeout=15
        )

        if resp.status_code != 200:
            print(f"Request failed: ASN {asn_int}: HTTP {resp.status_code}")
            return empty

        data = resp.json()

        if not isinstance(data, list) or len(data) == 0:
            return empty

        rep_values = []
        for entry in data:
            if isinstance(entry, dict):
                rep = entry.get("rep")
                if rep is not None:
                    try:
                        rep_values.append(float(rep))
                    except (ValueError, TypeError):
                        pass
        if rep_values:
            asn_avg_rep = round(sum(rep_values) / len(rep_values), 6)
        else:
            asn_avg_rep = None

        return {
            "asn_avg_rep": asn_avg_rep,
            "asn_in_nerd": 1,
        }

    except requests.exceptions.Timeout:
        print(f"ASN {asn_int}: timeout")
        return empty
    except Exception as e:
        print(f"ASN {asn_int}: {e}")
        return empty


def load_emails(path: str) -> pd.DataFrame:
    p = Path(path)
    if not p.exists():
        print(f"The file '{path}' does not exist.")
        sys.exit(1)

    df = pd.read_csv(path)

    required = {"sender_ip", "asn_number"}
    missing  = required - set(df.columns)

    if missing:
        print(f"Missing columns in CSV: {missing}")
        print(f"Available columns: {list(df.columns)}")
        sys.exit(1)

    return df

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()

    print(f"\nLoading emails from: {args.input}")
    df = load_emails(args.input)
    print(f"\nTotal loaded emails: {len(df)}")

    session = requests.Session()

    unique_ips = []
    for ip in df["sender_ip"].dropna().unique():
        if isinstance(ip, str) and ip.strip():
            unique_ips.append(ip)
    print(f"\nNERD query for {len(unique_ips)} unique IPs...")

    ip_cache = {}
    for i, ip in enumerate(unique_ips):
        if (i + 1) % 10 == 0:
            print(f"{i+1}/{len(unique_ips)} IPs processed...")
        ip_cache[ip] = query_ip(ip, args.token, session)
        time.sleep(DELAY_IP)

    unique_asns = []
    for asn in df["asn_number"].dropna().unique():
        unique_asns.append(asn)
    print(f"\nNERD query for {len(unique_asns)} unique ASNs...")

    asn_cache = {}
    for i, asn in enumerate(unique_asns):
        if (i + 1) % 5 == 0:
            print(f"{i+1}/{len(unique_asns)} ASNs processed...")
        asn_cache[asn] = query_asn_avg_rep(asn, args.token, session)
        time.sleep(DELAY_ASN)

    records = []
    for _, row in df.iterrows():
        ip  = row.get("sender_ip")
        asn = row.get("asn_number")

        if isinstance(ip, str) and ip.strip():
            ip_features = ip_cache.get(ip, {
                "ip_rep": None,
                "ip_fmp": None,
                "ip_geo_country": None,
                "ip_bl_count": None,
                "ip_events_total": None,
                "ip_in_nerd": 0
            })
        else:
            ip_features = {
                "ip_rep": None,
                "ip_fmp": None,
                "ip_geo_country": None,
                "ip_bl_count": None,
                "ip_events_total": None,
                "ip_in_nerd": 0
            }

        if asn is not None and not pd.isna(asn):
            asn_features = asn_cache.get(
                int(asn),
                {"asn_avg_rep": None, "asn_in_nerd": 0}
            )
        else:
            asn_features = {
                "asn_avg_rep": None,
                "asn_in_nerd": 0
            }

        records.append({
            "sender_ip": ip,
            "asn_number": asn,
            "ip_in_nerd": ip_features["ip_in_nerd"],
            "ip_rep": ip_features["ip_rep"],
            "ip_fmp": ip_features["ip_fmp"],
            "ip_geo_country": ip_features["ip_geo_country"],
            "ip_bl_count": ip_features["ip_bl_count"],
            "ip_events_total": ip_features["ip_events_total"],
            "asn_avg_rep": asn_features["asn_avg_rep"],
            "asn_in_nerd": asn_features["asn_in_nerd"]
        })

    df_out = pd.DataFrame(records)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df_out.to_csv(output_path, index=False)

    print(f"\nFeatures saved in: {output_path}")
    print(f"Dataset size: {df.shape[0]} emails x {df.shape[1]} columns")


if __name__ == "__main__":
    main()