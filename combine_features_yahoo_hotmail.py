import argparse
import sys
from pathlib import Path
import pandas as pd


COLUMNS_TO_EXTRACT = {
    "auth_features.csv": [
        "spf_result",
        "dkim_result",
        "dkim_algorithm",
        "dmarc_result",
        "dmarc_policy",
        "compauth"
    ],

    "domains_features.csv": [
        "lev_from_returnpath",
        "lev_from_dkim",
        "lev_returnpath_helo",
        "lev_helo_messageid",
        "dkim_signature_present",
        "reply_to_present"
    ],

    "hops.csv": [
        "hop_count",
        "total_delay_log"
    ],

    "nerd_features.csv": [
        "asn_in_nerd",
        "asn_avg_rep"
    ],

    "dns.csv": [
        "ptr_exists",
        "ptr_matches_helo",
        "helo_domain_resolves",
        "from_domain_has_mx",
    ]
}


def find_config_for_folder(folder: Path) -> dict:
    found = {}
    for filename, cols in COLUMNS_TO_EXTRACT.items():
        fpath = folder / filename
        if fpath.exists():
            found[fpath] = cols
    return found


def merge(folder: str, output: str) -> None:
    folder_path = Path(folder)
    if not folder_path.exists() or not folder_path.is_dir():
        print(f"The folder '{folder}' does not exist.")
        sys.exit(1)

    config = find_config_for_folder(folder_path)

    if not config:
        print(f"[ERROR] No configured CSV files found in '{folder}'.")
        print("  Expected files are defined in COLUMNS_TO_EXTRACT in the script.")
        sys.exit(1)

    print(f"\nFiles found in '{folder}':")

    dfs = []
    n_rows = None

    for fpath, cols in config.items():
        df_raw = pd.read_csv(fpath)

        if n_rows is None:
            n_rows = len(df_raw)
        elif len(df_raw) != n_rows:
            print(f"\n'{fpath.name}' has {len(df_raw)} rows, but previous files had {n_rows}.")
            sys.exit(1)

        missing_cols = []
        for c in cols:
            if c not in df_raw.columns:
                missing_cols.append(c)

        if missing_cols:
            print(f"\n'{fpath.name}' does not contain the columns: {missing_cols}")
            print(f"Available columns: {list(df_raw.columns)}")
            sys.exit(1)

        df_selected = df_raw[cols].copy()
        dfs.append(df_selected)

    df_final = pd.concat(dfs, axis=1)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df_final.to_csv(output_path, index=False)

    print(f"\nFeatures saved in: {output_path}")
    print(f"Dataset size: {df_final.shape[0]} emails x {df_final.shape[1]} columns")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    merge(args.input, args.output)

if __name__ == "__main__":
    main()