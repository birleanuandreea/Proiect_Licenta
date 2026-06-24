import os
import json
import random
import argparse


def load_emails(folder_path):
    all_emails = []

    for file in os.listdir(folder_path):
        if not file.endswith(".json"):
            continue

        path = os.path.join(folder_path, file)

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

                if isinstance(data, list):
                    all_emails.extend(data)
                else:
                    all_emails.append(data)

        except Exception as e:
            print(f"Skipping {file}: {e}")

    return all_emails


def split_and_save(emails, output_folder, ratio=0.8, seed=42):

    random.seed(seed)
    random.shuffle(emails)

    split_idx = int(len(emails) * ratio)
    train_emails = emails[:split_idx]
    test_emails = emails[split_idx:]

    train_dir = os.path.join(output_folder, "train")
    test_dir = os.path.join(output_folder, "test")

    os.makedirs(train_dir, exist_ok=True)
    os.makedirs(test_dir, exist_ok=True)

    chunk_size = 500

    for i in range(0, len(train_emails), chunk_size):
        chunk = train_emails[i: i + chunk_size]
        chunk_num = (i // chunk_size) + 1
        file_path = os.path.join(train_dir, f"train_{chunk_num}.json")

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(chunk, f, indent=4, ensure_ascii=False)

    for i in range(0, len(test_emails), chunk_size):
        chunk = test_emails[i: i + chunk_size]
        chunk_num = (i // chunk_size) + 1
        file_path = os.path.join(test_dir, f"test_{chunk_num}.json")

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(chunk, f, indent=4, ensure_ascii=False)

    num_train_files = ((len(train_emails) - 1) // chunk_size) + 1 if train_emails else 0
    num_test_files = ((len(test_emails) - 1) // chunk_size) + 1 if test_emails else 0

    print(f"Total emails processed: {len(emails)}")
    print(f"Train set: {len(train_emails)} emails (saved in {num_train_files} files)")
    print(f"Test set:  {len(test_emails)} emails (saved in {num_test_files} files)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True,)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ratio", type=float, default=0.8)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    emails = load_emails(args.input)
    split_and_save(emails, args.output, args.ratio, args.seed)