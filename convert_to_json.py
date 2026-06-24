import os
import mailbox
import mailparser
import json
import argparse
import email.utils
import email
from concurrent.futures import ProcessPoolExecutor


def process_single_file(file_name, input_folder, output_folder):
    input_file_path = os.path.join(input_folder, file_name)
    output_file_name = f"{file_name}.json"
    output_file_path = os.path.join(output_folder, output_file_name)

    is_eml = file_name.lower().endswith('.eml')

    print(f"Processing ({'EML' if is_eml else 'MBOX'}): {file_name}...")

    try:
        processed_emails = 0
        skipped_emails = 0
        parsing_errors = 0

        messages_generator = []

        if is_eml:
            try:
                with open(input_file_path, 'rb') as eml_f:
                    bytes_content = eml_f.read()
                    msg_obj = email.message_from_bytes(bytes_content)
                    messages_generator = [(msg_obj, bytes_content)]
            except Exception:
                print(f"Error opening EML file {file_name}")
                return False
        else:
            try:
                mbox = mailbox.mbox(input_file_path)
                messages_generator = mbox
            except Exception as e:
                print(f"Error opening MBOX file {file_name}: {e}")
                return False

        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write("[\n")
            for item in messages_generator:

                if is_eml:
                    msg, raw_bytes = item
                else:
                    msg = item
                    try:
                        raw_bytes = msg.as_bytes()
                    except Exception:
                        parsing_errors += 1
                        continue

                date_str = msg.get('Date')
                if date_str:
                    try:
                        dt = email.utils.parsedate_to_datetime(date_str)
                        if dt.year < 2020:
                            skipped_emails += 1
                            continue
                    except Exception:
                        skipped_emails += 1
                        continue
                else:
                    skipped_emails += 1
                    continue

                try:
                    mail = mailparser.parse_from_bytes(raw_bytes)
                    email_data = json.loads(mail.mail_json)

                    if isinstance(email_data, dict):
                        email_data.pop("subject", None)
                        email_data.pop("body", None)

                    email_str = json.dumps(email_data, indent=4, ensure_ascii=False)
                    indented_email_str = "\n".join("    " + line for line in email_str.splitlines())

                    if processed_emails > 0:
                        f.write(",\n")

                    f.write(indented_email_str)
                    processed_emails += 1

                except Exception:
                    parsing_errors += 1

            f.write("\n]")

        print(
            f"{file_name} - "
            f"Saved: {processed_emails} | "
            f"Filtered (Year < 2020): {skipped_emails} | "
            f"Errors: {parsing_errors}"
        )
        return True

    except Exception as e:
        print(f"Error processing file {file_name}: {e}")
        return False


def convert_email_folder_to_json_parallel(input_folder, output_folder):
    os.makedirs(output_folder, exist_ok=True)

    all_files = []
    for f in os.listdir(input_folder):
        full_path = os.path.join(input_folder, f)
        if os.path.isfile(full_path):
            all_files.append(f)

    if not all_files:
        print("No files found in input folder.")
        return

    print(f"Found {len(all_files)} files. Starting parallel processing...\n")

    with ProcessPoolExecutor() as executor:
        futures = [
            executor.submit(process_single_file, file, input_folder, output_folder)
            for file in all_files
        ]

        for future in futures:
            future.result()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    convert_email_folder_to_json_parallel(args.input, args.output)