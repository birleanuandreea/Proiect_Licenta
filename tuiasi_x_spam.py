import os
import json
import argparse

def este_gol(valoare):
    if valoare is None:
        return True
    if isinstance(valoare, str):
        return valoare.strip() == ""
    if isinstance(valoare, list):
        return all(este_gol(v) for v in valoare)
    if isinstance(valoare, dict):
        return len(valoare) == 0
    return False


def analizeaza_spamcheck(folder_input):
    if not os.path.exists(folder_input):
        print(f"[EROARE] Folderul '{folder_input}' nu există.")
        return

    fisiere_json = [f for f in os.listdir(folder_input) if f.endswith('.json')]

    if not fisiere_json:
        print(f"No JSON files found in folder '{folder_input}'.")
        return

    total_emailuri_analizate = 0

    statistici = {
        'prezent': 0,
        'absent': 0,
        'gol': 0
    }

    header_tinta = 'x-tuiasi-mailscanner-spamcheck'


    for nume_fisier in fisiere_json:
        cale_input = os.path.join(folder_input, nume_fisier)

        try:
            with open(cale_input, 'r', encoding='utf-8') as f:
                date_json = json.load(f)

            lista_emailuri = date_json if isinstance(date_json, list) else [date_json]

            for email in lista_emailuri:
                if not isinstance(email, dict):
                    continue

                total_emailuri_analizate += 1

                email_lower = {str(k).lower(): v for k, v in email.items()}

                if header_tinta in email_lower:
                    statistici['prezent'] += 1

                    if este_gol(email_lower[header_tinta]):
                        statistici['gol'] += 1
                else:
                    statistici['absent'] += 1

        except Exception as e:
            print(f"[ERROR] Problem processing file '{nume_fisier}': {e}")

    if total_emailuri_analizate > 0:
        prezent = statistici['prezent']
        absent = statistici['absent']
        gol = statistici['gol']

        proc_prezent = (prezent / total_emailuri_analizate) * 100
        proc_absent = (absent / total_emailuri_analizate) * 100
        proc_gol = (gol / prezent) * 100 if prezent > 0 else 0

        print(f"PRESENT: {prezent:5d} ({proc_prezent:6.2f}%)")
        print(f"ABSENT : {absent:5d} ({proc_absent:6.2f}%)")
        print(f"EMPTY: {gol:5d} out of {prezent} ({proc_gol:6.2f}%)")
    else:
        print("No emails were found.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    args = parser.parse_args()
    analizeaza_spamcheck(args.input)