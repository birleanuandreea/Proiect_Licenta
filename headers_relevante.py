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

def calculeaza_statistici(folder_input):
    if not os.path.exists(folder_input):
        print(f"Folder '{folder_input}' does not exist.")
        return

    fisiere_json = [f for f in os.listdir(folder_input) if f.endswith('.json')]
    
    if not fisiere_json:
        print(f"No JSON files found in folder '{folder_input}'.")
        return

    headere_cautate = [
        'from', 
        'to', 
        'reply-to', 
        'return-path', 
        'received', 
        'received-spf', 
        'authentication-results', 
        'message-id', 
        'dkim-signature',
        "arc-message-signature"
    ]
    
    statistici = {header: {'prezent': 0, 'gol': 0} for header in headere_cautate}
    total_emailuri = 0

    for nume_fisier in fisiere_json:
        cale_input = os.path.join(folder_input, nume_fisier)
        try:
            with open(cale_input, 'r', encoding='utf-8') as f:
                date_json = json.load(f)

            if isinstance(date_json, list):
                lista_emailuri = date_json
            else:
                lista_emailuri = [date_json]

            for email in lista_emailuri:
                if not isinstance(email, dict):
                    continue
                
                total_emailuri += 1
                
                email_lower = {}
                for k, v in email.items():
                    email_lower[str(k).lower()] = v

                for header in headere_cautate:
                    if header in email_lower:
                        statistici[header]['prezent'] += 1
                        
                        if este_gol(email_lower[header]):
                            statistici[header]['gol'] += 1

        except Exception as e:
            print(f"Problem processing file '{nume_fisier}': {e}")

    
    if total_emailuri > 0:
        print(f"  {'HEADER':<24} | {'PRESENT IN EMAILS':<25} | {'OF WHICH EMPTY VALUES':<25}")

        for header in headere_cautate:
            prezent = statistici[header]['prezent']
            gol = statistici[header]['gol']
            
            proc_prezent = (prezent / total_emailuri) * 100 if total_emailuri > 0 else 0
            proc_gol = (gol / prezent) * 100 if prezent > 0 else 0
            
            nume_afisare = header.title()
            if header == 'dkim-signature': nume_afisare = 'DKIM-Signature'
            elif header == 'received-spf': nume_afisare = 'Received-SPF'
            elif header == 'message-id': nume_afisare = 'Message-ID'
            elif header == 'authentication-results': nume_afisare = 'Auth-Results'
            elif header == 'arc-message-signature': nume_afisare = 'Arc-Auth-Results'
            
            str_prezent = f"{prezent:4d} / {total_emailuri:<4d} ({proc_prezent:5.1f}%)"
            str_gol = f"{gol:4d} / {prezent:<4d} ({proc_gol:5.1f}%)"
            
            print(f"  {nume_afisare:<24} | {str_prezent:<25} | {str_gol:<25}")
    else:
        print(" No valid emails were found to generate statistics.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    
    args = parser.parse_args()
    calculeaza_statistici(args.input)