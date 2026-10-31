import string
import math
import hashlib
import requests
import csv
from colorama import Fore, Style, init
from tabulate import tabulate
import pyfiglet
from colorama import Fore, Style

init(autoreset=True) # Makes colors work on Windows automatically

def print_banner():
    # Fonts: 'slant', 'doom', 'cybermedium', 'standard'
    ascii_banner = pyfiglet.figlet_format("PASLYZER", font="standard")
    print(Fore.LIGHTCYAN_EX + ascii_banner + Style.RESET_ALL)
    print(Fore.LIGHTRED_EX + "    < Coded by Akshit Bakshi >" + Style.RESET_ALL)
    print(Fore.LIGHTGREEN_EX + "    v1.0 - Password Security Analyzer\n" + Style.RESET_ALL)
def check_password_complexity(password):
    has_upper=False
    has_lower=False
    has_digit=False
    has_special=False
    for char in password:
        if char.isupper():
            has_upper=True
        if char.islower():
            has_lower=True
        if char.isdigit():
            has_digit=True
        if char in string.punctuation:
            has_special=True
    
    score=0
    if len(password)>=8:
        score+=1
    if has_upper:
        score+=1
    if has_digit:
        score+=1
    if has_lower:
        score+=1
    if has_special:
        score+=1
    entropy_bits=calculate_entropy(password,has_upper,has_lower, has_digit, has_special)
    return score, entropy_bits
def calculate_entropy(password,has_upper,has_lower,has_digit,has_special):
    pool_size=0
    if has_lower: pool_size+=26
    if has_digit: pool_size+=26
    if has_upper: pool_size+=26
    if has_special: pool_size+=32

    if pool_size==0:
        return 0
    entropy=len(password)*math.log2(pool_size)
    return round(entropy,2)
def check_breached_api(password):
    sha1_password=hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix=sha1_password[:5]
    suffix=sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response= requests.get(url, timeout=2)
        if response.status_code !=200:
            return "Error! API unavailable"
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h==suffix:
                return int(count)
        return 0
    except Exception as e:
        print(f"DEBUG Error: {e}")
        return "Error! Could not connect"

def generate_feedback(finscore,entropybits,breach_count):
    feedback=[]
    if isinstance(breach_count,int) and breach_count>0:
        print(f"{password} is leaked, appears in {breach_count:,} known data breaches, change it.")
    if finscore<=3 and entropybits<50:
        feedback.append("Password is mathematically too predictable.")
    elif finscore<=4 and entropybits<80:
        feedback.append("Good but not strong enough for secure data.")
    elif finscore==5 and breach_count==0:
        print(f"{password} password is safe")
    if not feedback:
        print("Strong, Excellent password.")
    return feedback

def run_bulk_audit():
    input_file=input("\nEnter the text filename: ").strip()
    if '.txt' not in input_file:
        input_file=input_file+".txt"
    output_file="audit_report.txt"
    print(f"\n Opening {input_file}...")
    try:
        with open(input_file,"r") as f_in, open(output_file, "w") as f_out:
            count=0
            for line in f_in:
                pwd=line.strip()
                if not pwd: continue
                breaches = check_breached_api(pwd)
                score, entropy = check_password_complexity(pwd)
                status="SAFE"
                if isinstance(breaches,int) and breaches >0:
                    status="UNSAFE(LEAKED)"
                elif score<3 and entropy<50:
                    status="UNSAFE(WEAK)"
                report_line= f"[{status}] {pwd:<20}, Score: {score}/5, Entropy: {entropy}, Breaches: {breaches}\n"
                f_out.write(report_line)
                print(".",end="", flush=True)
                count+=1
        print(f"\n\nAudit complete! checked {count} passwords.")
        print(f"Results saved to: {output_file}")
    except FileNotFoundError:
        print(f"Error! coudln't find {input_file}")

def audit_csv_file():
    input_file=input("\nEnter the CSV filename: ").strip()
    if '.csv' not in input_file:
        input_file=input_file+'.csv'
    if input_file.endswith(".csv"):
        output_file=input_file.replace(".csv","_Report.csv")
    else:
        output_file=input_file+"_Report.csv"
    print(f"Opening {input_file}...")
    count=0
    try:
        with open(input_file,mode='r',newline='',encoding='utf-8') as f_in:
            reader=csv.DictReader(f_in)
            headers=reader.fieldnames
            if not headers:
                print("Error! This file is empty.")
                return
            passcord_col=None
            for col in headers:
                if "password" in col.lower():
                    password_col=col
                    break
            if not passcord_col:
                print(f"Couldn't detect password column.")
                print(f"Found columns: {headers}")
                password_col=input("Which column contains the passwords? ").strip()
                if password_col not in headers:
                    print("Error! That column doesn't exist in the file.")
            print(f"Using column {password_col} for analysis.")
            new_headers=headers+['Score','Entropy','Breaches','Status']
            results=[]
            with open(output_file, mode='w',newline='',encoding='utf-8') as f_out:
                writer=csv.DictWriter(f_out,fieldnames=new_headers)
                writer.writeheader()
                count=0
                for row in reader:
                    pwd=row[password_col]
                    breaches=check_breached_api(pwd)
                    score, entropy=check_password_complexity(pwd)
                    if isinstance(breaches, int) and breaches>0:
                        status="UNSAFE(LEAKED)"
                        color_status = Fore.RED + "CRITICAL" + Style.RESET_ALL
                    elif score<3 and entropy<50:
                        status="UNSAFE(WEAK)"
                        color_status = Fore.YELLOW + "Weak" + Style.RESET_ALL
                    elif entropy>80:
                        status="SAFE(STRONG)"
                        color_status = Fore.GREEN + "Strong" + Style.RESET_ALL
                    else:
                        status="SAFE(MODERATE)"
                        color_status = Fore.BLUE + "Moderate" + Style.RESET_ALL
                    row['Score'] = f"{score}/5"
                    row['Entropy'] = f"{entropy} bits"
                    row['Breaches'] = breaches
                    row['Status'] = status
                    writer.writerow(row)
                    results.append([
                        row.get('EmployeeID', 'N/A'), # Tries to find ID, defaults to N/A
                        pwd, 
                        f"{score}/5", 
                        f"{entropy}", 
                        breaches, 
                        color_status
                    ])
                    print(".",end="",flush=True)
                    count+=1
        print("\n" + tabulate(results, headers=["ID", "Password", "Score", "Entropy", "Breaches", "Status"], tablefmt="grid"))
        print(f"\n\nAudit Complete! processed {count} employees")
        print(f"Report Generated: {output_file}")
    except FileNotFoundError:
        print(f"\nError! Could not find '{input_file}'.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
    
if __name__=="__main__":
    print_banner()
    print("1. Check a single password.")
    print("2. Bulk Audit")
    print("3. Employee CSV Audit")
    choice= int(input("\nEnter Choice(1-3): "))
    if choice==2:
        run_bulk_audit()
    elif choice==3:
        audit_csv_file()
    elif choice==1:
        password=input("Enter Password: ")
        breaches=check_breached_api(password)
        finscore, entropybits=check_password_complexity(password)
        print(f"FInal Score: {finscore} and Entropy Strength: {entropybits}")
        feedback=generate_feedback(finscore,entropybits,breaches)
        for i in feedback:
            print(i)
    else:
        print("Invalid Choice.")
    input("\nPress Enter to exit...")

