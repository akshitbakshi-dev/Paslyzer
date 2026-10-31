#  PASLYZER

**Advanced password security auditor — CLI tool for Python 3**

![Python](https://img.shields.io/badge/python-3.x-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Version](https://img.shields.io/badge/version-1.0-informational)

PASLYZER is a command-line password security auditor that combines structural complexity rules, Shannon entropy calculations, and real-world breach intelligence from the Have I Been Pwned (HIBP) database. It audits a single password, a bulk list of passwords, or an employee CSV file, and reports risk in color-coded terminal tables.

It is built as a red-team style audit utility: something a system administrator can run against an organization's credentials to find weak passwords before an attacker does.

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [Future Scope](#future-scope)
- [License](#license)

## Features

| Mode | Input | What it does | Output |
| --- | --- | --- | --- |
| Single password | Password typed at the prompt | Complexity score (0-5), entropy in bits, HIBP breach lookup | Score, entropy, and feedback printed to the console |
| Bulk file audit | A text file of passwords, one per line | Scores every line with the same checks, with a progress dot per line | Plain-text `audit_report.txt` with status, score, entropy, and breach count per password |
| CSV identity audit | An employee CSV file | Auto-detects the password column by header name (or asks if it can't); scores each row | Color-coded summary table in the terminal, plus a `<filename>_Report.csv` linking each employee ID to its risk rating |

Also included: a `pyfiglet` ASCII startup banner and `tabulate`-formatted report tables.

## How It Works

**Entropy.** Password strength is estimated with Shannon entropy, `E = L × log2(R)`, where `L` is password length and `R` is the size of the character pool used. More bits means more guesses an attacker needs.

**Breach detection.** PASLYZER checks the HIBP Pwned Passwords API using k-Anonymity: the password is hashed locally with SHA-1, and only the first 5 characters of that hash are sent to the API. The API returns every matching hash suffix and its breach count, and PASLYZER matches the rest locally. The full password, and its full hash, never leave your machine.

## Installation

```bash
git clone https://github.com/akshitbakshi-dev/paslyzer.git
cd paslyzer
pip install -r requirements.txt
```

## Usage

PASLYZER is menu-driven. Run it, then pick an option:

```bash
python paslyzer.py
```

```
1. Check a single password.
2. Bulk Audit
3. Employee CSV Audit
```

**1. Single password** — enter a password when prompted. PASLYZER prints its score out of 5, entropy in bits, and whether it has appeared in a known breach.

**2. Bulk Audit** — enter the filename of a `.txt` file containing one password per line (the `.txt` extension is added automatically if you leave it off). Results are written to `audit_report.txt` in the same folder.

**3. Employee CSV Audit** — enter the filename of a `.csv` file. PASLYZER looks for a column with "password" in its header; if it can't find one, it lists the available columns and asks you to pick. Results print as a color-coded table and are saved to `<filename>_Report.csv`.

## Project Structure

```
paslyzer/
├── paslyzer.py          # entry point / CLI
├── requirements.txt
├── LICENSE
├── README.md
└── .gitignore
```

## Tech Stack

- **Core:** Python 3, `math`, `string`
- **Cryptography:** `hashlib` (SHA-1 for k-Anonymity)
- **Network:** `requests` (HIBP API)
- **Data handling:** `csv`
- **CLI/UX:** `colorama`, `tabulate`, `pyfiglet`

## Future Scope

- Graphical interface (desktop or web)
- PDF export of audit reports
- Password reuse detection across accounts
- Active Directory / LDAP integration
- Scheduled, recurring audits
- REST API wrapper for integration with other security tooling

## License

Released under the [MIT License](LICENSE).

## Author

**Akshit Bakshi**
[www.linkedin.com/in/akshit-bakshi-89aa28331] · [https://github.com/akshitbakshi-dev]
