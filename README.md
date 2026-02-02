<div align="center">
  
<img src="assets/logo.png" alt="SQLScan Logo" width="300">

# SQLScan

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Focus-Web--Security-red?style=for-the-badge)](https://en.wikipedia.org/wiki/Web_application_security)
[![Stars](https://img.shields.io/github/stars/pangeran-droid/sqlscan?style=for-the-badge&color=yellow)](https://github.com/pangeran-droid/sqlscan/stargazers)

**SQLScan** is a lightweight Python-based **SQL Injection scanner** focused on  
**GET parameter testing** using classic detection techniques.

</div>

---

## Overview

SQLScan is designed to quickly identify common SQL Injection vulnerabilities
in URL parameters with clear, readable terminal output.

Supported detection techniques:
- Error-Based SQL Injection
- Boolean-Based SQL Injection
- Time-Based (Blind) SQL Injection

---

## Features

- **Error-Based SQL Injection**
  - Detects database error messages
  - Supported DBs:
    - MySQL / MariaDB
    - PostgreSQL
    - Microsoft SQL Server

- **Boolean-Based SQL Injection**
  - Compares response length differences (`OR 1=1` vs `OR 1=2`)

- **Time-Based SQL Injection**
  - Uses delay payloads (`SLEEP`, `pg_sleep`, `WAITFOR`)
  - Double verification (3s & 7s delay)

- **Multiple Target Support**
  - Scan a single URL
  - Scan multiple targets from a file

- **Clean Terminal Output**
  - Colored status indicators
  - Per‑parameter testing
  - Per‑target progress display

---

## Installation

```bash
git clone https://github.com/pangeran-droid/sqlscan.git
cd sqlscan
pip install -r requirements.txt
```

---

## Usage

```text
               __                    
   _________ _/ /_____________ _____ 
  / ___/ __ `/ / ___/ ___/ __ `/ __ \ 1.0
 (__  ) /_/ / (__  ) /__/ /_/ / / / /
/____/\__, /_/____/\___/\__,_/_/ /_/ 
|-------/_/=======]--------------->


usage: python3 sqlscan.py [options]

options:
  -h, --help       show this help message and exit
  -u, --url URL    Target URL (example: http://site.com/page.php?id=1)
  -l, --list LIST  Scan multiple targets from file (example: targets.txt)
  -v, --version    Show program version
                                            
```
---

## Examples

### Scan a single URL
```bash
python3 sqlscan.py "http://example.com/page.php?id=1"
```

### Scan multiple targets from file
target.txt
```text
http://site1.com/item.php?id=1
http://site2.com/view.php?id=5
http://site3.com/page.php?cat=2
```

```bash
python3 sqlscan.py -l targets.txt
```

---

## Output example

```text
[TARGET 1/1] http://site1.com/item.php?id=1

[START] Target: http://site1.com/item.php
[INFO] Parameters found: id

============================================================
[TEST] Parameter: id
============================================================
  [VULN] MySQL Error-Based SQL Injection detected!
  [INFO] Boolean-Based indication detected
      [INFO] Verifying MySQL Time-Based (double check)
      [OK] Delay 3s confirmed
      [OK] Delay 7s confirmed
  [VULN] MySQL Time-Based SQL Injection CONFIRMED

[DONE] Scan finished
```

---

## Project Structure

```text
sqlscan/
├── sqlscan.py
├── requirements.txt
├── assets/
│   └── logo.png
└── README.md
```

---

## Disclaimer

This tool is **for educational and authorized security testing only**.

Use SQLScan **only on systems you own or have explicit permission to test**.

The author is not responsible for any misuse or damage caused by this tool.

---

## Lisensi

MIT License © 2026 Pangeran
