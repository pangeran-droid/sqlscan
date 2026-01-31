<div align="center">

<img src="assets/logo.png" alt="SQLScan Logo" width="300">

# SQLScan

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

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

### Scan with time-based SQLi + headers
```bash
python3 sqlscan.py "http://example.com/page.php?id=1" -t -H
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

### Scan a Burp Suite request file
```bash
python3 sqlscan.py -b request.txt -t -H -a
```

---

## Output example

```bash
TARGET 1/3] http://testphp.vulnweb.com/listproducts.php?cat=1

[START] Target: http://testphp.vulnweb.com/listproducts.php
[INFO] Parameters found: cat

============================================================
[TEST] Parameter: cat
============================================================
  [VULN] MySQL Error-Based SQL Injection detected!

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
