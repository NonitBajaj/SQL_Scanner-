import requests
import argparse
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# ANSI color codes for prettier output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'

# (The GET-based functions: scan_error_based, scan_boolean_based, scan_time_based remain the same as before)
# ... You can paste the previous GET functions here ...

def scan_post_error_based(url, data_dict, param_to_test):
    """Scans for error-based SQL injection in POST requests."""
    print(f"{YELLOW}[*] Testing for Error-Based SQLi on POST parameter: {param_to_test}{RESET}")
    
    error_payloads = ["'", "\"", "')"]
    error_messages = [
        "you have an error in your sql syntax",
        "unclosed quotation mark", "warning: mysql",
        "sql command not properly ended"
    ]

    for payload in error_payloads:
        # Create a copy of the original data to modify
        injected_data = data_dict.copy()
        # Inject the payload into the parameter we want to test
        injected_data[param_to_test] = payload
        
        try:
            # Send the request using POST and the modified data
            res = requests.post(url, data=injected_data, timeout=10)
            
            for message in error_messages:
                if message in res.text.lower():
                    print(f"{GREEN}[+] Vulnerable to Error-Based SQLi (POST)!{RESET}")
                    print(f"  Parameter: {param_to_test}")
                    print(f"  Payload: {payload}")
                    return True # Vulnerability found
                    
        except requests.RequestException as e:
            print(f"{RED}[-] Error during request: {e}{RESET}")
            continue
            
    print(f"{RED}[-] Not vulnerable to Error-Based SQLi (POST).{RESET}")
    return False


def main():
    parser = argparse.ArgumentParser(description="A simple SQL Injection scanner for GET and POST.")
    parser.add_argument("-u", "--url", required=True, help="Full URL to test")
    
    # Arguments for POST requests
    parser.add_argument("--data", help="POST data string (e.g., 'user=test&pass=123')")
    parser.add_argument("--param", help="The POST parameter to test")
    
    args = parser.parse_args()

    # --- POST SCAN LOGIC ---
    if args.data:
        if not args.param:
            print(f"{RED}Error: --param is required when using --data.{RESET}")
            sys.exit(1)
            
        print(f"\n{YELLOW}--- Starting POST Scan on {args.url} ---{RESET}")
        # Convert the data string into a dictionary
        post_data_dict = dict(item.split('=') for item in args.data.split('&'))
        
        # Run the POST scanner
        scan_post_error_based(args.url, post_data_dict, args.param)

    # --- GET SCAN LOGIC ---
    else:
        parsed_url = urlparse(args.url)
        if not parsed_url.query:
            print(f"{RED}URL has no query parameters to test. For POST, use --data.{RESET}")
            sys.exit(1)
        
        print(f"\n{YELLOW}--- Starting GET Scan on {args.url} ---{RESET}")
        param_to_test = list(parse_qs(parsed_url.query).keys())[0]
        
        # For simplicity, we only show the error-based GET scan here.
        # You can add the boolean and time-based calls back if you wish.
        scan_error_based(args.url, param_to_test)


    print(f"{YELLOW}--- Scan Finished ---{RESET}\n")


if __name__ == "__main__":
    # Make sure you have the 'scan_error_based' function from the previous code
    # if you want the GET functionality to work.
    main()