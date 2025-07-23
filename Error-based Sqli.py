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