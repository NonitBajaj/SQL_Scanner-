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