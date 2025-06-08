import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

def check_subdomain(subdomain):
    try:
        ip_address = socket.gethostbyname(subdomain)
        return subdomain, ip_address
    except socket.gaierror:
        return None, None

def main():
    parser = argparse.ArgumentParser(description="Subdomain Scanner - RON")
    parser.add_argument("-d", "--domain", required=True, help="Target domain, e.g., google.com")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file (subdomain dictionary).")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads to use (default: 50).")

    args = parser.parse_args()

    domain = args.domain
    wordlist_path = args.wordlist
    num_threads = args.threads

    found_subdomains = []

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            subdomains_to_check = [f"{line.strip()}.{domain}" for line in f if line.strip()]
            if not subdomains_to_check:
                print(f"[!] Error: The wordlist file '{wordlist_path}' is empty or improperly formatted.")
                sys.exit(1)
    except FileNotFoundError:
        print(f"[!] Error: Wordlist file not found at '{wordlist_path}'")
        sys.exit(1)

    print(f"[*] Starting scan on domain: {domain}")
    print(f"[*] Using {len(subdomains_to_check)} words from the wordlist with {num_threads} threads.")
    print("-" * 50)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(check_subdomain, sub) for sub in subdomains_to_check]
        
        for future in tqdm(as_completed(futures), total=len(subdomains_to_check), desc="Scanning"):
            result, ip = future.result()
            if result:
                print(f"\r[+] FOUND: {result} --> {ip}".ljust(60))
                found_subdomains.append(f"{result} --> {ip}")

    print("-" * 50)
    if found_subdomains:
        print(f"\n[*] Scan complete. Found {len(found_subdomains)} active subdomains:")
        for sub in sorted(found_subdomains):
            print(sub)
    else:
        print("\n[-] Scan complete. No active subdomains found using this wordlist.")

if __name__ == "__main__":
    main()
