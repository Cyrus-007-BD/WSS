import os
import sys
import platform
import threading
import dns.resolver  # type: ignore
import requests
from bs4 import BeautifulSoup  # type: ignore
import re
import argparse
import time
from queue import Queue
from colorama import init, Fore

# Initialize colorama for colored output
init(autoreset=True)

# Global storage for results
subdomains = set()
admin_pages = []
lock = threading.Lock()

# User-Agent for HTTP requests
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
}

def load_admin_paths_from_file(file_path="admin.txt"):
    """Load admin paths from a given file."""
    if not os.path.exists(file_path):
        print(Fore.RED + f"[ERROR] {file_path} does not exist.")
        return []
    
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines() if line.strip() and not line.startswith('#')]

def fetch_crtsh(domain):
    """Fetch subdomains from crt.sh"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    if sub.endswith(domain):
                        with lock:
                            subdomains.add(sub.strip())
            print(Fore.GREEN + "[+] Fetched from crt.sh")
        else:
            print(Fore.RED + f"[-] crt.sh request failed with status code {response.status_code}")
    except Exception as e:
        print(Fore.RED + f"[Error] fetching crt.sh: {e}")

def fetch_search_engine(domain, engine):
    """Fetch subdomains from search engines (Bing, DuckDuckGo)"""
    urls = {
        "bing": f"https://www.bing.com/search?q=site%3A*.{domain}",
        "duckduckgo": f"https://duckduckgo.com/html/?q=site%3A*.{domain}"
    }
    
    try:
        response = requests.get(urls[engine], headers=HEADERS, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            for link in soup.find_all("a", href=True):
                match = re.search(r"https?://([a-zA-Z0-9.-]+\." + re.escape(domain) + ")", link["href"])
                if match:
                    with lock:
                        subdomains.add(match.group(1))
            print(Fore.GREEN + f"[+] Fetched from {engine}")
        else:
            print(Fore.RED + f"[-] {engine} request failed with status code {response.status_code}")
    except Exception as e:
        print(Fore.RED + f"[Error] fetching {engine}: {e}")

def fetch_wordlist_subdomains(domain, wordlist_file="subdomains.txt"):
    """Fetch subdomains from a wordlist using DNS resolution"""
    if not os.path.isfile(wordlist_file):
        print(Fore.RED + f"[!] Wordlist file '{wordlist_file}' not found.")
        return

    try:
        with open(wordlist_file, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(Fore.RED + f"[!] Error reading the wordlist file: {e}")
        return

    print(Fore.CYAN + "[INFO] Enumerating subdomains using DNS resolution...")

    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            for answer in answers:
                with lock:
                    subdomains.add(subdomain)
                print(Fore.YELLOW + f"[+] Found: {subdomain} -> {answer}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.resolver.LifetimeTimeout:
            print(Fore.RED + f"[!] Timeout querying {subdomain}")

def enumerate_subdomains(domain):
    """Enumerate subdomains using multiple sources"""
    print(Fore.CYAN + f"[INFO] Enumerating subdomains for: {domain}")

    sources = [
        lambda: fetch_crtsh(domain),
        lambda: fetch_search_engine(domain, "bing"),
        lambda: fetch_search_engine(domain, "duckduckgo")
    ]

    threads = [threading.Thread(target=source) for source in sources]

    for thread in threads:
        thread.start()

    fetch_wordlist_subdomains(domain)

    for thread in threads:
        thread.join()

    if subdomains:
        print(Fore.YELLOW + "\n[RESULT] Found subdomains:")
        for sub in sorted(subdomains):
            print(Fore.YELLOW + "[+] Found: " + Fore.RED + sub)
    else:
        print(Fore.RED + "[!] No subdomains found.")

def check_admin_page(url, path):
    """Check if an admin page exists"""
    admin_url = url + path
    try:
        response = requests.get(admin_url, timeout=5)
        if response.status_code == 200:
            print(Fore.GREEN + f"[+] Found admin page: {admin_url}")
        elif response.status_code == 403:
            print(Fore.YELLOW + f"[+] Admin page found but access denied: {admin_url}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[Error] checking {admin_url}: {e}")

def check_admins_on_domain(domain):
    """Search for admin pages"""
    print(Fore.CYAN + f"\n[INFO] Searching for admin pages on {domain}")

    admin_paths = load_admin_paths_from_file()
    if not admin_paths:
        print(Fore.RED + "[ERROR] No admin paths found.")
        return

    for path in admin_paths:
        check_admin_page(domain, path)

def add_https_www(url):
    """Ensure URL starts with https:// and www"""
    if not re.match(r'^https?://', url):
        url = 'https://www.' + url
    return url

def print_banner():
    try:
        import pyfiglet
        result = pyfiglet.figlet_format("WSS", font="big", justify="left", width=5000)
        print(Fore.WHITE + result + "\t\t\t\t\t--v0.1--")
    except ImportError:
        print(Fore.CYAN + "WSS - Web Security Scanner")
    
    print(Fore.CYAN + "Discover subdomains and admin paths quickly and efficiently!")
    print(Fore.CYAN + "Author: Cyrus_007")

def clear_terminal():
    """Clear terminal screen"""
    os.system('cls' if platform.system().lower() == "windows" else 'clear')

if __name__ == "__main__":
    clear_terminal()
    print_banner()

    parser = argparse.ArgumentParser(description="Web Security Scanner - Find subdomains & admin pages")
    parser.add_argument("-s", "--subdomain", metavar="DOMAIN", help="Enumerate subdomains for a given domain")
    parser.add_argument("-a", "--admin", metavar="DOMAIN", help="Search for admin pages on a given domain")
    args = parser.parse_args()

    if args.subdomain:
        enumerate_subdomains(args.subdomain)
    elif args.admin:
        check_admins_on_domain(f"https://{args.admin}")
    else:
        print(Fore.RED + "[!] Please specify either -s for subdomain search or -a for admin page search.")
        sys.exit(1)
