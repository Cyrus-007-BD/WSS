import os
import sys
import platform
import threading
import dns.resolver # type: ignore
import requests
from bs4 import BeautifulSoup # type: ignore
import re
from queue import Queue
from colorama import init, Fore
import argparse
import time

# Initialize colorama for colored output
init(autoreset=True)

# Global set to store unique subdomains
subdomains = set()
admin_pages = []
# Mutex lock for thread safety
lock = threading.Lock()

# User-Agent for HTTP requests
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
}

# GitHub repository details for the update feature
GITHUB_REPO_URL = "https://raw.githubusercontent.com/Cyrus-007-BD/WSSDH/blob/main/WSSDH.py"
CURRENT_VERSION = "1.0"

def load_admin_paths_from_file(file_path="admin.txt"):
    """Load admin paths from the given file."""
    if not os.path.exists(file_path):
        print(Fore.RED + f"[ERROR] {file_path} does not exist.")
        return []
    
    with open(file_path, 'r') as file:
        admin_paths = [line.strip() for line in file.readlines() if line.strip() and not line.startswith('#')]
    
    return admin_paths

def load_custom_list(file_path):
    """Load a custom list of domains or subdomains from a provided file."""
    if not os.path.exists(file_path):
        print(Fore.RED + f"[ERROR] {file_path} does not exist.")
        return []
    
    with open(file_path, 'r') as file:
        items = [line.strip() for line in file.readlines() if line.strip()]
    
    return items

def fetch_crtsh(domain):
    """Fetch subdomains from crt.sh"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, headers=HEADERS)
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

def fetch_bing(domain):
    """Fetch subdomains from Bing search results"""
    url = f"https://www.bing.com/search?q=site%3A*.{domain}"
    try:
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                match = re.search(r"https?://([a-zA-Z0-9.-]+\." + re.escape(domain) + ")", href)
                if match:
                    with lock:
                        subdomains.add(match.group(1))
            print(Fore.GREEN + "[+] Fetched from Bing")
        else:
            print(Fore.RED + f"[-] Bing request failed with status code {response.status_code}")
    except Exception as e:
        print(Fore.RED + f"[Error] fetching Bing: {e}")

def fetch_duckduckgo(domain):
    """Fetch subdomains from DuckDuckGo search results"""
    url = f"https://duckduckgo.com/html/?q=site%3A*.{domain}"
    try:
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            for result in soup.find_all("a", href=True):
                href = result["href"]
                match = re.search(r"https?://([a-zA-Z0-9.-]+\." + re.escape(domain) + ")", href)
                if match:
                    with lock:
                        subdomains.add(match.group(1))
            print(Fore.GREEN + "[+] Fetched from DuckDuckGo")
        else:
            print(Fore.RED + f"[-] DuckDuckGo request failed with status code {response.status_code}")
    except Exception as e:
        print(Fore.RED + f"[Error] fetching DuckDuckGo: {e}")

def fetch_wordlist_subdomains(domain, wordlist_file="subdomains.txt"):
    """Fetch subdomains from a local wordlist using DNS resolution"""
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
                print(Fore.YELLOW + f"[+] Found: " + Fore.RED + f"{subdomain} -> {answer}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.resolver.LifetimeTimeout:
            print(Fore.RED + f"[!] Timeout querying {subdomain}")
        except KeyboardInterrupt:
            print("\n[!] Stopped by user.")
            sys.exit(0)

def enumerate_subdomains(domain):
    """Main function to enumerate subdomains using multiple sources"""
    print(Fore.CYAN + f"[INFO] Enumerating subdomains for: {domain}")

    # List of enumeration functions
    sources = [fetch_crtsh, fetch_bing, fetch_duckduckgo]

    # Create threads for each source
    threads = []
    for source in sources:
        thread = threading.Thread(target=source, args=(domain,))
        threads.append(thread)
        thread.start()

    # Start DNS-based subdomain enumeration
    fetch_wordlist_subdomains(domain)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Display unique subdomains
    if subdomains:
        print(Fore.YELLOW + "\n[RESULT] Found subdomains:")
        for sub in sorted(subdomains):
            print(Fore.YELLOW + "[+] Found: " + Fore.RED + sub)
    else:
        print(Fore.RED + "[!] No subdomains found.")

# Function to check if admin page exists
def check_admin_page(url, path):
    """Function to check if admin page exists"""
    admin_url = url + path
    try:
        response = requests.get(admin_url, timeout=5)
        if response.status_code == 200:
            print(Fore.GREEN + f"[+] Found admin page: {admin_url}")
        elif response.status_code == 403:
            print(Fore.YELLOW + f"[+] Admin page found but access denied: {admin_url}")
        elif response.status_code == 301 or response.status_code == 302:
            print(Fore.CYAN + f"[+] Redirected to admin page: {admin_url}")
        else:
            print(Fore.RED + f"[-] No admin page found at: {admin_url}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[Error] checking {admin_url}: {e}")

def check_admins_on_domain(domain, admin_paths=None):
    """Search for admin pages using provided paths or fallback to admin.txt."""
    print(Fore.CYAN + f"\n\n[INFO] Starting admin page search on {domain}")
    
    # Use provided admin paths or load from admin.txt if not provided
    if admin_paths is None or not admin_paths:
        admin_paths = load_admin_paths_from_file()
    
    if not admin_paths:
        print(Fore.RED + "[ERROR] No admin paths found.")
        return

    # Loop through each admin path and check if it exists
    for path in admin_paths:
        check_admin_page(domain, path)

# Function to ensure the domain starts with http:// or https://
def add_https_www(url):
    # Check if the URL starts with http:// or https://, if not, add https://www
    if not re.match(r'^https?://', url):
        url = 'https://www.' + url
    elif url.startswith('http://') or url.startswith('https://'):
        # If the URL already starts with http or https, ensure 'www' is included
        if 'www.' not in url:
            url = url.replace('http://', 'http://www.').replace('https://', 'https://www.')
    return url

def process_file(file_path, mode, custom_list=None):
    """Process a list of domains from a file with optional custom lists."""
    if not os.path.isfile(file_path):
        print(Fore.RED + f"[ERROR] File '{file_path}' not found.")
        sys.exit(1)

    # Load custom admin paths if provided
    admin_paths = load_admin_paths_from_file(custom_list) if mode == "admin" and custom_list else None

    with open(file_path, 'r') as file:
        domains = [line.strip() for line in file if line.strip()]

    for domain in domains:
        clear_terminal()
        print(Fore.CYAN + f"[INFO] Processing domain: {domain}")

        if mode == "subdomain":
            enumerate_subdomains(domain)
        elif mode == "admin":
            check_admins_on_domain(f"https://{domain}", admin_paths)
        subdomains.clear()
        admin_pages.clear()
        time.sleep(2)  # Pause briefly before processing the next 

def print_banner():
    import pyfiglet 
    result = pyfiglet.figlet_format("WSASDH", font = "big", justify="left", width=5000)
    print (Fore.RED + result + "\t\t\t\t\t--v0.1--")
    print(Fore.RED + "WSASDH - Web Subdomain Admin Search and Discovery Helper")
    print(Fore.RED + "Discover subdomains and admin paths quickly and efficiently!")
    print(Fore.RED + "Author: Cyrus_007")

def clear_terminal():
    # Clear the terminal based on the platform
    system = platform.system().lower()
    if system == "windows":
        os.system('cls')
    else:
        os.system('clear')

def check_for_update():
    """Check for updates from the GitHub repository"""
    try:
        print(Fore.CYAN + "\n[INFO] Checking for updates...")
        response = requests.get(GITHUB_REPO_URL, headers=HEADERS)
        if response.status_code == 200:
            with open(__file__, 'r') as current_file:
                current_content = current_file.read()
            latest_content = response.text
            if latest_content != current_content:
                print(Fore.YELLOW + "[INFO] New update found! Updating...")
                with open(__file__, 'w') as current_file:
                    current_file.write(latest_content)
                print(Fore.GREEN + "[+] Update successful! Please restart the script.")
                sys.exit(0)
            else:
                print(Fore.GREEN + "[INFO] You are using the latest version.")
        else:
            print(Fore.RED + f"[Failed] to check for updates (status code: {response.status_code})")
    except Exception as e:
        print(Fore.RED + f"[Error] checking for updates: {e}")

if __name__ == "__main__":
    clear_terminal()
    print_banner()
    check_for_update()

    print("\n")

    parser = argparse.ArgumentParser(
        epilog="A subdomain and admin page enumeration tool without API keys.",
        usage="\npython3 WSASDH.py -s example.com \npython3 WSASDH.py -a example.com"
    )
    parser.add_argument("-s", "--subdomain", help="Enumerate subdomains for a given domain", metavar="")
    parser.add_argument("-a", "--admin", help="Search for admin pages on a given domain", metavar="")
    args = parser.parse_args()

    if args.subdomain:
        enumerate_subdomains(args.subdomain)
    elif args.admin:
        check_admins_on_domain(f"https://{args.admin}", load_admin_paths_from_file())
    else:
        print(Fore.RED + "[!] Please specify either -s for subdomain search or -a for admin page search.")
        sys.exit(1)
