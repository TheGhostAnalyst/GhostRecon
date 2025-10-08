from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import time
import warnings
import random
from datetime import datetime
import re
import pyinputplus as pyip
from colorama import init, Fore, Style
import socket
import sys
import os
import subprocess
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import phonenumbers
from phonenumbers import timezone, PhoneNumberType
from phonenumbers import geocoder
from phonenumbers import carrier
from phonenumbers import NumberParseException

init()
warnings.filterwarnings("ignore")

# Global proxy (Tor)
PROXIES = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def scan_num(number):
    num_reg = re.compile(r"^\+\d{1,2}\s?[-.]?\d{2,3}\s?[-.]?\d{2,3}\s?[-.]?\d{2,4}")
    try:
        if num_reg.match(number):
            phone_no = phonenumbers.parse(number)
            country_code = phone_no.country_code
            national_num = phone_no.national_number
            time_zone = timezone.time_zones_for_number(phone_no)
            location = geocoder.description_for_number(phone_no, "en")
            service_prov = carrier.name_for_number(phone_no, "en")
            is_valid = phonenumbers.is_valid_number(phone_no)
            is_poss = phonenumbers.is_possible_number(phone_no)
            num_type = phonenumbers.number_type(phone_no)

            # readable number type map
            type_map = {
                PhoneNumberType.FIXED_LINE: "Fixed Line",
                PhoneNumberType.MOBILE: "Mobile",
                PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
                PhoneNumberType.TOLL_FREE: "Toll Free",
                PhoneNumberType.PREMIUM_RATE: "Premium Rate",
                PhoneNumberType.SHARED_COST: "Shared Cost",
                PhoneNumberType.VOIP: "VoIP",
                PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
                PhoneNumberType.PAGER: "Pager",
                PhoneNumberType.UAN: "Universal Access Number",
                PhoneNumberType.VOICEMAIL: "Voicemail",
                PhoneNumberType.UNKNOWN: "Unknown"
            }

            readable_type = type_map.get(num_type, "Unknown")

            print(f"Country Code: {country_code}")
            print(f"National Number: {national_num}")
            print(f"Timezone: {time_zone}")
            print(f"Location: {location}")
            print(f"Service provider: {service_prov}")
            print(f"Is Valid Number: {is_valid}")
            print(f"Is Possible Number: {is_poss}")
            print(f"Number Type: {readable_type}")

            seperator = '=' * 80
            with open('Number_Scan.txt', 'a') as f:
                f.write(f"\n{seperator}\n")
                f.write(f"Country Code: {country_code}\n")
                f.write(f"National Number: {national_num}\n")
                f.write(f"Timezone: {time_zone}\n")
                f.write(f"Location: {location}\n")
                f.write(f"Service provider: {service_prov}\n")
                f.write(f"Is Valid Number: {is_valid}\n")
                f.write(f"Is Possible Number: {is_poss}\n")
                f.write(f"Number Type: {readable_type}\n")

            print("\n✅ Scan saved to Number_Scan.txt")
            time.sleep(1)

        else:
            print(f"❌ Invalid number format: {number}")
    except NumberParseException as e:
        print(f"⚠️ Error parsing number: {e}")
        return
    

def get_whois_info(domain):                    
    result = subprocess.run(
        ['whois', domain], # runs the terminal command: whois domain.com
        stdout=subprocess.PIPE, # captures the normal output (instead of printing it directly)
        stderr=subprocess.PIPE, # captures the error output (if something goes wrong)
        text=True # makes sure output is in string form (not raw bytes)
    )

    if result.stderr:
        print(f"Error: {result.stderr}")
    else:
        return result.stdout


def extract_relevant_info(domain, whois_data):
    registrar_regex = re.compile(r"(Registrar.*?)(DNSSEC)", re.DOTALL) # match everything between Registrar and DNSSEC
    registrant_regex = re.compile(r"(Registrant.*?)(Name Server)", re.DOTALL) # <same as above> with re.DOTALL matching . and \n

    registrar_info = registrar_regex.search(whois_data)
    registrant_info = registrant_regex.search(whois_data)

    registrar_data = registrar_info.group(1) if registrar_info else "Registrar info not found."
    registrant_data = registrant_info.group(1) if registrant_info else "Registrant info not found."

    print(f"\n[+] Whois results for {domain}")
    print("Registrar Info:")
    print(registrar_data)
    print("\nRegistrant Info:")
    print(registrant_data)

    seperator = '=' * 120
    now = datetime.now().strftime('%Y:%m:%d %H:%M:%S')
    with open('domain_whois.txt', 'a') as f:
        f.write(f'{seperator}\n')
        f.write(f'[+] Timestamp: {now}\n')
        f.write(f'[+] Whois scan on {domain}:\n')
        f.write("[+] Registrar Info:\n")
        f.write(f"{registrar_data}\n")
        f.write("\n[+] Registrant Info:\n")
        f.write(f'{registrant_data}\n')
        f.write(f'{seperator}\n\n')

def subdomain_scan(domain):
    """
    Extracts subdomains from crt.sh JSON endpoint and optionally validates them.
    """
    ua = UserAgent()
    headers = {'User-Agent': ua.random}
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    seen, found, final_found = set(), [], []

    print(f'[+] Checking crt.sh for subdomains of {domain}...........')

    # retry setup
    # wait_time = backoff_factor× 2^(retry_number−1)
    retries = Retry(
    total=3,                # max retries
    backoff_factor=1,       # exponential backoff factor
    status_forcelist=[429, 500, 502, 503, 504]  # which HTTP status codes to retry
    )

    adapter = HTTPAdapter(max_retries=retries) # Connector that enforces retry behavior when making HTTP/HTTPS calls.
    s = requests.Session()
    s.headers.update(headers)
    s.mount("https://", adapter) # apply to https
    s.mount("http://", adapter) # apply to https

    try:
        res = s.get(url, timeout=20)
        if res.status_code == 200:
            print(f'Status Code: {res.status_code}')
            try:
                data = res.json() # parse into json format
            except ValueError:
                print(Fore.RED + "[!] Response was not JSON. crt.sh may have blocked you." + Fore.RESET)
                return found, final_found

            for cert in data:
                regex = re.compile(r'(?!.*@)[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
                match = cert.get('name_value') or cert.get('common_name')
                if not match:
                    continue
                for m in match.splitlines():   # split a multi-line string into separate lines
                    m = m.strip()              # remove surrounding whitespace (spaces, tabs, newlines)
                    if not m:                  # skip empty lines (after strip)
                        continue

                    if regex.match(m):
                        if m and m not in seen:
                            seen.add(m)
                            found.append(m)
                            print(Fore.GREEN + f'[+] Found subdomain: {m}')
                            try:
                                ip = socket.gethostbyname(m)
                                final_found.append((m, ip))
                                print(Fore.GREEN + f"[+] Valid Subdomain: {m} -> {ip}")
                            except socket.gaierror:
                                print(Fore.RED + f"[!] Could not resolve: {m}")
                                continue               # skip to next subdomain
                            except Exception as e:
                                print(Fore.RED + f"[!] DNS error for {m}: {e}")
                                continue
                            time.sleep(random.uniform(1, 2))
        else:
            print("An error occurred with status code:", res.status_code)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Failed to get {domain}: {e}")


    print(Fore.CYAN + f"[+] Total found: {len(found)} | Valid: {len(final_found)}")
    length = len(final_found)
    if final_found:
        print(Fore.RED + f'\n[+] Found {length} valid subdomains (200 OK). Saved in Subdomain_Scans.txt')
    seperator = '=' * 120
    now = datetime.now().strftime('%Y:%m:%d %H:%M:%S')
    if final_found:
        with open('Subdomain_Scans.txt', 'a') as f:
            f.write(f'{seperator}\n')
            f.write(f'Timestamp: {now}\n')
            f.write(f'Subdomain Scan for {domain} completed. Found {length} valid subdomains.\n')
            for m, ip in final_found:
                f.write(f'{m} --> {ip}\n')
            f.write(f'{seperator}\n\n')


def scan_directories(domain):
    found, seen = [], set()
    with open('directories.txt', 'r') as f:
        directories = [line.strip() for line in f if line.strip()]

    if not domain.startswith('https://'):
        domain = f'https://{domain}'
    if not domain.endswith('/'):
        domain += '/'
    proxies = {'http': 'socks5h://127.0.0.1:9050',
               'https': 'socks5h://127.0.0.1:9050'}
    session = requests.session()
    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    for dir in directories:
        url = domain + dir
        try:
            headers = {'User-Agent': UserAgent().random}
            session.headers.update(headers)
            session.proxies.update(proxies)
            print(Fore.GREEN + f'[+] Scanning {url}........')
            resp = session.get(url, timeout=(3, 8))
            status, title = resp.status_code, "N/A"

            if status == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                title_tag = soup.find("title")
                title = title_tag.text.strip() if title_tag else "No title"
                if url not in seen:
                    found.append((url, title))
                    seen.add(url)
                    print(f'[+] Found: {url} (200 OK) Title: {title}')
            elif status == 403:
                print(Fore.BLUE + f"[-] Forbidden: {url} (403)")
            elif status == 404:
                print(Fore.RED + f"[x] Not found: {url} (404)")
            elif status in {301, 302}:
                print(Fore.BLUE + f"[!] Redirected: {url} ({status})")
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[!] Error fetching {domain}: {e}")
    seperator = '=' * 120
    now = datetime.now().strftime('%Y:%m:%d %H:%M:%S')
    if found:
        print(Fore.RED + f"\n[+] Found {len(found)} directories. Saved in Directory_Scans.txt")
        with open('Directory_Scans.txt', 'a') as f:
            f.write(f'{seperator}\n')
            f.write(f'Timestamp: {now}\n')
            f.write(f"Found {len(found)} directories for {domain}\n")
            for url, title in found:
                f.write(f'{url} ---- Title: {title}\n')
            f.write(f'{seperator}\n\n')
    else:
        print(Fore.YELLOW + "\n[-] No directories found.")



def extract_links(domain):
    """
    Extracts valid HTTP/HTTPS links from a domain, handles retries, timeouts, proxies, and saves results.
    """
    found, seen = [], set()
    if not domain.startswith(('http://', 'https://')):
        domain = f'https://{domain}'

    try:
        # -----------------------------
        # Session setup
        # -----------------------------
        s = requests.Session()
        s.headers.update({'User-Agent': UserAgent().random})
        proxies = {'http': 'socks5h://127.0.0.1:9050',
               'https': 'socks5h://127.0.0.1:9050'}
        if proxies:
            s.proxies.update(proxies)

        retries = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retries)
        s.mount("http://", adapter)
        s.mount("https://", adapter)

        # -----------------------------
        # Fetch domain page
        # -----------------------------
        res = s.get(domain, timeout=(3, 10))
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")
        print(f'\n[+] Extracting links from {domain}...')

        # -----------------------------
        # Parse links and validate
        # -----------------------------
        for a in soup.find_all('a', href=True):
            final_link = urljoin(domain, a['href'])
            if final_link not in seen and final_link.startswith(('http://', 'https://')):
                seen.add(final_link)
                try:
                    resp = s.get(final_link, timeout=(3, 10))
                    resp.raise_for_status()
                    found.append(final_link)
                    print(Fore.GREEN + f'[+] Valid link: {final_link}')
                except requests.exceptions.RequestException as e:
                    print(Fore.RED + f"[!] Failed after retries: {e}")

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[!] Error fetching {domain}: {e}")

    # -----------------------------
    # Save results to file
    # -----------------------------
    separator = '=' * 120
    now = datetime.now().strftime('%Y:%m:%d %H:%M:%S')
    print(Fore.RED + f'\n[+] Found {len(found)} unique links. Saved in Domain_Links.txt')

    if found:
        with open('Domain_Links.txt', 'a') as f:
            f.write(f'{separator}\n')
            f.write(f'Timestamp: {now}\n')
            f.write(f'Found {len(found)} unique tested links in {domain}\n')
            for link in found:
                f.write(f'{link}\n')
            f.write(f'{separator}\n\n')


def get_ipaddr(ip):
    url = f'https://ipinfo.io/{ip}/json'
    try:
        resp = requests.get(url, proxies=PROXIES, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            print(f"\n[+] IP info for {ip}")
            print(f"IP: {data.get('ip')}")
            print(f"Hostname: {data.get('hostname', 'N/A')}")
            print(f"City: {data.get('city', 'N/A')}")
            print(f"Region: {data.get('region', 'N/A')}")
            print(f"Country: {data.get('country', 'N/A')}")
            print(f"Org: {data.get('org', 'N/A')}")
            print(f"Location: {data.get('loc', 'N/A')}")
            print(f"ASN: {data.get('asn', 'N/A')}")
            print(f"Postal Code: {data.get('postal', 'N/A')}")
            print(f"Timezone: {data.get('timezone', 'N/A')}")

            seperator = '=' * 120
            now = datetime.now().strftime('%Y:%m:%d %H:%M:%S')
            with open('ip_addr.txt', 'a') as f:
                f.write(f'{seperator}\n')
                f.write(f'[+] Timestamp: {now}\n')
                for k, v in data.items():
                    f.write(f"[+] {k}: {v}\n")
                f.write(f'{seperator}\n\n')
    except Exception as e:
        print(Fore.RED + f"[!] Error fetching IP info: {e}")


def getdomain_ipaddr(domain):
    clean_domain = domain.replace("https://", "").replace("http://", "")
    try:
        ip_address = socket.gethostbyname(clean_domain)
        print(f"\n[+] {domain} resolves to {ip_address}")
    except Exception as e:
        print(Fore.RED + f"[!] Could not resolve {domain}: {e}")
    seperator = '=' * 120
    with open('domain_addr.txt', 'a') as f:
        f.write(f'{seperator}\n')
        f.write(f"[+] {domain} resolves to {ip_address}\n")
        f.write(f'{seperator}\n\n')


def dns_lookup(ip):
    try:
        lookup = socket.gethostbyaddr(ip)
        print(f"[+] Scanning {ip}.........")
        if lookup:
            hostname, aliases, related_ips = lookup[0], lookup[1], lookup[2]
            print(f"[+] The Primary hostname for {ip} is {hostname}")
            print(f"[+] Alias: {aliases if aliases else 'N/A'}")
            print(f"[+] Associated IP's: {related_ips}")

            # Forward lookup
            try:
                forward_ip = socket.gethostbyname_ex(hostname)[2]  # list of IPs
            except Exception as e:
                forward_ip = []
                print(f"[!] Could not forward-resolve {hostname}: {e}")

            # Write results to file
            separator = "=" * 120
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open('hostnames.txt', 'a', encoding="utf-8") as f:
                f.write(f"{separator}\n")
                f.write(f"[+] Timestamp: {now}\n")
                f.write(f"[+] The Primary hostname for {ip} is {hostname}\n")
                f.write(f"[+] Alias: {aliases if aliases else 'N/A'}\n")
                f.write(f"[+] Associated IP's: {related_ips}\n")
                if forward_ip:
                    f.write(f"[+] Hostname resolves to: {forward_ip}\n")
                    print(f"[+] Hostname resolves to: {forward_ip}")
                    if ip not in forward_ip:
                        f.write(f"[!] Mismatch! Hostname resolves to: {forward_ip}, but original IP was {ip}\n")
                        print(f"[!] Mismatch! Hostname resolves to: {forward_ip}, but original IP was {ip}\n")
                else:
                    f.write(f"[!] Forward lookup failed or mismatch for {hostname}\n")
                f.write(f"{separator}\n\n")  # add separator at the end of each entry

        time.sleep(3)

    except socket.herror:
        print(f"[!] No reverse DNS found for IP {ip}")
        time.sleep(3)
        return None





# Main menu
try:
    while True:
        print(Fore.GREEN + Style.BRIGHT + """
  ____ _               _     ____                      
 / ___| |__   ___  ___| |_  |  _ \ ___  ___ ___  _ __  
| |  _| '_ \ / _ \/ __| __| | |_) / _ \/ __/ _ \| '_ \ 
| |_| | | | | (_) \__ \ |_  |  _ <  __/ (_| (_) | | | |
 \____|_| |_|\___/|___/\__| |_| \_\___|\___\___/|_| |_|
                                                       
   [==== HACK THE PLANET ====]

credits: The Ghost Analyst

--- Saved Output Files ---
[1] Subdomain Scan   → Subdomain_Scans.txt
[2] Directory Scan   → Directory_Scans.txt
[3] Extract Links    → Domain_Links.txt
[4] IP Info (IP)     → ip_addr.txt
[5] IP Info (Domain) → domain_addr.txt
[6] Reverse DNS Lookup → hostnames.txt      
[7] Whois Scan       → domain_whois.txt
[8] Phone Number Scan → Number_Scan.txt
----------------------------
""")
        ask = pyip.inputNum("""Make a choice:
1. Subdomain Scan
2. Directory Scan
3. Extract Links
4. IP Info (by IP)
5. IP Info (by Domain)
6. Reverse DNS Lookup(from ip)
7. Whois Scan
8. Phone Number Scan
9. Exit
========= """, max=9, min=1)

        if ask == 1:
            domain = input('Enter domain (e.g., example.com): ')
            if '.' in domain:
                subdomain_scan(domain)
                time.sleep(5)

        elif ask == 2:
            domain = input('Enter domain (e.g., example.com): ')
            if '.' in domain:
                scan_directories(domain)
                time.sleep(5)

        elif ask == 3:
            domain = input('Enter domain (e.g., example.com): ')
            if '.' in domain:
                extract_links(domain)
                time.sleep(5)

        elif ask == 4:
            ip = input('Enter IP (e.g., 8.8.8.8): ')
            regex = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
            if regex.match(ip):
                get_ipaddr(ip)
                time.sleep(5)
            else:
                print(Fore.RED + 'Invalid IP format')
                time.sleep(3)

        elif ask == 5:
            domain = input('Enter domain (e.g., example.com): ')
            if '.' in domain:
                getdomain_ipaddr(domain)
                time.sleep(5)
        elif ask == 6:
            dns = input('Enter IP (e.g., 8.8.8.8): ')
            reg = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
            if reg.match(dns):
                dns_lookup(dns)

        elif ask == 7:
            domain = input('Enter domain (e.g., example.com): ')
            if '.' in domain:
                whois_data = get_whois_info(domain)
                if whois_data:
                    extract_relevant_info(domain, whois_data)
                time.sleep(5)
            else:
                print("Plese input a valid IP address.")
        elif ask == 8:
            phone = input('Enter number to scan with country code (eg., +123XXXXXXX...): ')
            print("Searching Database......")
            time.sleep(1)
            scan_num(phone)
        elif ask == 9:
            print('Goodbye!')
            sys.exit()

except KeyboardInterrupt:
    print(f'\nScan interrupted by user.\n')
