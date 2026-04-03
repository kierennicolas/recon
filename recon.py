import os
import sys
import socket
import subprocess
import dns.resolver
import csv
import ssl
import time
import re
import zlib
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
WORDLIST_FILE = "subdomains.txt"
COMMON_PORTS = list(range(1, 1025)) + [1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211]

def ensure_wordlist():
    if not os.path.exists(WORDLIST_FILE):
        print("[+] Downloading wordlist...")
        import urllib.request
        urllib.request.urlretrieve(WORDLIST_URL, WORDLIST_FILE)

def get_dns_records(domain, debug=False):
    records = {
        'A': [], 'AAAA': [], 'MX': [], 'TXT': [], 'NS': [],
        'SPF': [], 'DKIM': [], 'DMARC': [],
        'DMARC_Policy': [],
        'Email_Security_Flags': []
    }

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['1.1.1.1']
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
        except Exception as e:
            if debug:
                print(f"[DEBUG] {rtype} lookup failed: {e}")

    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = ''.join([part.decode("utf-8") if isinstance(part, bytes) else str(part) for part in rdata.strings])
            if debug:
                print(f"[DEBUG] TXT: {txt}")
            records['TXT'].append(txt)
            if "v=spf1" in txt:
                records['SPF'].append(txt)
    except Exception as e:
        if debug:
            print(f"[DEBUG] TXT/SPF error: {e}")

    try:
        dkim_name = f"default._domainkey.{domain}"
        answers = resolver.resolve(dkim_name, "TXT")
        records['DKIM'] = [str(rdata).strip('"') for rdata in answers]
    except Exception as e:
        if debug:
            print(f"[DEBUG] DKIM error: {e}")

    try:
        dmarc_name = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_name, "TXT")
        for rdata in answers:
            record = ''.join([part.decode("utf-8") if isinstance(part, bytes) else str(part) for part in rdata.strings])
            if debug:
                print(f"[DEBUG] DMARC TXT: {record}")
            records["DMARC"].append(record)
            if "p=" in record:
                for part in record.split(";"):
                    if part.strip().startswith("p="):
                        policy = part.strip().split("=")[1].lower()
                        records["DMARC_Policy"].append(policy)
    except Exception as e:
        if debug:
            print(f"[DEBUG] DMARC error: {e}")

    flags = []
    if not records["SPF"]:
        flags.append("Missing SPF")
    if not records["DKIM"]:
        flags.append("Missing DKIM")
    if not records["DMARC"]:
        flags.append("Missing DMARC")
    elif "none" in records["DMARC_Policy"]:
        flags.append("Weak DMARC policy: none")

    records["Email_Security_Flags"] = flags or ["All present & strong"]
    return records

def write_dns_to_csv(domain, records):
    safe_name = domain.replace(".", "_")
    with open(f"{safe_name}_dns.csv", "w", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL, lineterminator='\r\n')
        writer.writerow(["Domain", "Type", "Value"])
        for rtype, values in records.items():
            if isinstance(values, list):
                for val in values:
                    writer.writerow([domain, rtype, val])

def check_https_and_meta(fqdn):
    import http.client
    import ssl

    try:
        start = time.time()
        context = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(fqdn, timeout=5, context=context)
        conn.request("GET", "/", headers={"Host": fqdn, "User-Agent": "Mozilla/5.0 (X11; RISC OS 5.31) Gecko"})
        response = conn.getresponse()
        data = response.read().decode(errors="replace")
        load_time = round((time.time() - start) * 1000)

        headers = {k: v for k, v in response.getheaders()}
        title_match = re.search(r"<title>(.*?)</title>", data, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else ""
        login_form = "login" in data.lower() and "<form" in data.lower()

        soup = BeautifulSoup(data, "html.parser")
        stripped_preview = soup.get_text(separator=" ", strip=True)[:200]

        return {
            "https": True,
            "status": response.status,
            "server": headers.get("server", ""),
            "headers": str(headers),
            "title": title,
            "load_time": load_time,
            "preview": stripped_preview,
            "login": login_form
        }
    except Exception as e:
        return {
            "https": False,
            "status": None,
            "server": "",
            "headers": "",
            "title": "",
            "load_time": None,
            "preview": "",
            "login": False
        }

def scan_open_ports(ip, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(scan_single_port, ip, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(str(result))
    return ", ".join(open_ports)

def scan_single_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                return port
    except Exception:
        pass
    return None

def process_subdomain(sub, domain, email_summary, do_scan, debug=False):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        cname = socket.getfqdn(fqdn)
        reverse_dns = socket.gethostbyaddr(ip)[0] if ip else ""
        meta = check_https_and_meta(fqdn)
        html_crc32 = str(zlib.crc32(meta["preview"].encode('utf-8')))
        ports = scan_open_ports(ip, COMMON_PORTS) if do_scan else ""
        return (
            fqdn, ip, cname, reverse_dns,
            meta["title"], meta["server"],
            meta["https"], "", meta["status"],
            "", meta["load_time"], meta["headers"],
            meta["preview"], html_crc32, meta["login"],
            email_summary, ports
        )
    except (socket.gaierror, socket.herror, OSError) as e:
        if debug:
            print(f"[!] DNS error for {fqdn}: {e}")
    except Exception as e:
        if debug:
            print(f"[!] Unexpected error for {fqdn}: {e}")
    return None

def brute_subdomains(domain, wordlist, email_summary="", do_scan=False, debug=False):
    found = []

    wildcard_test = f"thisdoesnotexistxyz123.{domain}"
    try:
        wildcard_ip = socket.gethostbyname(wildcard_test)
        print(f"[!] Wildcard DNS detected! ({wildcard_test} -> {wildcard_ip})")
        print("[!] This may produce false positives during brute-force.")
    except socket.gaierror:
        print("[+] No wildcard DNS detected.")

    with open(wordlist) as f:
        subs = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(process_subdomain, sub, domain, email_summary, do_scan, debug): sub
            for sub in subs
        }
        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            if result:
                found.append(result)
                print(f"[{i}/{len(subs)}] Found {result[0]}")
            elif debug:
                print(f"[{i}/{len(subs)}] Skipped {futures[future]}.{domain}")

    print(f"[+] {len(found)} valid subdomains discovered for {domain}.")
    return found

def write_subdomains_to_csv(domain, results):
    safe_name = domain.replace(".", "_")
    with open(f"{safe_name}_subdomains.csv", "w", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL, lineterminator='\r\n')
        writer.writerow([
            "Subdomain", "IP Address", "CNAME", "Reverse DNS",
            "HTTP Title", "Server Header",
            "HTTPS Available", "TLS Expiry", "HTTP Status Code",
            "Ping Time (ms)", "HTTP Load Time (ms)", "Full Headers",
            "HTML Preview", "HTML CRC32", "Login Form Detected",
            "Domain Email Security", "Open Ports"
        ])
        writer.writerows(results)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 recon.py domain.com[,another.com] [--debug]")
        sys.exit(1)

    ensure_wordlist()
    debug = '--debug' in sys.argv[1]

    domains = sys.argv[1].replace('--debug', '').split(",")
    for domain in domains:
        domain = domain.strip()
        print(f"\n[+] Starting recon on: {domain}")
        dns_records = get_dns_records(domain, debug=debug)
        write_dns_to_csv(domain, dns_records)

        email_security_summary = "; ".join(dns_records.get("Email_Security_Flags", []))
        if any(x in email_security_summary for x in ["Missing", "Weak"]):
            print(f"[!] WARNING for {domain}: {email_security_summary}")

        do_scan = input("[?] Would you like to scan ports on discovered subdomains? (y/n): ").strip().lower() == 'y'
        results = brute_subdomains(domain, WORDLIST_FILE, email_summary=email_security_summary, do_scan=do_scan, debug=debug)
        write_subdomains_to_csv(domain, results)
        print(f"[+] Recon complete for {domain}. Results saved to CSV files.")

if __name__ == "__main__":
    main()
