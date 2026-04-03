import argparse
import csv
import os
import random
import re
import shutil
import socket
import ssl
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from http.client import HTTPConnection, HTTPSConnection

try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except Exception:
    HAVE_DNSPYTHON = False


WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
WORDLIST_FILE = "subdomains.txt"
DEFAULT_TIMEOUT = 5.0
DEFAULT_USER_AGENT = "ReconTool/2.2 (RISC OS/Linux compatible)"
COMMON_PORTS = list(range(1, 1025)) + [1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211]


class MiniHTMLParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.in_title = False
        self.title_parts = []
        self.text_parts = []
        self.form_count = 0
        self.password_field = False

    def handle_starttag(self, tag, attrs):
        tag = (tag or "").lower()
        attrs_map = {}
        for item in attrs:
            key = (item[0] or "").lower()
            value = item[1] or ""
            attrs_map[key] = value

        if tag == "title":
            self.in_title = True
        elif tag == "form":
            self.form_count += 1
        elif tag == "input":
            input_type = attrs_map.get("type", "").lower()
            if input_type == "password":
                self.password_field = True

    def handle_endtag(self, tag):
        if (tag or "").lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if not data:
            return
        if self.in_title:
            self.title_parts.append(data)
        self.text_parts.append(data)

    def get_title(self):
        return " ".join(" ".join(self.title_parts).split()).strip()

    def get_preview(self, limit=200):
        text = " ".join(" ".join(self.text_parts).split()).strip()
        return text[:limit]

    def login_detected(self):
        return self.form_count > 0 and self.password_field



def log(message, quiet=False):
    if not quiet:
        print(message)



def warn(message):
    print(message, file=sys.stderr)



def safe_domain(domain):
    if not domain or len(domain) > 253:
        return False
    if domain.endswith("."):
        domain = domain[:-1]
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    pattern = re.compile(r"^[A-Za-z0-9-]{1,63}$")
    for label in labels:
        if not pattern.match(label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True



def parse_args(argv):
    parser = argparse.ArgumentParser(description="Recon helper for RISC OS and Linux")
    parser.add_argument("domains", help="Comma-separated domains, e.g. example.com,example.org")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--ports", action="store_true", help="Scan common TCP ports on discovered subdomains")
    parser.add_argument("--threads", type=int, default=12, help="Worker threads for subdomain checks")
    parser.add_argument("--port-threads", type=int, default=24, help="Worker threads for port scanning")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Network timeout in seconds")
    parser.add_argument("--wordlist", default=WORDLIST_FILE, help="Path to subdomain wordlist")
    parser.add_argument("--wordlist-url", default=WORDLIST_URL, help="URL to fetch the wordlist if missing")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of subdomains read from the wordlist")
    parser.add_argument("--resolver", action="append", default=[], help="DNS resolver IP to use, repeatable")
    parser.add_argument("--dkim-selector", action="append", default=[], help="DKIM selector to check, repeatable")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="HTTP User-Agent")
    parser.add_argument("--insecure", action="store_true", help="Allow unverified HTTPS for discovery")
    parser.add_argument("--make-riscos-obey", action="store_true", help="Write a simple RISC OS Obey launcher for this command")
    parser.add_argument("--python-command", default="python3", help="Python command for generated launcher, e.g. python3 or Python3")
    parser.add_argument("--quiet", action="store_true", help="Reduce console output")
    return parser.parse_args(argv)



def choose_limit(user_limit, domain_count, do_ports):
    if user_limit is not None and user_limit > 0:
        return user_limit
    limit = 5000
    if do_ports:
        limit = min(limit, 1000)
    if domain_count > 1:
        limit = min(limit, max(500, int(5000 / domain_count)))
    return limit



def ensure_wordlist(path, url, timeout, quiet=False):
    if os.path.exists(path):
        return
    log("[+] Downloading wordlist...", quiet=quiet)
    request = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
    response = urllib.request.urlopen(request, timeout=timeout)
    try:
        data = response.read()
    finally:
        response.close()
    handle = open(path, "wb")
    try:
        handle.write(data)
    finally:
        handle.close()



def trim_wordlist(path, limit):
    if not limit:
        return path
    temp_path = "%s.%d.tmp" % (path, limit)
    src = open(path, "r", encoding="utf-8", errors="replace")
    try:
        dst = open(temp_path, "w", encoding="utf-8")
        try:
            index = 0
            for line in src:
                if index >= limit:
                    break
                dst.write(line)
                index += 1
        finally:
            dst.close()
    finally:
        src.close()
    return temp_path



def build_resolver(nameservers, timeout):
    if not HAVE_DNSPYTHON:
        return None
    resolver = dns.resolver.Resolver(configure=True)
    if nameservers:
        resolver.nameservers = list(nameservers)
    resolver.timeout = timeout
    resolver.lifetime = max(timeout * 2.0, timeout + 1.0)
    return resolver



def find_dns_helper():
    if sys.platform.lower().startswith("riscos"):
        return None
    candidates = ["nslookup"]
    if os.name == "nt":
        candidates.append("nslookup.exe")
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path
    return None



def parse_nslookup_output(output, rtype):
    results = []
    lines = output.splitlines()
    for raw_line in lines:
        line = raw_line.strip()
        lower = line.lower()
        if not line:
            continue
        if lower.startswith("server:") or lower.startswith("address:") or lower.startswith("addresses:"):
            continue
        if line.startswith("***"):
            continue

        if rtype == "MX":
            if "mail exchanger" in lower and "=" in line:
                results.append(line.split("=", 1)[1].strip().rstrip("."))
        elif rtype == "NS":
            if "nameserver" in lower and "=" in line:
                results.append(line.split("=", 1)[1].strip().rstrip("."))
        elif rtype == "CNAME":
            if "canonical name" in lower and "=" in line:
                results.append(line.split("=", 1)[1].strip().rstrip("."))
        elif rtype == "TXT":
            if "text =" in lower and "=" in line:
                value = line.split("=", 1)[1].strip()
                if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
                    value = value[1:-1]
                results.append(value)
            elif line.startswith('"') and line.endswith('"'):
                results.append(line[1:-1])
    
    deduped = []
    seen = set()
    for value in results:
        if value not in seen:
            seen.add(value)
            deduped.append(value)
    return deduped



def run_dns_helper_query(name, rtype, timeout, debug=False):
    helper_cmd = find_dns_helper()
    if not helper_cmd:
        return []

    command = [helper_cmd, "-timeout=%d" % max(1, int(timeout)), "-type=%s" % rtype, name]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(2.0, timeout + 1.0),
            check=False,
        )
        output = completed.stdout or ""
        if completed.stderr:
            output = output + "
" + completed.stderr
        return parse_nslookup_output(output, rtype)
    except Exception as exc:
        if debug:
            warn("[DEBUG] DNS helper %s failed for %s: %s" % (rtype, name, exc))
        return []

    command = [nslookup_cmd, "-timeout=%d" % max(1, int(timeout)), "-type=%s" % rtype, name]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(2.0, timeout + 1.0),
            check=False,
        )
        output = completed.stdout or ""
        if completed.stderr:
            output = output + "\n" + completed.stderr
        return parse_nslookup_output(output, rtype)
    except Exception as exc:
        if debug:
            warn("[DEBUG] nslookup %s failed for %s: %s" % (rtype, name, exc))
        return []



def resolve_rrset(name, rtype, resolver, timeout, debug=False):
    if resolver:
        values = []
        try:
            answers = resolver.resolve(name, rtype)
            for rdata in answers:
                if rtype == "TXT":
                    if hasattr(rdata, "strings"):
                        parts = []
                        for part in rdata.strings:
                            if isinstance(part, bytes):
                                parts.append(part.decode("utf-8", "replace"))
                            else:
                                parts.append(str(part))
                        values.append("".join(parts))
                    else:
                        values.append(str(rdata).strip('"'))
                else:
                    values.append(str(rdata).rstrip("."))
        except Exception as exc:
            if debug:
                warn("[DEBUG] %s lookup failed for %s: %s" % (rtype, name, exc))
        return values

    return run_dns_helper_query(name, rtype, timeout, debug=debug)



def resolve_addresses(host, debug=False):
    addresses = []
    seen = set()
    try:
        info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for item in info:
            family, socktype, proto, canonname, sockaddr = item
            if family == socket.AF_INET:
                address = sockaddr[0]
            elif family == socket.AF_INET6:
                address = sockaddr[0]
            else:
                continue
            if address not in seen:
                seen.add(address)
                addresses.append(address)
    except Exception as exc:
        if debug:
            warn("[DEBUG] Address resolution failed for %s: %s" % (host, exc))
    return addresses



def get_dns_mode(resolver):
    if resolver:
        return "dnspython"
    if find_dns_helper():
        return "dns-helper"
    return "limited"



def get_dns_records(domain, resolver, selectors, timeout, debug=False):
    records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "TXT": [],
        "NS": [],
        "CNAME": [],
        "SPF": [],
        "DKIM": [],
        "DMARC": [],
        "DMARC_Policy": [],
        "Email_Security_Flags": [],
    }

    dns_mode = get_dns_mode(resolver)
    addresses = resolve_addresses(domain, debug=debug)
    for address in addresses:
        if ":" in address:
            records["AAAA"].append(address)
        else:
            records["A"].append(address)

    if dns_mode != "limited":
        records["MX"] = resolve_rrset(domain, "MX", resolver, timeout, debug=debug)
        records["TXT"] = resolve_rrset(domain, "TXT", resolver, timeout, debug=debug)
        records["NS"] = resolve_rrset(domain, "NS", resolver, timeout, debug=debug)
        records["CNAME"] = resolve_rrset(domain, "CNAME", resolver, timeout, debug=debug)
    else:
        records["Email_Security_Flags"].append("Limited DNS mode (no dnspython or external DNS helper)")

    for txt in records["TXT"]:
        if "v=spf1" in txt.lower():
            records["SPF"].append(txt)

    if dns_mode != "limited":
        dmarc_name = "_dmarc.%s" % domain
        dmarc_values = resolve_rrset(dmarc_name, "TXT", resolver, timeout, debug=debug)
        for value in dmarc_values:
            records["DMARC"].append(value)
            for part in value.split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    records["DMARC_Policy"].append(part.split("=", 1)[1].strip().lower())

        for selector in selectors:
            dkim_name = "%s._domainkey.%s" % (selector, domain)
            dkim_values = resolve_rrset(dkim_name, "TXT", resolver, timeout, debug=debug)
            for value in dkim_values:
                records["DKIM"].append("%s=%s" % (selector, value))

    flags = list(records["Email_Security_Flags"])
    if dns_mode == "dns-helper":
        flags.append("DNS helper mode (external helper fallback)")
    if not records["SPF"]:
        flags.append("Missing SPF")
    if dns_mode != "limited":
        if not records["DMARC"]:
            flags.append("Missing DMARC")
        elif "none" in records["DMARC_Policy"]:
            flags.append("Weak DMARC policy: none")
        if selectors:
            if not records["DKIM"]:
                flags.append("No DKIM record found for supplied selector(s)")
        else:
            flags.append("DKIM not checked (no selector supplied)")
    if not flags:
        flags.append("All checked controls present")
    records["Email_Security_Flags"] = flags
    return records



def write_dns_to_csv(domain, records):
    filename = "%s_dns.csv" % domain.replace(".", "_")
    handle = open(filename, "w", newline="", encoding="utf-8")
    try:
        writer = csv.writer(handle, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
        writer.writerow(["Domain", "Type", "Value"])
        for rtype in records:
            values = records[rtype]
            if isinstance(values, list):
                for value in values:
                    writer.writerow([domain, rtype, value])
    finally:
        handle.close()
    return filename



def get_tls_expiry(host, timeout, verify=True, debug=False):
    context = ssl.create_default_context() if verify else ssl._create_unverified_context()
    try:
        sock = socket.create_connection((host, 443), timeout)
        try:
            tls_sock = context.wrap_socket(sock, server_hostname=host)
            try:
                cert = tls_sock.getpeercert()
                return cert.get("notAfter", "")
            finally:
                tls_sock.close()
        finally:
            sock.close()
    except Exception as exc:
        if debug:
            warn("[DEBUG] TLS expiry lookup failed for %s: %s" % (host, exc))
        return ""



def fetch_http_metadata(host, scheme, timeout, user_agent, verify_tls=True, debug=False):
    start = time.time()
    headers = {}
    status = None
    server = ""
    title = ""
    preview = ""
    load_time = None
    login = False
    body = b""
    connection = None
    context = None

    try:
        if scheme == "https":
            if verify_tls:
                context = ssl.create_default_context()
            else:
                context = ssl._create_unverified_context()
            connection = HTTPSConnection(host, timeout=timeout, context=context)
        else:
            connection = HTTPConnection(host, timeout=timeout)

        connection.request(
            "GET",
            "/",
            headers={
                "Host": host,
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        status = response.status
        headers = {}
        for header_name, header_value in response.getheaders():
            headers[str(header_name)] = str(header_value)
        server = headers.get("Server", headers.get("server", ""))
        body = response.read(65536)
        content_type = headers.get("Content-Type", headers.get("content-type", ""))

        if "html" in content_type.lower() or body.lower().find(b"<html") != -1:
            text = body.decode("utf-8", "replace")
            parser = MiniHTMLParser()
            try:
                parser.feed(text)
            except Exception:
                pass
            title = parser.get_title()
            preview = parser.get_preview()
            login = parser.login_detected()

        load_time = int((time.time() - start) * 1000)
    except Exception as exc:
        if debug:
            warn("[DEBUG] %s fetch failed for %s: %s" % (scheme.upper(), host, exc))
    finally:
        try:
            if connection is not None:
                connection.close()
        except Exception:
            pass

    return {
        "scheme": scheme,
        "reachable": status is not None,
        "status": status,
        "server": server,
        "headers": headers,
        "title": title,
        "preview": preview,
        "load_time": load_time,
        "login": login,
        "body_crc32": ("%08x" % (zlib.crc32(body) & 0xFFFFFFFF)) if body else "",
    }



def check_web(host, timeout, user_agent, insecure=False, debug=False):
    https_meta = fetch_http_metadata(host, "https", timeout, user_agent, verify_tls=(not insecure), debug=debug)
    if https_meta.get("reachable"):
        https_meta["https"] = True
        https_meta["tls_expiry"] = get_tls_expiry(host, timeout, verify=(not insecure), debug=debug)
        return https_meta

    http_meta = fetch_http_metadata(host, "http", timeout, user_agent, verify_tls=False, debug=debug)
    http_meta["https"] = False
    http_meta["tls_expiry"] = ""
    return http_meta



def get_reverse_dns(ip, debug=False):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception as exc:
        if debug:
            warn("[DEBUG] Reverse DNS failed for %s: %s" % (ip, exc))
        return ""



def get_cname(name, resolver, timeout, debug=False):
    values = resolve_rrset(name, "CNAME", resolver, timeout, debug=debug)
    if values:
        return values[0]
    return ""



def scan_single_port(host, port, timeout):
    try:
        info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except Exception:
        return None

    for item in info:
        family, socktype, proto, canonname, sockaddr = item
        try:
            sock = socket.socket(family, socktype, proto)
            try:
                sock.settimeout(timeout)
                if sock.connect_ex(sockaddr) == 0:
                    return port
            finally:
                sock.close()
        except Exception:
            pass
    return None



def scan_open_ports(host, ports, timeout, max_workers):
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for port in ports:
            future = executor.submit(scan_single_port, host, port, timeout)
            futures[future] = port

        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort()
    return ", ".join([str(port) for port in open_ports])



def random_label(length=18):
    alphabet = string.ascii_lowercase + string.digits
    chars = []
    for _ in range(length):
        chars.append(random.choice(alphabet))
    return "".join(chars)



def wildcard_signature(domain, timeout, user_agent, insecure, debug=False):
    samples = []
    for _ in range(2):
        host = "%s.%s" % (random_label(), domain)
        addresses = resolve_addresses(host, debug=debug)
        if addresses:
            meta = check_web(host, timeout, user_agent, insecure=insecure, debug=debug)
            samples.append({
                "addresses": tuple(addresses),
                "status": meta.get("status"),
                "title": meta.get("title"),
                "body_crc32": meta.get("body_crc32"),
                "host": host,
            })

    if len(samples) >= 2 and samples[0]["addresses"] == samples[1]["addresses"]:
        return samples[0]
    return {}



def is_probable_wildcard(addresses, meta, wildcard):
    if not wildcard:
        return False
    if tuple(addresses) != wildcard.get("addresses", ()):
        return False
    if meta.get("status") != wildcard.get("status"):
        return False
    if meta.get("title") != wildcard.get("title"):
        return False
    if meta.get("body_crc32") != wildcard.get("body_crc32"):
        return False
    return True



def process_subdomain(sub, domain, resolver, email_summary, do_scan, port_threads, timeout, user_agent, insecure, wildcard, debug=False):
    fqdn = "%s.%s" % (sub, domain)
    addresses = resolve_addresses(fqdn, debug=debug)
    if not addresses:
        return None

    meta = check_web(fqdn, timeout, user_agent, insecure=insecure, debug=debug)
    if is_probable_wildcard(addresses, meta, wildcard):
        if debug:
            warn("[DEBUG] Filtered probable wildcard match: %s" % fqdn)
        return None

    primary_ip = addresses[0]
    reverse_dns = get_reverse_dns(primary_ip, debug=debug)
    cname = get_cname(fqdn, resolver, timeout, debug=debug)
    ports = ""
    if do_scan:
        ports = scan_open_ports(fqdn, COMMON_PORTS, timeout, port_threads)

    return (
        fqdn,
        "; ".join(addresses),
        cname,
        reverse_dns,
        str(meta.get("title", "")),
        str(meta.get("server", "")),
        bool(meta.get("https", False)),
        str(meta.get("tls_expiry", "")),
        meta.get("status"),
        "",
        meta.get("load_time"),
        str(meta.get("headers", "")),
        str(meta.get("preview", "")),
        str(meta.get("body_crc32", "")),
        bool(meta.get("login", False)),
        email_summary,
        ports,
    )



def brute_subdomains(domain, wordlist, resolver, email_summary, do_scan, threads, port_threads, timeout, user_agent, insecure, debug=False, quiet=False):
    results = []
    wildcard = wildcard_signature(domain, timeout, user_agent, insecure, debug=debug)
    if wildcard:
        log("[!] Wildcard DNS suspected for %s via %s" % (domain, wildcard.get("host", "<unknown>")), quiet=quiet)
    else:
        log("[+] No wildcard DNS detected.", quiet=quiet)

    handle = open(wordlist, "r", encoding="utf-8", errors="replace")
    try:
        subdomains = []
        for line in handle:
            value = line.strip()
            if value:
                subdomains.append(value)
    finally:
        handle.close()

    total = len(subdomains)
    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        futures = {}
        for sub in subdomains:
            future = executor.submit(
                process_subdomain,
                sub,
                domain,
                resolver,
                email_summary,
                do_scan,
                port_threads,
                timeout,
                user_agent,
                insecure,
                wildcard,
                debug,
            )
            futures[future] = sub

        index = 0
        for future in as_completed(futures):
            index += 1
            sub = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                if debug:
                    warn("[DEBUG] Worker failed for %s.%s: %s" % (sub, domain, exc))
                continue

            if result:
                results.append(result)
                log("[%d/%d] Found %s" % (index, total, result[0]), quiet=quiet)
            elif debug:
                warn("[DEBUG] [%d/%d] Skipped %s.%s" % (index, total, sub, domain))

    results.sort(key=lambda row: row[0])
    log("[+] %d valid subdomains discovered for %s." % (len(results), domain), quiet=quiet)
    return results



def write_subdomains_to_csv(domain, results):
    filename = "%s_subdomains.csv" % domain.replace(".", "_")
    handle = open(filename, "w", newline="", encoding="utf-8")
    try:
        writer = csv.writer(handle, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
        writer.writerow([
            "Subdomain",
            "IP Address(es)",
            "CNAME",
            "Reverse DNS",
            "HTTP Title",
            "Server Header",
            "HTTPS Available",
            "TLS Expiry",
            "HTTP Status Code",
            "Ping Time (ms)",
            "HTTP Load Time (ms)",
            "Full Headers",
            "HTML Preview",
            "Body CRC32",
            "Login Form Detected",
            "Domain Email Security",
            "Open Ports",
        ])
        for row in results:
            writer.writerow(list(row))
    finally:
        handle.close()
    return filename



def shell_quote_basic(value):
    if not value:
        return '""'
    if " " in value or "\t" in value:
        return '"%s"' % value.replace('"', '\\"')
    return value



def build_command_args_for_launcher(args):
    result = [args.domains]
    if args.debug:
        result.append("--debug")
    if args.ports:
        result.append("--ports")
    if args.threads != 12:
        result.extend(["--threads", str(args.threads)])
    if args.port_threads != 24:
        result.extend(["--port-threads", str(args.port_threads)])
    if args.timeout != DEFAULT_TIMEOUT:
        result.extend(["--timeout", str(args.timeout)])
    if args.wordlist != WORDLIST_FILE:
        result.extend(["--wordlist", args.wordlist])
    if args.wordlist_url != WORDLIST_URL:
        result.extend(["--wordlist-url", args.wordlist_url])
    if args.limit is not None:
        result.extend(["--limit", str(args.limit)])
    for item in args.resolver:
        result.extend(["--resolver", item])
    for item in args.dkim_selector:
        result.extend(["--dkim-selector", item])
    if args.user_agent != DEFAULT_USER_AGENT:
        result.extend(["--user-agent", args.user_agent])
    if args.insecure:
        result.append("--insecure")
    if args.quiet:
        result.append("--quiet")
    return result



def write_riscos_obey(args):
    script_name = os.path.basename(sys.argv[0]) or "recon.py"
    launcher_name = "run_recon.obey"
    parts = [args.python_command, script_name]
    parts.extend(build_command_args_for_launcher(args))
    command_line = " ".join([shell_quote_basic(part) for part in parts])

    handle = open(launcher_name, "w", encoding="utf-8", newline="\n")
    try:
        handle.write("| Generated launcher for RISC OS\n")
        handle.write("| Set this file's type to Obey on RISC OS if required\n")
        handle.write(command_line)
        handle.write("\n")
    finally:
        handle.close()
    return launcher_name



def main(argv):
    args = parse_args(argv)
    domains = []
    for item in args.domains.split(","):
        domain = item.strip().lower()
        if domain:
            domains.append(domain)

    if not domains:
        warn("No domains supplied.")
        return 1

    invalid = []
    for domain in domains:
        if not safe_domain(domain):
            invalid.append(domain)
    if invalid:
        warn("Invalid domain(s): %s" % ", ".join(invalid))
        return 1

    limit = choose_limit(args.limit, len(domains), args.ports)

    try:
        ensure_wordlist(args.wordlist, args.wordlist_url, args.timeout, quiet=args.quiet)
    except (OSError, urllib.error.URLError) as exc:
        warn("Could not prepare wordlist: %s" % exc)
        return 1

    if args.make_riscos_obey:
        try:
            launcher = write_riscos_obey(args)
            log("[+] Wrote launcher: %s" % launcher, quiet=args.quiet)
        except OSError as exc:
            warn("Could not write RISC OS launcher: %s" % exc)
            return 1

    wordlist_path = args.wordlist
    temp_wordlist = None
    if limit:
        try:
            temp_wordlist = trim_wordlist(args.wordlist, limit)
            wordlist_path = temp_wordlist
        except OSError as exc:
            warn("Could not trim wordlist: %s" % exc)
            return 1

    resolver = build_resolver(args.resolver, args.timeout)

    try:
        for domain in domains:
            log("\n[+] Starting recon on: %s" % domain, quiet=args.quiet)
            dns_records = get_dns_records(domain, resolver, args.dkim_selector, args.timeout, debug=args.debug)
            dns_csv = write_dns_to_csv(domain, dns_records)

            email_summary = "; ".join(dns_records.get("Email_Security_Flags", []))
            if "Missing" in email_summary or "Weak" in email_summary or "No DKIM" in email_summary:
                warn("[!] WARNING for %s: %s" % (domain, email_summary))
            else:
                log("[+] Email security summary for %s: %s" % (domain, email_summary), quiet=args.quiet)

            results = brute_subdomains(
                domain,
                wordlist_path,
                resolver,
                email_summary,
                args.ports,
                args.threads,
                args.port_threads,
                args.timeout,
                args.user_agent,
                args.insecure,
                debug=args.debug,
                quiet=args.quiet,
            )
            sub_csv = write_subdomains_to_csv(domain, results)
            log("[+] Recon complete for %s." % domain, quiet=args.quiet)
            log("[+] Saved: %s" % dns_csv, quiet=args.quiet)
            log("[+] Saved: %s" % sub_csv, quiet=args.quiet)
    finally:
        if temp_wordlist:
            try:
                os.remove(temp_wordlist)
            except OSError:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
