import socket
import sys
import re
import logging
from subprocess import Popen, PIPE
import argparse
import csv
import shutil
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

COMMON_TLDS = [
    "com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "co", "io", "xyz", "pro",
    "us", "uk", "de", "fr", "es", "it", "nl", "ru", "ca", "au", "mx", "br", "in", "cn", "jp", "kr", "se", "no", "fi",
    "dk", "ch", "be", "pl", "cz", "at", "pt", "gr", "ie", "nz", "za", "sg", "hk", "my", "th", "tw", "vn", "id", "ph",
    "ae", "sa", "tr", "il", "eg", "ar", "cl", "co", "pe"
]

def check_whois_installed():
    """Check if the 'whois' command is available."""
    if not shutil.which("whois"):
        logger.error("The 'whois' command is not installed. Please install it and try again.")
        sys.exit(1)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Perform WHOIS lookups for a list of domains with common TLDs")
    parser.add_argument("-d", "--domains", required=True, help="File containing a list of base domains (without TLD)")
    parser.add_argument("-o", "--output", help="Output results in CSV format")
    args = parser.parse_args()
    return args.domains, args.output

def extract_info(pattern, output):
    """Extract relevant WHOIS information based on a regex pattern."""
    match = re.search(r'%s\s*(.+)' % pattern, output)
    return match.group(1).strip() if match else "N/A"

def resolve_domain_ip(domain_name):
    """Resolve a domain name to an IP address."""
    try:
        return socket.gethostbyname(domain_name)
    except Exception as e:
        logger.warning(f"[-] Could not resolve {domain_name} - {e}")
        return None

def perform_whois(ip_address):
    """Perform a WHOIS lookup and extract relevant information."""
    netname, inetnum, country = "N/A", "N/A", "N/A"
    try:
        p = Popen(['whois', ip_address], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        rc = p.returncode
        output = output.decode(errors="ignore").lower()

        if rc == 0:
            logger.debug(f"[DEBUG] WHOIS Output for {ip_address}:\n{output}\n")
            netname = extract_info("netname:", output)
            country = extract_info("country:", output)
            inetnum = extract_info("inetnum:", output) if "inetnum" in output else extract_info("netrange:", output)
    except Exception as e:
        logger.error(f"[-] WHOIS lookup failed for {ip_address} - {e}")
    return netname, inetnum, country, ip_address

def run_tool(domains_file, output_file):
    """Main function to process the domain list and output results."""
    results = []
    with open(domains_file, "r") as ins:
        for line in ins:
            base_domain = line.strip()
            if not base_domain:
                continue
            
            for tld in COMMON_TLDS:
                full_domain = f"{base_domain}.{tld}"
                logger.info(f"[+] Processing {full_domain}...")
                ip_address = resolve_domain_ip(full_domain)
                if ip_address is not None:
                    netname, inetnum, country, domain_ip = perform_whois(ip_address)
                    result = {
                        "Domain Name": full_domain,
                        "Network Name": netname,
                        "Domain IP": domain_ip,
                        "IP Range": inetnum,
                        "Country": country,
                    }
                    results.append(result)

    if output_file:
        with open(output_file, "w", newline="") as out:
            fieldnames = ["Domain Name", "Network Name", "Domain IP", "IP Range", "Country"]
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        logger.info(f"[+] Results saved to {output_file}")

    print("\nResults:")
    for result in results:
        print(f"[+] {result['Domain Name']} resolved correctly")
        print(f"    - Domain Name: {result['Domain Name']}")
        print(f"    - Network Name: {result['Network Name']}")
        print(f"    - Domain IP: {result['Domain IP']}")
        print(f"    - IP Range: {result['IP Range']}")
        print(f"    - Country: {result['Country']}\n")

if __name__ == "__main__":
    check_whois_installed()
    domains_file, output_file = parse_arguments()
    run_tool(domains_file, output_file)