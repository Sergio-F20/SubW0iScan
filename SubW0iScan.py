#!/usr/bin/env python

# SubWh0iScan
#
# Description:
#   Perform WHOIS lookups for a list of domains and extract relevant information
#
# github.com/Sergio-F20
#
# Usage: python SubWh0iScan.py -d subdomains-list.txt -o subdomains-info.csv
#


import socket, sys, re, logging
from subprocess import Popen, PIPE
import argparse
import csv

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Perform WHOIS lookups for a list of domains and extract relevant information")
    parser.add_argument("-d", "--domains", required=True, help="File containing a list of domains")
    parser.add_argument("-o", "--output", help="Output results in CSV format")
    args = parser.parse_args()
    return args.domains, args.output

def extract_info(pattern, output):
    match = re.search('%s(.+)' % pattern, output)
    return match.group(1)

def resolve_domain_ip(domain_name):
    try:
        return socket.gethostbyname(domain_name)
    except Exception as e:
        error_msg = f"[-] Could not resolve {domain_name} - {e}"
        print(error_msg)
        return None

def perform_whois(ip_address):
    netname, inetnum, country = "N/A", "N/A", "N/A"
    p = Popen(['whois', ip_address], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, err = p.communicate()

    rc = p.returncode
    output = output.lower().decode()
    if rc == 0:
        netname = extract_info("netname:", output).strip()
        country = extract_info("country:", output).strip()
        if "netrange" in output:
            inetnum = extract_info("netrange:", output).strip()
        elif "inetnum" in output:
            inetnum = extract_info("inetnum:", output).strip()
    return netname, inetnum, country, ip_address

def run_tool(domains_file, output_file):
    results = []

    with open(domains_file, "r") as ins:
        for line in ins:
            domain_name = line.strip()
            ip_address = resolve_domain_ip(domain_name)
            if ip_address is not None:
                netname, inetnum, country, domain_ip = perform_whois(ip_address)
                result = {
                    "Domain Name": domain_name,
                    "Network Name": netname,
                    "Domain IP": domain_ip,
                    "IP Range": inetnum,
                    "Country": country,
                }
                results.append(result)

    if output_file:
        with open(output_file, "w") as out:
            fieldnames = ["Domain Name", "Network Name", "Domain IP", "IP Range", "Country"]
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)

    print("\nResults:")
    for result in results:
        print("[+] {} resolved correctly".format(result["Domain Name"]))
        print(f"    - Domain Name: {result['Domain Name']}")
        print(f"    - Network Name: {result['Network Name']}")
        print(f"    - Domain IP: {result['Domain IP']}")
        print(f"    - IP Range: {result['IP Range']}")
        print(f"    - Country: {result['Country']}")

if __name__ == "__main__":
    domains_file, output_file = parse_arguments()
    run_tool(domains_file, output_file)
