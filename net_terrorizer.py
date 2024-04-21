#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: April 21th 2024
# Description of Script
# The script is a Python tool designed for network scanning using Nmap, a popular network 
# exploration and security auditing tool. It allows users to perform comprehensive scans on remote
# IP addresses or CIDR notations, providing detailed information about open ports, services,
# operating systems, vulnerabilities (CVEs), and Metasploit modules. The script integrates 
# with the system's subprocess module to run Nmap commands and parse the scan results. 
# Additionally, it includes techniques to evade firewall detection, such as packet 
# fragmentation and decoy IP addresses, enhancing the scan's stealth and accuracy. 
# The user-friendly interface prompts for input, executes scans, and displays results, making
# it an effective tool for network administrators and security professionals to assess and 
# secure their network infrastructure.
#################################################################################################
import ipaddress
import re
import sys
import subprocess

def nmap_scan(host, port_range=None):
    try:
        # Construct Nmap command with techniques to avoid firewall detection
        if port_range:
            arguments = f'-T2 -sS -sV -O --version-all --script=banner -A --script vulners -p {port_range} --mtu 16 --badsum --data-length 500'
        else:
            arguments = '-T2 -sS -sV -O --version-all --script=banner -A --script vulners --mtu 16 --badsum --data-length 500'

        # Add firewall evasion options
        arguments += ' -f -D RND:10'

        # Run Nmap command using subprocess
        command = f"nmap {arguments} {host}"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Extract CVEs and Metasploit modules if they exist
        cves = re.findall(r"CVE-\d+-\d+", stdout.decode())
        metasploit_modules = re.findall(r"exploit/(.*?)/", stdout.decode())

        return stdout.decode(), stderr.decode(), cves, metasploit_modules

    except Exception as e:
        return f"Error during Nmap scan: {e}", "", [], []

def main():
    try:
        # Prompt user for input: list of remote IP addresses or CIDR notations
        remote_input = input("Enter the list of remote IP addresses or CIDR notations to scan (press Enter to exit): ").split()
        # Exit if user presses Enter
        if not remote_input:
            print("Exiting...")
            sys.exit()
        # Prompt user for input: port/ports to scan
        port_input = input("Enter the port/ports to scan (leave empty for full scan): ")
        # Set port range to scan (default is None for full scan)
        port_range = port_input if port_input else None

        # Iterate over each IP address or CIDR notation
        for ip_or_cidr in remote_input:
            # Check if input is CIDR notation
            if '/' in ip_or_cidr:
                # Parse CIDR notation and iterate over all IP addresses in the range
                ip_network = ipaddress.ip_network(ip_or_cidr)
                for ip in ip_network:
                    ip_address = str(ip)
                    # Print message about scanning IP address
                    print(f"Scanning IP address: {ip_address}")
                    # Perform Nmap scan on the current IP address
                    stdout, stderr, cves, metasploit_modules = nmap_scan(ip_address, port_range)
                    # Print scan output
                    print(stdout)
                    print(stderr)
                    if cves:
                        print("\nFound CVEs:")
                        for cve in cves:
                            print(cve)
                    if metasploit_modules:
                        print("\nFound Metasploit modules:")
                        for module in metasploit_modules:
                            print(module)
                    # Print separator
                    print("-" * 50)
            else:
                # Perform Nmap scan on the specified IP address
                stdout, stderr, cves, metasploit_modules = nmap_scan(ip_or_cidr, port_range)
                # Print scan output
                print(stdout)
                print(stderr)
                if cves:
                    print("\nFound CVEs:")
                    for cve in cves:
                        print(cve)
                if metasploit_modules:
                    print("\nFound Metasploit modules:")
                    for module in metasploit_modules:
                        print(module)
                # Print separator
                print("-" * 50)

    except Exception as e:
        # Print error message if an exception occurs during input parsing or Nmap scan
        print(f"Error during script execution: {e}")

if __name__ == "__main__":
    main()
