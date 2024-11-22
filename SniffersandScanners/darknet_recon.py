#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 14th 2024
# Description of Script
# The script provided is a Python tool for conducting network scans using Nmap and searching
# for Metasploit modules corresponding to identified vulnerabilities. It prompts the user to input
# remote IP addresses or CIDR notations for scanning. After performing Nmap scans to discover hosts
# and their open ports along with potential vulnerabilities, the script simulates finding CVE IDs.
# It then utilizes Metasploit's `msfconsole` command-line tool to search for exploit modules related
# to the identified CVEs. The user is prompted to enter the superuser password when required for 
# executing commands. Overall, this script serves as a versatile tool for network reconnaissance
# and vulnerability assessment, seamlessly integrating Nmap and Metasploit functionalities.
#################################################################################################
import subprocess
import re
import ipaddress
import nmap
import getpass

# Function to perform Nmap scan
def nmap_scan(host):
    try:
        # Create Nmap PortScanner object
        nm = nmap.PortScanner()
        # Perform Nmap scan on the specified host
        nm.scan(hosts=host, arguments='-T4 -sS -sV -O --version-all --script=banner -A --script vulners')
        # Print Nmap scan results for the host
        print("Nmap scan results for host:", host)
        # Iterate over all scanned hosts
        for host in nm.all_hosts():
            print(f"Host: {host}")
            # Iterate over each protocol
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                # Iterate over each scanned port
                ports = nm[host][proto].keys()
                for port in ports:
                    # Extract information about each port
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    product = nm[host][proto][port]['product']
                    version = nm[host][proto][port]['version']
                    extrainfo = nm[host][proto][port]['extrainfo']
                    # Print port information
                    print(f"Port: {port}\tState: {state}\tService: {service}\tProduct: {product}\tVersion: {version}\tExtra Info: {extrainfo}")

            # Print OS detection results
            if 'osmatch' in nm[host]:
                for osmatch in nm[host]['osmatch']:
                    print(f"OS Match: {osmatch['name']}")

            # Print service detection results
            if 'osclass' in nm[host]:
                for osclass in nm[host]['osclass']:
                    print(f"OS Class: {osclass['type']} - {osclass['osfamily']}")

            # Print any additional information from Nmap scripts
            if 'script' in nm[host]:
                for script in nm[host]['script']:
                    print(f"Script: {script}")
                    # If vulners script is executed, extract CVE IDs
                    if script == 'vulners':
                        cve_pattern = r'CVE-\d{4}-\d{4,7}'
                        cve_matches = re.findall(cve_pattern, nm[host]['script']['vulners'])
                        if cve_matches:
                            print("CVEs Found:", ", ".join(cve_matches))

    except Exception as e:
        # Print error message if an exception occurs during Nmap scan
        print(f"Error during Nmap scan: {e}")

# Function to search Metasploit modules for given CVE IDs
def search_metasploit(cve_ids):
    print("\nMetasploit modules for the found vulnerabilities:")
    try:
        for cve_id in cve_ids:
            # Run 'msfconsole' command to search for modules
            command = f"msfconsole -q -x 'search type:exploit {cve_id}'"
            process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(input=f'set PASSWORD {getpass.getpass()}'.encode())
            # Parse the output to extract module information
            modules = re.findall(r"(\d+)\s*(\w+/[\w/-]+)\s*\((\w+)\)", stdout.decode())

            if modules:
                print(f"\nVulnerability: {cve_id}")
                for module in modules:
                    print(f"Module: {module[1]} ({module[2]})")
            else:
                print(f"\nNo Metasploit modules found for vulnerability: {cve_id}")

    except Exception as e:
        print(f"Error searching Metasploit modules: {e}")

# Main function
def main():
    try:
        # Prompt user for input: remote IP address or CIDR notation
        remote_input = input("Enter the remote IP address or CIDR notation to scan (press Enter to exit): ")
        # Exit if user presses Enter
        if not remote_input:
            print("Exiting...")
            return
        # Perform Nmap scan
        nmap_scan(remote_input)

        # Process Nmap scan results to find vulnerabilities
        # For demonstration, we simulate finding some CVE IDs
        cve_ids = ['CVE-2017-1001000', 'CVE-2019-6977', 'CVE-2018-1000861']
        search_metasploit(cve_ids)

    except KeyboardInterrupt:
        # Print message and exit gracefully if Ctrl+C is pressed
        print("\nExiting...")
        return
    except Exception as e:
        # Print error message if an exception occurs
        print(f"Error: {e}")

# Entry point of the script
if __name__ == "__main__":
    # Call the main function
    main()
