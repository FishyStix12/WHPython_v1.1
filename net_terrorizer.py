#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: April 21th 2024
# Description of Script
# This Python script provides a comprehensive tool for conducting customizable Nmap network scans,
# allowing users to interactively select specific Nmap scripts and scan options. Users can specify
# a list of remote IP addresses or CIDR notations and define port ranges for their scans. The 
# script prompts users to choose from a wide array of Nmap scripts, each designed to perform 
# different tasks such as detecting web server honeypots, analyzing firewall rules, retrieving 
# service banners, and identifying vulnerabilities. New additions include scripts for detecting 
# SQL injection and XSS vulnerabilities, identifying SSH authentication methods, and checking
# for the presence of backdoors in FTP servers. After executing the scan, the script offers 
# the option to save the detailed results, including any found CVEs and Metasploit modules, to 
# a user-defined text file. This functionality makes the script a powerful and flexible tool 
# for network exploration, security assessment, and detailed documentation.
#################################################################################################
import subprocess
import sys
import re
import ipaddress

def prompt_for_scripts():
    """Prompt the user whether to use specific Nmap scripts and return the selected scripts."""
    scripts = []
    
    # Define the available scripts and their descriptions
    script_descriptions = {
    "http-honeypot": "Detects if the target web server is a honeypot.",
    "firewalk": "Determines firewall rules by analyzing how TTL is handled in packets.",
    "banner": "Retrieves service banners for further analysis.",
    "vulners": "Checks for vulnerabilities by querying the Vulners database.",
    "broadcast-dns-service-discovery": "Discovers services broadcast via DNS-SD.",
    "dns-recursion": "Checks if a DNS server allows open recursion.",
    "smtp-commands": "Enumerates SMTP commands supported by the target mail server.",
    "smtp-open-relay": "Tests if the SMTP server is an open relay.",
    "smtp-enum-users": "Enumerates email addresses and usernames via SMTP.",
    "snmp-processes": "Enumerates running processes via SNMP.",
    "snmp-sysdescr": "Retrieves system information via SNMP.",
    "snmp-win32-software": "Enumerates installed software on Windows systems via SNMP.",
    "ftp-bounce": "Tests if the FTP server is vulnerable to the FTP bounce attack.",
    "netbios-ssn": "Enumerates NetBIOS session services and their details.",
    "http-title": "Retrieves the title of the web page served by HTTP servers.",
    "http-auth-finder": "Detects HTTP servers that use various authentication mechanisms.",
    "ssh-auth-methods": "Identifies supported SSH authentication methods on the target server.",
    "http-enum": "Enumerates directories and scripts accessible on HTTP servers.",
    "http-sql-injection": "Tests for SQL injection vulnerabilities in HTTP parameters.",
    "http-stored-xss": "Detects stored cross-site scripting (XSS) vulnerabilities in HTTP applications.",
    "smb-vuln-ms17-010": "Checks if the target system is vulnerable to the MS17-010 SMB vulnerability (EternalBlue).",
    "ftp-vsftpd-backdoor": "Detects the presence of a backdoor in vsftpd (Very Secure FTP Daemon) versions 2.3.4."
}   
    # Ask the user for each script
    for script, description in script_descriptions.items():
        user_input = input(f"Do you want to use the {script} script? ({description}) [y/N]: ").lower()
        if user_input == 'y':
            scripts.append(script)
    
    return ','.join(scripts) if scripts else None

def nmap_scan(host, port_range):
    try:
        # Get the scripts the user wants to use
        selected_scripts = prompt_for_scripts()

        # Define the Nmap scan arguments based on the port range and selected scripts
        if port_range:
            arguments = f'-T2 -sS -sV -O --version-all -A -p {port_range} --mtu 16 --badsum --data-length 500'
        else:
            arguments = f'-T2 -sS -sV -Pn -O --version-all -A -p- --mtu 16 --badsum --data-length 500'
        
        # If scripts are selected, add them to the arguments
        if selected_scripts:
            arguments += f' --script={selected_scripts}'
        
        # Add firewall evasion options
        arguments += ' -f -D RND:10'

        # Run the Nmap command using subprocess
        command = f"nmap {arguments} {host}"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Extract CVEs and Metasploit modules if they exist
        cves = re.findall(r"CVE-\d+-\d+", stdout.decode())
        metasploit_modules = re.findall(r"exploit/(.*?)/", stdout.decode())

        return stdout.decode(), stderr.decode(), cves, metasploit_modules

    except Exception as e:
        return f"Error during Nmap scan: {e}", "", [], []

def save_output_to_file(filename, stdout, stderr, cves, metasploit_modules):
    """Saves the Nmap output to a user-specified file."""
    try:
        with open(filename, 'w') as file:
            # Save scan output
            file.write("=== Nmap Scan Output ===\n")
            file.write(stdout + "\n")
            file.write(stderr + "\n")
            
            # Save CVEs if any
            if cves:
                file.write("\nFound CVEs:\n")
                for cve in cves:
                    file.write(f"{cve}\n")
            
            # Save Metasploit modules if any
            if metasploit_modules:
                file.write("\nFound Metasploit modules:\n")
                for module in metasploit_modules:
                    file.write(f"{module}\n")
        
        print(f"Output saved to {filename}")
    
    except Exception as e:
        print(f"Error saving output to file: {e}")

def main():
    try:
        # Prompt user for input: list of remote IP addresses or CIDR notations
        remote_input = input("Enter the list of remote IP addresses or CIDR notations to scan (press Enter to exit): ").split()
        
        # Exit if the user presses Enter
        if not remote_input:
            print("Exiting...")
            sys.exit()

        # Prompt user for input: port/ports to scan
        port_input = input("Enter the port/ports to scan (leave empty for full scan): ")
        
        # Set port range to scan (default is None for full scan)
        port_range = port_input if port_input else None

        # Ask user if they want to save the output to a file
        save_to_file = input("Do you want to save the output to a text file? [y/N]: ").lower()

        # If the user wants to save the output, ask for a filename
        if save_to_file == 'y':
            filename = input("Enter the filename to save the output (e.g., scan_results.txt): ")
        else:
            filename = None

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
                    # Perform Nmap scan on the current IP address
                    # stdout: Standard Output - This captures the regular output of the Nmap scan.
                    # stderr: Standard Error - This captures any error messages or warnings generated by the Nmap scan.
                    # It is used to handle any issues that occurred during the scanning process, such as invalid input or connection problems.
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
                    # Save output if user requested
                    if filename:
                        save_output_to_file(filename, stdout, stderr, cves, metasploit_modules)
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
                # Save output if user requested
                if filename:
                    save_output_to_file(filename, stdout, stderr, cves, metasploit_modules)
                # Print separator
                print("-" * 50)

    except Exception as e:
        # Print error message if an exception occurs during input parsing or Nmap scan
        print(f"Error during script execution: {e}")

if __name__ == "__main__":
    main()
