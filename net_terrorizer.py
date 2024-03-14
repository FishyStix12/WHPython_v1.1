#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# The script is a Python tool crafted for ethical hacking endeavors, focusing on network 
# reconnaissance and vulnerability assessment. Leveraging the `python-nmap` library, it 
# orchestrates comprehensive scans on remote hosts, probing for open ports, identifying service 
# versions, and detecting potential security weaknesses. Multithreading capabilities empower 
# the script to concurrently monitor network traffic, triggering Nmap scans upon detecting 
# novel hosts. Users can input either single IP addresses or CIDR notations to specify target 
# ranges for scanning. With integration of the `vulners` script, the tool extends its functionality 
# to include vulnerability detection, highlighting potential threats and associated CVE identifiers. 
# This versatile script equips ethical hackers with essential insights, aiding in the identification 
# and mitigation of security risks within authorized systems.
#################################################################################################
from scapy.all import *
import nmap
import threading
import ipaddress
import re
import sys

# Set to store scanned hosts to avoid duplicate scans
scanned_hosts = set()

# Lock for thread-safe access to scanned_hosts set
lock = threading.Lock()

# Function to handle packet callback
def packet_callback(packet):
    try:
        # Check if the packet has an IP layer
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            print(f"IP source: {ip_src}, IP destination: {ip_dst}")

            # Check if the destination IP is not localhost and has not been scanned before
            if ip_dst != '127.0.0.1' and ip_dst not in scanned_hosts:
                with lock:
                    scanned_hosts.add(ip_dst)
                print(f"Starting Nmap scan for host: {ip_dst}")
                threading.Thread(target=nmap_scan, args=(ip_dst,)).start()
    except Exception as e:
        print(f"Error processing packet: {e}")

# Function to perform Nmap scan
def nmap_scan(host):
    try:
        nm = nmap.PortScanner()
        # Perform Nmap scan with specified arguments
        nm.scan(hosts=host, arguments='-T4 -sS -sV -O --version-all --script=banner -A --script vulners')
        print("Nmap scan results for host:", host)
        # Iterate over scanned hosts
        for host in nm.all_hosts():
            print(f"Host: {host}")
            # Iterate over protocols for each host
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                # Iterate over ports for each protocol
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    product = nm[host][proto][port]['product']
                    version = nm[host][proto][port]['version']
                    extrainfo = nm[host][proto][port]['extrainfo']
                    print(f"Port: {port}\tState: {state}\tService: {service}\tProduct: {product}\tVersion: {version}\tExtra Info: {extrainfo}")

            # Print OS match information if available
            if 'osmatch' in nm[host]:
                for osmatch in nm[host]['osmatch']:
                    print(f"OS Match: {osmatch['name']}")

            # Print OS class information if available
            if 'osclass' in nm[host]:
                for osclass in nm[host]['osclass']:
                    print(f"OS Class: {osclass['type']} - {osclass['osfamily']}")

            # Print script information if available
            if 'script' in nm[host]:
                for script in nm[host]['script']:
                    print(f"Script: {script}")
                    if script == 'vulners':
                        cve_pattern = r'CVE-\d{4}-\d{4,7}'
                        cve_matches = re.findall(cve_pattern, nm[host]['script']['vulners'])
                        if cve_matches:
                            print("CVEs Found:", ", ".join(cve_matches))

    except Exception as e:
        print(f"Error during Nmap scan: {e}")

# Function to start packet sniffing
def sniff_packets():
    try:
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        print(f"Error sniffing packets: {e}")

# Main function
def main():
    # Create a thread to run the packet sniffer
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.daemon = True
    sniff_thread.start()

    # Main loop to keep the program running
    while True:
        try:
            # Prompt user for input
            remote_input = input("Enter the remote IP address or CIDR notation to scan (press Enter to exit): ")
            if not remote_input:
                print("Exiting...")
                sys.exit()
            port_input = input("Enter the port/ports to scan (leave empty for full scan): ")
            port_range = "1-65535" if not port_input else port_input

            # Check if input is in CIDR notation
            if '/' in remote_input:
                ip_network = ipaddress.ip_network(remote_input)
                # Iterate over IP addresses in the network
                for ip in ip_network:
                    ip_address = str(ip)
                    print("Scanning IP:", ip_address)
                    if ip_address != '127.0.0.1' and ip_address not in scanned_hosts:
                        with lock:
                            scanned_hosts.add(ip_address)
                        print(f"Starting Nmap scan for host: {ip_address}")
                        threading.Thread(target=nmap_scan, args=(ip_address, port_range)).start()
            else:
                # Scan single IP address
                print("Scanning IP:", remote_input)
                if remote_input != '127.0.0.1' and remote_input not in scanned_hosts:
                    with lock:
                        scanned_hosts.add(remote_input)
                    print(f"Starting Nmap scan for host: {remote_input}")
                    threading.Thread(target=nmap_scan, args=(remote_input, port_range)).start()

        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit()
        except Exception as e:
            print(f"Error in main loop: {e}")

if __name__ == "__main__":
    main()
