#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: April 21st 2024
# Description of Script
# This script is a tool crafted for ethical hacking endeavors, focusing on network reconnaissance 
# and vulnerability assessment. Leveraging the `python-nmap` library, it orchestrates comprehensive
# scans on remote hosts, probing for open ports, identifying service versions, and detecting 
# potential security weaknesses. Multithreading capabilities empower the script to concurrently
# monitor network traffic, triggering Nmap scans upon detecting novel hosts. Users can input 
# either single IP addresses or CIDR notations to specify target ranges for scanning. With 
# integration of the `vulners` script, the tool extends its functionality to include vulnerability
# detection, highlighting potential threats and associated CVE identifiers. This versatile
# script equips ethical hackers with essential insights, aiding in the identification and 
# mitigation of security risks within authorized systems. 
#################################################################################################
import sys
import threading
import ipaddress
import re
from scapy.packet import Packet
from scapy.fields import IPField, XShortField, XByteField
from scapy.layers.inet import TCP, IP
import nmap

# Set to store scanned hosts to avoid duplicate scans
from scapy.sendrecv import sniff

scanned_hosts = set()  # Initialize an empty set to store scanned hosts
lock = threading.Lock()  # Create a lock to ensure thread-safe access to shared resources

# Function to handle packet callback
def packet_callback(packet):
    try:
        # Check if the packet contains an IP and TCP layer
        if packet.haslayer(IP) and packet.haslayer(TCP):  # Check if the packet has an IP and TCP layer
            # Extract source and destination IP addresses and ports
            ip_src = packet[IP].src  # Extract the source IP address from the packet
            ip_dst = packet[IP].dst  # Extract the destination IP address from the packet
            tcp_src = packet[TCP].sport  # Extract the source TCP port from the packet
            tcp_dst = packet[TCP].dport  # Extract the destination TCP port from the packet
            # Print source and destination IP addresses and ports
            print(f"IP source: {ip_src}, IP destination: {ip_dst}, TCP source port: {tcp_src}, TCP destination port: {tcp_dst}")

            # Check if the destination IP and port is not localhost and not already scanned
            if ip_dst != '127.0.0.1' and tcp_dst not in scanned_hosts:
                # Acquire lock for thread-safe access to scanned_hosts set
                with lock:
                    # Add destination IP and port to scanned_hosts set
                    scanned_hosts.add(tcp_dst)
                # Print message about starting Nmap scan
                print(f"Starting Nmap scan for host: {ip_dst}:{tcp_dst}")
                # Start a new thread to perform Nmap scan
                threading.Thread(target=nmap_scan, args=(ip_dst, tcp_dst)).start()
    except Exception as e:
        # Print error message if an exception occurs
        print(f"Error processing packet: {e}")

# Function to perform Nmap scan
def nmap_scan(host, port):
    try:
        # Create Nmap PortScanner object
        nm = nmap.PortScanner()
        # Perform Nmap scan on the specified host and port
        nm.scan(hosts=host, ports=port, arguments='-T4 -sS -sV -O --version-all --script=banner -A --script vulners')
        # Print Nmap scan results for the host and port
        print("Nmap scan results for host:", host, "port:", port)
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
                    print(f"Port: {port}, State: {state}, Service: {service}, Product: {product}, Version: {version}, Extrainfo: {extrainfo}")

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
    except Exception as e:
        print(f"Error: {e}")


# Set to store scanned hosts to avoid duplicate scans
scanned_hosts = set()  # Initialize an empty set to store scanned hosts
lock = threading.Lock()  # Create a lock to ensure thread-safe access to shared resources

# Function to handle packet callback
def packet_callback(packet):
    try:
        # Check if the packet contains an IP layer
        if packet.haslayer(IP):  # Check if the packet has an IP layer
            # Extract source and destination IP addresses
            ip_src = packet[IP].src  # Extract the source IP address from the packet
            ip_dst = packet[IP].dst  # Extract the destination IP address from the packet
            # Print source and destination IP addresses
            # print(f"IP source: {ip_src}, IP destination: {ip_dst}")

            # Check if the destination IP is not localhost and not already scanned
            if ip_dst != '127.0.0.1' and ip_dst not in scanned_hosts:
                # Acquire lock for thread-safe access to scanned_hosts set
                with lock:
                    # Add destination IP to scanned_hosts set
                    scanned_hosts.add(ip_dst)
                # Print message about starting Nmap scan
                print(f"Starting Nmap scan for host: {ip_dst}")
                # Start a new thread to perform Nmap scan
                threading.Thread(target=nmap_scan, args=(ip_dst,)).start()
    except Exception as e:
        # Print error message if an exception occurs
        print(f"Error processing packet: {e}")

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

# Function to start packet sniffing
def sniff_packets():
    try:
        # Start sniffing packets and call packet_callback function for each packet
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        # Print error message if an exception occurs during packet sniffing
        print(f"Error sniffing packets: {e}")

# Main function
def main():
    try:
        # Create a thread to run the packet sniffer
        sniff_thread = threading.Thread(target=sniff_packets)
        sniff_thread.daemon = True
        sniff_thread.start()

        # Main loop to keep the program running
        while True:
            try:
                # Prompt user for input: remote IP address or CIDR notation
                remote_input = input("Enter the remote IP address or CIDR notation to scan (press Enter to exit): ")
                # Exit if user presses Enter
                if not remote_input:
                    print("Exiting...")
                    sys.exit()
                # Prompt user for input: port/ports to scan
                port_input = input("Enter the port/ports to scan (leave empty for full scan): ")
                # Set port range to scan (default is 1-65535 if input is empty)
                port_range = "1-65535" if not port_input else port_input

                # Check if input is CIDR notation
                if '/' in remote_input:
                    # Parse CIDR notation and iterate over all IP addresses in the range
                    ip_network = ipaddress.ip_network(remote_input)
                    for ip in ip_network:
                        ip_address = str(ip)
                        # Print message about scanning IP
                        print("Scanning IP:", ip_address)
                        # Check if IP address is not localhost and not already scanned
                        if ip_address != '127.0.0.1' and ip_address not in scanned_hosts:
                            # Acquire lock for thread-safe access to scanned_hosts set
                            with lock:
                                # Add IP address to scanned_hosts set
                                scanned_hosts.add(ip_address)
                            # Print message about starting Nmap scan
                            print(f"Starting Nmap scan for host: {ip_address}")
                            # Start a new thread to perform Nmap scan
                            threading.Thread(target=nmap_scan, args=(ip_address, port_range)).start()
                else:
                    # Print message about scanning IP
                    print("Scanning IP:", remote_input)
                    # Check if IP address is not localhost and not already scanned
                    if remote_input != '127.0.0.1' and remote_input not in scanned_hosts:
                        # Acquire lock for thread-safe access to scanned_hosts set
                        with lock:
                            # Add IP address to scanned_hosts set
                            scanned_hosts.add(remote_input)
                        # Print message about starting Nmap scan
                        print(f"Starting Nmap scan for host: {remote_input}")
                        # Start a new thread to perform Nmap scan
                        threading.Thread(target=nmap_scan, args=(remote_input, port_range)).start()

            except KeyboardInterrupt:
                # Print message and exit gracefully if Ctrl+C is pressed
                print("\nExiting...")
                sys.exit()
            except Exception as e:
                # Print error message if an exception occurs
                print(f"Error: {e}")
    except Exception as e:
        # Print error message if an exception occurs
        print(f"Error: {e}")

# Entry point of the script
if __name__ == "__main__":
    # Call the main function
    main()
