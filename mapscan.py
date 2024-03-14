#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# This script is a Python tool for sniffing network packets and automatically initiating Nmap 
# port scans on newly discovered hosts. This tool uses the scapy library to sniff packets and 
# the python-nmap library to perform Nmap scans. When a packet with an IP destination different 
# from localhost is captured, NetScanPy checks if the destination IP has already been scanned. 
# If not, it adds the IP to the list of scanned hosts and launches an Nmap scan for that host. 
# This tool is useful for monitoring network traffic and identifying potentially vulnerable hosts 
# on the network.
# Important Note please run the following commands to have the appropriate libraries for this
# script:
# pip install scapy
# sudo apt-get update
# sudo apt-get install nmap
# pip install python-nmap
# Example usage:
# python netscanpy.py
# Example output:
# IP source: 192.168.1.10, IP destination: 8.8.8.8
# Starting Nmap scan for host: 8.8.8.8
# Nmap scan results for host:  8.8.8.8
# Host: 8.8.8.8
# Protocol: tcp
# Port: 53	State: open
# Protocol: udp
# Port: 53	State: open
#################################################################################################
# Import necessary libraries
# Import necessary libraries
from scapy.all import *
import nmap
import threading
import ipaddress
import sys

# Callback function to handle each packet
def packet_callback(packet):
    try:
        # Check if the packet contains an IP layer
        if packet.haslayer(IP):
            # Extract the source and destination IP addresses
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            print(f"IP source: {ip_src}, IP destination: {ip_dst}")

            # Check if the destination IP is not localhost and not already scanned
            if ip_dst != '127.0.0.1' and ip_dst not in scanned_hosts:
                # Add the destination IP to the set of scanned hosts
                scanned_hosts.add(ip_dst)
                print(f"Starting Nmap scan for host: {ip_dst}")
                # Start an Nmap scan for the host
                nmap_scan(ip_dst)
    except Exception as e:
        # Print an error message if an exception occurs
        print(f"Error processing packet: {e}")

# Function to perform an Nmap scan on a host
def nmap_scan(host):
    try:
        # Create an Nmap PortScanner object
        nm = nmap.PortScanner()
        # Perform a comprehensive scan on the specified host
        nm.scan(hosts=host, arguments='-p 1-65535 -T4 -sS -sV -O --version-all --script=banner -A --script vulners')
        print("Nmap scan results for host: ", host)
        # Iterate over each scanned host
        for host in nm.all_hosts():
            print(f"Host: {host}")
            # Iterate over each protocol (e.g., TCP, UDP)
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                # Iterate over each scanned port
                ports = nm[host][proto].keys()
                for port in ports:
                    # Get the state of the port (open, closed, filtered, etc.)
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    product = nm[host][proto][port]['product']
                    version = nm[host][proto][port]['version']
                    extrainfo = nm[host][proto][port]['extrainfo']
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

    except Exception as e:
        # Print an error message if an exception occurs during the Nmap scan
        print(f"Error during Nmap scan: {e}")

# Function to start sniffing packets
def sniff_packets():
    try:
        # Start sniffing packets and call the packet_callback function for each packet
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        # Print an error message if an exception occurs during packet sniffing
        print(f"Error sniffing packets: {e}")

# Set to store scanned hosts to avoid duplicate scans
scanned_hosts = set()

# Create a thread to run the packet sniffer
sniff_thread = threading.Thread(target=sniff_packets)
# Set the thread as a daemon so it won't block program termination
sniff_thread.daemon = True
# Start the packet sniffer thread
sniff_thread.start()

# Main loop to keep the program running
while True:
    try:
        # Prompt the user for the remote IP address or CIDR notation
        remote_input = input("Enter the remote IP address or CIDR notation to implement the keylogger on: ")
        # Check if input is a single IP address or a CIDR notation
        if '/' in remote_input:
            # Parse CIDR notation and get all IP addresses in the range
            ip_network = ipaddress.ip_network(remote_input)
            for ip in ip_network:
                ip_address = str(ip)
                # Additional logic can be added here
                print("Scanning IP:", ip_address)
                # Check if the IP is not localhost and not already scanned
                if ip_address != '127.0.0.1' and ip_address not in scanned_hosts:
                    # Add the IP to the set of scanned hosts
                    scanned_hosts.add(ip_address)
                    print(f"Starting Nmap scan for host: {ip_address}")
                    # Start an Nmap scan for the host
                    nmap_scan(ip_address)
        else:
            # Additional logic can be added here for single IP address
            print("Scanning IP:", remote_input)
            # Check if the IP is not localhost and not already scanned
            if remote_input != '127.0.0.1' and remote_input not in scanned_hosts:
                # Add the IP to the set of scanned hosts
                scanned_hosts.add(remote_input)
                print(f"Starting Nmap scan for host: {remote_input}")
                # Start an Nmap scan for the host
                nmap_scan(remote_input)
    except KeyboardInterrupt:
        # Print a message and exit gracefully if Ctrl+C is pressed
        print("\nExiting...")
        break
    except Exception as e:
        # Print an error message if an exception occurs in the main loop
        print(f"Error in main loop: {e}")

