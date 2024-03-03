# Import necessary libraries
from scapy.all import *
import nmap
import threading

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
        # Perform a scan on the specified host using TCP SYN scan with aggressive timing
        nm.scan(hosts=host, arguments='-p 1-65535 -T4 -sS')
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
                    print(f"Port: {port}\tState: {state}")
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
        # Add your additional logic here
        pass
    except KeyboardInterrupt:
        # Print a message and exit gracefully if Ctrl+C is pressed
        print("\nExiting...")
        break
    except Exception as e:
        # Print an error message if an exception occurs in the main loop
        print(f"Error in main loop: {e}")