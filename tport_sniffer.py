#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# This Python script utilizes the Scapy library to sniff network packets and detect potential 
# email credentials being transmitted in plaintext. It allows the user to specify TCP port 
# filters to focus on specific network traffic. When a packet containing 'user' or 'pass' 
#in its payload is detected, the script prints the destination IP address and the payload, 
# which may include email credentials. This tool can be used for network security auditing or 
# monitoring purposes to identify and mitigate potential credential leaks.
# Example Usuage:
# Do you want to add more filters? (yes/no): yes
# Enter the port number: 25
# Do you want to add more filters? (yes/no): yes
# Enter the port number: 110
# Do you want to add more filters? (yes/no): no
# Applying filter: tcp port 25 or tcp port 110
# Example output:
# [*] Destination: 192.168.1.1
# [*] USER myemail@example.com
#################################################################################################
#imports the socket and threading modules for python 3.
from scapy.all import sniff, TCP, IP

def packet_callback(packet):
    """
    Callback function called for each packet.
    It checks if the packet is TCP and contains payload.
    If the payload contains 'user' or 'pass', it prints the destination IP and payload.
    """
    if TCP in packet and packet[TCP].payload:
        payload_str = str(packet[TCP].payload)
        if 'user' in payload_str.lower() or 'pass' in payload_str.lower():
            print(f"[*] Destination: {packet[IP].dst}")
            print(f"[*] {payload_str}")

def main():
    """
    Main function to configure filters and start packet sniffing.
    It prompts the user to add filters based on port numbers and starts sniffing packets.
    """
    filters = []
    while True:
        user_input = input("Do you want to add more filters? (yes/no): ")
        if user_input.lower() != 'yes':
            break
        port = int(input("Enter the port number: "))
        filters.append(f'tcp port {port}')
    filter_str = ' or '.join(filters)
    print(f"Applying filter: {filter_str}")
    sniff(filter=filter_str, prn=packet_callback)

if __name__ == '__main__':
    # Call the main function to start packet sniffing
    main()
