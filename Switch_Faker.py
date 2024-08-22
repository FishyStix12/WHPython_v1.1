#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: August 22 2024
# Description of Script
# This script is designed for Linux systems that performs MAC address spoofing, network flooding, 
# and packet sniffing. It allows users to change their network interface’s MAC address either 
# by specifying a new address or by generating a random one. Following the MAC address change,
# the script floods the network with packets using the new MAC address to test network resilience.
# After the flooding phase, it captures network traffic for a user-specified duration and saves 
# the captured packets to a file of the user's choice. This script is useful for network testing
# and analysis, offering functionality to both disrupt and monitor network traffic.
#################################################################################################
from scapy.all import *
import subprocess
import re
import random
import time

def get_current_mac(interface):
    """
    Retrieve the current MAC address of the specified network interface.
    """
    result = subprocess.run(["ifconfig", interface], capture_output=True, text=True)
    match = re.search(r"ether\s([0-9a-fA-F:]{17})", result.stdout)
    if match:
        return match.group(1)
    else:
        return None

def set_mac(interface, new_mac):
    """
    Change the MAC address of the specified network interface.
    """
    print(f"Changing MAC address of {interface} to {new_mac}...")
    subprocess.run(["sudo", "ifconfig", interface, "down"])  # Bring the interface down
    subprocess.run(["sudo", "ifconfig", interface, "hw", "ether", new_mac])  # Change MAC address
    subprocess.run(["sudo", "ifconfig", interface, "up"])  # Bring the interface back up
    print(f"MAC address changed to: {new_mac}")

def generate_random_mac():
    """
    Generate a random MAC address.
    The first three bytes (00:16:3e) are a locally administered address prefix.
    """
    mac = [0x00, 0x16, 0x3e, random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: f"{x:02x}", mac))

def flood_mac(interface, duration, mac_address):
    """
    Flood the network with packets containing the specified MAC address for a specified duration.
    Args:
        interface (str): The network interface to use for sending packets.
        duration (int): How long to continue flooding (in seconds).
        mac_address (str): The MAC address to use for flooding.
    """
    end_time = time.time() + duration  # Calculate the end time for flooding
    
    while time.time() < end_time:
        # Create an Ethernet frame with the specified source MAC address
        packet = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / IP(dst="0.0.0.0")
        
        # Send the packet on the specified interface
        sendp(packet, iface=interface, verbose=False)
        
        # Print the source MAC address of the packet being sent
        print("Flooding network with packet:", packet.src)

def packet_callback(packet):
    """
    Callback function to process and display captured packets.
    """
    print(f"Packet captured: {packet.summary()}")
    # Save the packet to the global packets list
    packets.append(packet)

def sniff_packets(interface, duration, filename):
    """
    Start sniffing packets on the specified network interface for a specified duration.
    Args:
        interface (str): The network interface to sniff packets on.
        duration (int): How long to continue sniffing (in seconds).
        filename (str): The name of the file to save captured packets.
    """
    print(f"Starting packet sniffing on interface {interface} for {duration} seconds...")
    sniff(iface=interface, prn=packet_callback, timeout=duration)
    # Save captured packets to the specified PCAP file
    wrpcap(filename, packets)
    print(f"Packet sniffing completed. Packets saved to '{filename}'.")

def main():
    """
    Main function to handle user input and initiate MAC address change, MAC flooding, and packet sniffing.
    - Prompts the user for the network interface, duration, new MAC address, and output filename.
    - Calls functions to change the MAC address, perform MAC flooding, and start packet sniffing.
    """
    interface = input("Enter the network interface (e.g., eth0, wlan0): ")
    
    # Retrieve and display the current MAC address
    current_mac = get_current_mac(interface)
    if current_mac:
        print(f"Current MAC address: {current_mac}")
    else:
        print(f"Could not retrieve MAC address for {interface}.")
        return
    
    # Ask the user if they want to specify a new MAC address
    change_mac = input("Do you want to specify a MAC address? (yes/no): ").lower()
    if change_mac == "yes":
        new_mac = input("Enter the new MAC address: ")
    else:
        # Generate a random MAC address
        new_mac = generate_random_mac()
        print(f"Generated random MAC address: {new_mac}")
    
    # Change the MAC address
    set_mac(interface, new_mac)
    
    # Start MAC flooding
    flood_duration = int(input("Enter the duration for flooding (in seconds): "))
    print(f"Starting MAC flooding on interface {interface} with MAC address {new_mac} for {flood_duration} seconds...")
    flood_mac(interface, flood_duration, new_mac)
    print("MAC flooding completed.")
    
    # Ask the user for the filename to save captured packets
    filename = input("Enter the filename to save captured packets (e.g., captured_packets.pcap): ")
    
    # Start packet sniffing
    sniff_duration = int(input("Enter the duration for packet sniffing (in seconds): "))
    global packets
    packets = []  # Initialize the list to store captured packets
    sniff_packets(interface, sniff_duration, filename)

if __name__ == "__main__":
    main()
