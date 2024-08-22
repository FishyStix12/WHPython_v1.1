#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: August 22 2024
# Description of Script
# This script is for Linux systems that facilitates network testing by performing MAC address spoofing,
# network flooding, and packet sniffing. It allows users to change their network interface’s MAC address
# either by specifying a custom address or by generating a random one. After modifying the MAC address,
# the script floods the network with packets to simulate stress on the network. Following this, it
# sets the network interface to promiscuous mode to capture all traffic for a specified duration,
# saving the captured packets to a user-defined file. This script is designed for network analysis,
# enabling users to disrupt and monitor network traffic effectively.
#################################################################################################
from scapy.all import *
import subprocess
import re
import random
import time

def get_current_mac(interface):
    """
    Retrieve the current MAC address of the specified network interface.
    
    Args:
        interface (str): The name of the network interface (e.g., 'eth0').

    Returns:
        str: The current MAC address of the interface, or None if it could not be retrieved.
    """
    result = subprocess.run(["ifconfig", interface], capture_output=True, text=True)
    match = re.search(r"ether\s([0-9a-fA-F:]{17})", result.stdout)
    if match:
        return match.group(1)  # Return the MAC address if found
    else:
        return None  # Return None if no MAC address was found

def set_mac(interface, new_mac):
    """
    Change the MAC address of the specified network interface.
    
    Args:
        interface (str): The name of the network interface (e.g., 'eth0').
        new_mac (str): The new MAC address to set (e.g., '00:11:22:33:44:55').
    """
    print(f"Changing MAC address of {interface} to {new_mac}...")
    subprocess.run(["sudo", "ifconfig", interface, "down"])  # Bring the interface down
    subprocess.run(["sudo", "ifconfig", interface, "hw", "ether", new_mac])  # Set new MAC address
    subprocess.run(["sudo", "ifconfig", interface, "up"])  # Bring the interface back up
    print(f"MAC address changed to: {new_mac}")

 def set_promiscuous_mode(interface, enable=True):
    """
    Set the network interface to promiscuous mode.
    
    Args:
        interface (str): The name of the network interface (e.g., 'eth0').
        enable (bool): Whether to enable or disable promiscuous mode. Default is True.
    """
    mode = "promisc" if enable else "nopromisc"
    print(f"Setting promiscuous mode {mode} for {interface}...")
    subprocess.run(["sudo", "ip", "link", "set", interface, mode])
    print(f"Promiscuous mode {mode} for {interface}.")

def generate_random_mac():
    """
    Generate a random MAC address with a locally administered address prefix.
    
    Returns:
        str: A randomly generated MAC address (e.g., '00:16:3e:5a:6b:7c').
    """
    mac = [0x00, 0x16, 0x3e, random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: f"{x:02x}", mac))  # Convert list to MAC address string

def flood_mac(interface, duration, mac_address):
    """
    Flood the network with packets containing the specified MAC address.
    
    Args:
        interface (str): The network interface to use for sending packets.
        duration (int): Duration for flooding in seconds.
        mac_address (str): The MAC address to use for flooding.
    """
    end_time = time.time() + duration  # Calculate end time
    while time.time() < end_time:
        # Create a broadcast packet with the specified source MAC address
        packet = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / IP(dst="0.0.0.0")
        sendp(packet, iface=interface, verbose=False)  # Send packet
        print("Flooding network with packet from:", mac_address)

def packet_callback(packet):
    """
    Callback function to process and display captured packets.
    
    Args:
        packet (scapy.packet): The captured packet.
    """
    if packet.haslayer(Ether):  # Check if the packet has an Ethernet layer
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        ip_src = ip_dst = None
        src_port = dst_port = None

        # Check if the packet has an IP layer
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
        
        # Check if the packet has a UDP layer
        if packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        # Check if the packet has a TCP layer
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        
        # Print the packet details in the desired format
        if ip_src and ip_dst:
            if src_port and dst_port:
                print(f"Captured packet: Ethernet / IP / UDP {src_mac} > {dst_mac} {ip_src}:{src_port} > {ip_dst}:{dst_port}")
            else:
                print(f"Captured packet: Ethernet / IP {src_mac} > {dst_mac} {ip_src} > {ip_dst}")
        else:
            print(f"Captured packet: Ethernet {src_mac} > {dst_mac}")

def sniff_packets(interface, duration, filename):
    """
    Start sniffing packets on the specified network interface.
    
    Args:
        interface (str): The network interface to sniff packets on.
        duration (int): Duration for sniffing in seconds.
        filename (str): The name of the file to save captured packets.
    """
    print(f"Starting packet sniffing on interface {interface} for {duration} seconds...")
    global packets
    packets = []  # Initialize the list to store captured packets
    # Sniff packets and call packet_callback for each packet captured
    sniff(iface=interface, prn=packet_callback, timeout=duration)
    # Save captured packets to a PCAP file
    wrpcap(filename, packets)
    print(f"Packet sniffing completed. Packets saved to '{filename}'.")

def main():
    """
    Main function to handle user input and initiate MAC address change, MAC flooding, and packet sniffing.
    """
    def main():
    """
    Main function to handle user input and initiate MAC address change, MAC flooding, and packet sniffing.
    """
    interface = input("Enter the network interface (e.g., eth0, wlan0): ")
    
    current_mac = get_current_mac(interface)
    if current_mac:
        print(f"Current MAC address: {current_mac}")
    else:
        print(f"Could not retrieve MAC address for {interface}.")
        return
    
    change_mac = input("Do you want to specify a MAC address? (yes/no): ").lower()
    if change_mac == "yes":
        new_mac = input("Enter the new MAC address: ")
    else:
        new_mac = generate_random_mac()
        print(f"Generated random MAC address: {new_mac}")
    
    set_mac(interface, new_mac)
    
    flood_duration = int(input("Enter the duration for flooding (in seconds): "))
    print(f"Starting MAC flooding on interface {interface} with MAC address {new_mac} for {flood_duration} seconds...")
    flood_mac(interface, flood_duration, new_mac)
    print("MAC flooding completed.")
    
    # Set the interface to promiscuous mode before sniffing
    set_promiscuous_mode(interface, enable=True)
    
    filename = input("Enter the filename to save captured packets (e.g., captured_packets.pcap): ")
    sniff_duration = int(input("Enter the duration for packet sniffing (in seconds): "))
    sniff_packets(interface, sniff_duration, filename)
    
    # Optionally, you can disable promiscuous mode after sniffing
    set_promiscuous_mode(interface, enable=False)

if __name__ == "__main__":
    main()
