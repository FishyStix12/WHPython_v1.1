#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: September 18 2024
# Description of Script
# The SeqSensei script is an advanced network analysis tool that empowers users to send and 
# analyze TCP packets with precision. Through an interactive menu, users can craft and send 
# custom TCP packets with SYN, RST, FIN, and ACK flags, allowing for comprehensive network 
# testing and analysis. The script also features a packet capture mode that listens on a 
# specified network interface to identify and examine ACK packets, extracting crucial information
# such as the Next Sequence Number (NSN). Ideal for network engineers, security professionals, and
# ethical hackers, **SeqSensei** combines interactive packet crafting with real-time packet 
# analysis to facilitate deeper insights into TCP communications and network behavior.1
#################################################################################################
from scapy.all import *

def get_user_input(prompt, default=None):
    """
    Prompts the user for input with a default value.
    Returns the user's input or the default value if no input is provided.
    """
    user_input = input(prompt)
    if user_input.strip() == "":
        return default
    return user_input.strip()

def send_custom_packet():
    """
    Crafts and sends a custom TCP packet based on user-defined parameters.
    """
    packet_type = get_user_input("Enter packet type (SYN, RST, FIN, ACK) (default: SYN): ", "SYN").upper()
    
    # Get user input for Source IP, Source Port, Destination IP, and Destination Port
    src_ip = get_user_input("Enter Source IP (default: 192.168.1.100): ", "192.168.1.100")
    src_port = int(get_user_input("Enter Source Port (default: 12345): ", "12345"))
    dst_ip = get_user_input("Enter Destination IP (default: 192.168.1.200): ", "192.168.1.200")
    dst_port = int(get_user_input("Enter Destination Port (default: 80): ", "80"))

    # Map packet types to TCP flags
    flags = {
        "SYN": "S",
        "RST": "R",
        "FIN": "F",
        "ACK": "A"
    }
    
    # Create the TCP packet with the appropriate flag
    if packet_type in flags:
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags=flags[packet_type])
    else:
        print("Invalid packet type. Using default SYN.")
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S")

    # Display the packet details
    print("\nCrafted Packet:")
    print(packet.summary())  # Provides a summary of the crafted packet

    # Send the packet over the network
    send(packet)
    print(f"{packet_type} Packet sent from {src_ip}:{src_port} to {dst_ip}:{dst_port}")

def capture_ack_packets():
    """
    Captures TCP packets on the specified interface and processes ACK packets to extract NSN.
    """
    def process_packet(packet):
        """
        Processes each captured packet to check if it's an ACK packet and extracts relevant information.
        """
        # Check if the packet has a TCP layer and if it is an ACK packet
        if packet.haslayer(TCP) and packet[TCP].flags == "A":  # "A" stands for ACK flag
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            seq_num = packet[TCP].seq
            ack_num = packet[TCP].ack

            # Display the details of the captured ACK packet
            print(f"\nCaptured ACK Packet:")
            print(f"Source IP: {src_ip}")
            print(f"Destination IP: {dst_ip}")
            print(f"Sequence Number (SEQ): {seq_num}")
            print(f"Next Sequence Number (ACK/NSN): {ack_num}")
            print("-" * 50)  # Separator for readability

    # Prompt user for network interface to sniff on
    interface = get_user_input("Enter network interface to sniff on (default: eth0): ", "eth0")

    # Inform user that packet capture is starting
    print(f"\nStarting packet capture on {interface}...")

    # Sniff TCP packets on the specified interface and apply the process_packet function to each
    sniff(iface=interface, filter="tcp", prn=process_packet, store=0)

def main():
    """
    Main function to display an interactive menu for user choices.
    """
    while True:
        print("\nMenu:")
        print("1. Send a custom TCP packet (SYN, RST, FIN, ACK)")
        print("2. Capture and analyze ACK packets")
        print("3. Exit")

        choice = input("Enter your choice (1, 2, 3): ")

        if choice == '1':
            send_custom_packet()  # Call function to send a custom packet
        elif choice == '2':
            capture_ack_packets()  # Call function to capture and analyze ACK packets
        elif choice == '3':
            print("Exiting...")  # Exit the script
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")  # Handle invalid input

if __name__ == "__main__":
    main()  # Run the main function to start the script
