from scapy.all import *

def get_user_input(prompt, default=None):
    user_input = input(prompt)
    if user_input.strip() == "":
        return default
    return user_input.strip()

def send_custom_packet():
    # Get user input for Source IP, Source Port, Destination IP, and Destination Port
    src_ip = get_user_input("Enter Source IP (default: 192.168.1.100): ", "192.168.1.100")
    src_port = int(get_user_input("Enter Source Port (default: 12345): ", "12345"))
    dst_ip = get_user_input("Enter Destination IP (default: 192.168.1.200): ", "192.168.1.200")
    dst_port = int(get_user_input("Enter Destination Port (default: 80): ", "80"))

    # Create a TCP packet with user-defined parameters
    packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S")

    # Display the packet details
    print("\nCrafted Packet:")
    print(packet.summary())

    # Send the packet
    send(packet)
    print(f"Packet sent from {src_ip}:{src_port} to {dst_ip}:{dst_port}")

def capture_ack_packets():
    def process_packet(packet):
        # Check if the packet has a TCP layer and is an ACK packet
        if packet.haslayer(TCP) and packet[TCP].flags == "A":  # "A" means ACK flag
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            seq_num = packet[TCP].seq
            ack_num = packet[TCP].ack

            print(f"\nCaptured ACK Packet:")
            print(f"Source IP: {src_ip}")
            print(f"Destination IP: {dst_ip}")
            print(f"Sequence Number (SEQ): {seq_num}")
            print(f"Next Sequence Number (ACK/NSN): {ack_num}")
            print("-" * 50)

    # Prompt user for interface to sniff on (optional, defaults to default interface)
    interface = get_user_input("Enter network interface to sniff on (default: eth0): ", "eth0")

    print(f"\nStarting packet capture on {interface}...")
    
    # Sniff TCP packets and apply the function to process ACK packets
    sniff(iface=interface, filter="tcp", prn=process_packet, store=0)

def main():
    while True:
        print("\nMenu:")
        print("1. Send a custom TCP packet")
        print("2. Capture and analyze ACK packets")
        print("3. Exit")

        choice = input("Enter your choice (1, 2, 3): ")

        if choice == '1':
            send_custom_packet()
        elif choice == '2':
            capture_ack_packets()
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
