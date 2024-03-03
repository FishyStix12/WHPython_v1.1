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
