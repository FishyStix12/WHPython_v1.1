#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: August 22 2024
# Description of Script
# This script is designed to change the MAC address of a network interface on Linux-based systems.
# It allows you to either specify a new MAC address or generate a random one. The script works 
# by temporarily disabling the network interface, applying the new MAC address, and then 
# re-enabling the interface. It retrieves the current MAC address, provides an option to input a
# specific address or use a randomly generated one, and requires root privileges to modify network
# settings. Please ensure you have the necessary permissions and understand the impact of changing
# your MAC address before using this script.
#################################################################################################
import subprocess
import re
import random

def get_current_mac(interface):
    """
    Retrieve the current MAC address of the specified network interface.
    """
    result = subprocess.run(["ifconfig", interface], capture_output=True, text=True)
    # Use regex to extract MAC address from the ifconfig output
    match = re.search(r"ether\s([0-9a-fA-F:]{17})", result.stdout)
    if match:
        return match.group(1)
    else:
        return None

def random_mac():
    """
    Generate a random MAC address.
    The first three bytes (00:16:3e) are a locally administered address prefix.
    """
    mac = [0x00, 0x16, 0x3e, random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: f"{x:02x}", mac))

def change_mac(interface, new_mac):
    """
    Change the MAC address of the specified network interface.
    This involves:
    - Bringing the interface down
    - Changing the MAC address
    - Bringing the interface back up
    """
    # Bring the network interface down
    subprocess.run(["sudo", "ifconfig", interface, "down"])
    # Change the MAC address
    subprocess.run(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
    # Bring the network interface back up
    subprocess.run(["sudo", "ifconfig", interface, "up"])

def main():
    """
    Main function to handle user input and MAC address change.
    """
    interface = input("Enter the network interface (e.g., eth0, wlan0): ")

    current_mac = get_current_mac(interface)
    if current_mac:
        print(f"Current MAC address: {current_mac}")
    else:
        print(f"Could not find MAC address for {interface}")
        return

    change_choice = input("Do you want to specify a MAC address? (yes/no): ").lower()

    if change_choice == "yes":
        new_mac = input("Enter the new MAC address: ")
    else:
        # Generate a random MAC address
        new_mac = random_mac()
        print(f"Generated random MAC address: {new_mac}")

    # Change the MAC address
    change_mac(interface, new_mac)

    # Verify that the MAC address has been changed
    updated_mac = get_current_mac(interface)
    if updated_mac == new_mac:
        print(f"MAC address successfully changed to: {updated_mac}")
    else:
        print("Failed to change MAC address")

if __name__ == "__main__":
    main()
