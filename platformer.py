#! /usr/bin/python
#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# This script utilizes the platform module to gather detailed information about the operating 
# system of a target host. This information includes the operating system name (system), network 
# name of the machine (node), operating system release (release), operating system version (version), 
# machine type (machine), and processor type (processor). The get_os_details function collects this
# information into a dictionary and returns it. When the script is executed, it calls the 
# get_os_details function and then iterates over the dictionary to print each key-value pair
# in a readable format.
# Example Output:
# system: Windows
# node: DESKTOP-ABC123
# release: 10
# version: 10.0.19041
# machine: AMD64
# processor: Intel64 Family 6 Model 142 Stepping 11, GenuineIntel
#################################################################################################
import platform

def get_os_details():  # Define a function named get_os_details to retrieve operating system details
    details = {  # Create a dictionary to store the operating system details
        "system": platform.system(),  # Get the operating system name (e.g., 'Linux', 'Windows')
        "node": platform.node(),  # Get the network name of the machine (e.g., 'hostname' or IP address)
        "release": platform.release(),  # Get the operating system release (e.g., '10' for Windows 10)
        "version": platform.version(),  # Get the operating system version
        "machine": platform.machine(),  # Get the machine type (e.g., 'x86_64' for 64-bit architecture)
        "processor": platform.processor(),  # Get the processor type (e.g., 'Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz')
    }
    return details  # Return the dictionary containing the operating system details

if __name__ == "__main__":  # Check if the script is being run as the main program
    os_details = get_os_details()  # Call the get_os_details function to retrieve the operating system details
    for key, value in os_details.items():  # Iterate over the key-value pairs in the os_details dictionary
        print(f"{key}: {value}")  # Print each operating system detail in a formatted string
