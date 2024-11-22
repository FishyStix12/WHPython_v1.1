#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 3rd 2024
# Description of Script
# This script is used to help Pentesters to whip up a UDP client. The user inputs an IPv4 address
# or hostname and UDP Port to establish the client connection. Runs on Python 3.
#################################################################################################
#Imports the python socket module
import socket

# THese lines establish what the target host and target port for the UDP Client will be.
target_host = input("Please enter the Appropriate IPv4 Address or Hostname: ")
target_port = int(input("Please enter the Target UDP port: "))
#target_host = "127.0.0.1"
#target_port = 9997

#This line creates the socket object
#The AF_INET parameter indicates we will be using IPv4
# THe SOCK_DGRAM parameter indicates this will be a UDP client
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# This line sends some data to the server you want to send data to
client.sendto(b"AAABBBCCC",(target_host,target_port))

# This line recieves some UDP data back such as details of the remote host and port.
data, addr = client.recvfrom(4096)

# Prints and decodes the data and closes the client.
print(data.decode())
client.close()

