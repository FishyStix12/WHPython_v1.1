#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 3rd 2024
# Description of Script
# This script is used to help Pentesters to whip up a TCP client. The user inputs an IPv4 address
# or hostname and TCP Port to establish the client connection. Runs on Python 3.
#################################################################################################
#Importants the socket module for python 3.
import socket

# These lines establish what the target host and target port for the TCP client will be.
target_host = input("Please enter an IPv4 address or Hostname: ")
target_port = input("Please enter the appropriate TCP Port: ")X

# this line creates a socket object.
# The AF_INET parameter indicates we will be using a standard IPv4 address or hostname.
# The SOCK_STREAM parameter indicates that this will be a TCP client
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#This line connects the client
client.connect((target_host,target_port))

#This line sends some data
client.send(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")

#This line recieves data
response = client.recv(4096)

#This line prints and decodes the recieved data and closes the client
print(response.decode())
client.close()

