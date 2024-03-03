#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 3rd 2024
# Description of Script
# This script is used to help Pentesters to whip up a Threaded TCP Server on python 3. Please
# Provide an IPv4 Address or hostname and the appropriate TCP port for this script to work.
#################################################################################################
#imports the socket and threading modules for python 3.
import socket
import threading

#Asks the user for the IP Address and TCP port the user wants the server to listen on.
IP = input("Please enter the IP address you want the TCP Server to listen on: ")
PORT = int(input("Please enter the TCP port you want the TCP Server to listen on: "))

# To start we pass the IPv4 Address or Hostname and TCP port we want the server to listen on.
# Then we tell the server to start listening, with a maz back-log of connection set to 5.
# Then the server is put into the main loop, where it waits for an incoming connection. 
def main():
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((IP, PORT))
	server.listen(5)
	print(f'[*] Listening on {IP}:{PORT}')

#When the client connects we recieve the client socket in the client variable, and the remote connections
# details in the address variable.
# Then the script creates a new thread object that points to ourhandle_client function, and then
# it passes the client socket object as an argument.
# We then start the thread to handle the client connection, at which the main server loop is ready to
# handle another incoming connection.
	while True:
		client, address = server.accept()
		print(f'[*] Accepted Connection from {address[0]}:{address[1]}')
		client_handler = threading.Thread(target=handle_client, args=(client,))
		client_handler.start()
# The handle-client function performs recv() (recv is is the maximum length of the message to read at once. 
# It will try to read up to that number, but no more, then return the read value.) and then sends a simple message
# Back to the client.
def handle_client(client_socket):
	with client_socket as sock:
		request = sock.recv(1024)
		print(f'[*] Received: {request.decode("utf-8")}')
		sock.send(b'ACK')

if __name__=='__main__':
	main()
