#! /usr/bin/python

import os
import paramiko
import socket
import sys
import threading

# Get the current working directory
CWD = os.path.dirname(os.path.realpath(__file__))
# Path to the RSA key
HOSTKEY = paramiko.RSAKey(filename=os.path.join(CWD, 'test_rsa.key'))

# Server class for handling server-side operations
class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    # Method to check if the channel request is allowed
    def check_channel_request(self, kind: str, chanid):
        # Accept only 'session' channel requests
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    # Method to check authentication using username and password
    def check_auth_password(self, username, password):
        # Request username and password from the user
        input_username = input('Enter username here: ')
        input_password = input('Enter password here: ')
        # Check if the provided username and password match the expected values
        if username == input_username and password == input_password:
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

if __name__ == '__main__':
    # Get server IP address from user input
    server_input = input('Input Server IP Address: ')
    server = server_input
    # Get TCP port from user input
    ssh_input = input("Please input TCP Port: ")
    ssh_port = int(ssh_input)

    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set socket options
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind the socket to the server and port
        sock.bind((server, ssh_port))
        # Listen for incoming connections
        sock.listen(100)
        print('[+] Listening for connection ...')
        # Accept a client connection
        client, addr = sock.accept()
    except Exception as e:
        # Print error message if socket creation or binding fails
        print('[-] Listen Failed: ' + str(e))
        sys.exit(1)
    else:
        # Print a message when a connection is successfully established
        print('[+] Got a connection!', client, addr)

    # Create a transport object for SSH
    bhSession = paramiko.Transport(client)
    # Add the RSA key to the server
    bhSession.add_server_key(HOSTKEY)
    # Initialize the server object
    server = Server()
    # Start the SSH server
    bhSession.start_server(server=server)

    # Accept a channel request
    chan = bhSession.accept(20)
    if chan is None:
        # Print an error message if no channel is accepted
        print('*** No channel.')
        sys.exit(1)

    # Print a message when authentication is successful
    print('[+] Authenticated!')
    # Receive and print initial message from the client
    print(chan.recv(1024))
    # Send a welcome message to the client
    chan.send('Welcome to bh_ssh')

    try:
        while True:
            # Get user input for command
            command = input("Enter command: ")
            if command != 'exit':
                # Send command to the channel
                chan.send(command)
                # Receive and print the output
                r = chan.recv(8192)
                print(r.decode())
            else:
                # Send exit command and close the session
                chan.send('exit')
                print('exiting')
                bhSession.close()
                break
    except KeyboardInterrupt:
        # Close the session on keyboard interrupt
        bhSession.close()
