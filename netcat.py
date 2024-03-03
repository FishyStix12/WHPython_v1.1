#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 3rd 2024
# Description of Script
# A Python implementation of the NetCat tool, offering file transfer, command execution,
# and interactive command shell functionalities over TCP/IP connections. This tool provides
# a flexible command-line interface for both client and server modes, allowing for easy
# network operations and troubleshooting.
#################################################################################################

# Import necessary modules
import argparse  # For parsing command-line arguments
import socket  # For socket programming
import shlex  # For splitting shell-like syntax
import subprocess  # For executing shell commands
import sys  # For system-specific parameters and functions
import textwrap  # For text wrapping
import threading  # For threading support

# Function to execute a shell command and return its output
def execute(cmd):
    # Strip leading/trailing whitespace from the command
    cmd = cmd.strip()
    if not cmd:
        return
    # Execute the command and capture its output
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    # Decode the output bytes to a string and return it
    return output.decode()

# Class representing the NetCat tool
class NetCat:
    def __init__(self, args, buffer=None):
        # Initialize the NetCat object with command-line arguments and an optional buffer
        self.args = args
        self.buffer = buffer
        # Create a TCP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set socket option to reuse the address
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        # Start listening or send data based on command-line arguments
        if self.args.listen:
            self.listen()  # Listen for incoming connections
        else:
            self.send()  # Connect to a target and send data

    def send(self):
        # Connect to the target address and port
        self.socket.connect((self.args.target, self.args.port))
        # If a buffer is provided, send it to the target
        if self.buffer:
            self.socket.send(self.buffer)

        try:
            while True:
                recv_len = 1
                response = ''
                # Receive data in chunks until no more data is available
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                # Print the received data and wait for user input
                if response:
                    print(response)
                    user_input = input('> ')  # Read user input
                    user_input += '\n'
                    self.socket.send(user_input.encode())  # Send user input to the target
        except KeyboardInterrupt:
            print('User terminated.')
            self.socket.close()
            sys.exit()

    def listen(self):
        # Bind the socket to the target address and port
        self.socket.bind((self.args.target, self.args.port))
        # Start listening for incoming connections
        self.socket.listen(5)
        while True:
            # Accept incoming connection
            client_socket, _ = self.socket.accept()
            # Create a new thread to handle the client connection
            client_thread = threading.Thread(target=self.handle, args=(client_socket,))
            client_thread.start()

    def handle(self, client_socket):
        # Handle incoming client connection
        if self.args.execute:
            # Execute a command and send the output to the client
            output = execute(self.args.execute)
            client_socket.send(output.encode())
        elif self.args.upload:
            # Receive a file from the client and save it to disk
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
            message = f'Saved file {self.args.upload}'
            client_socket.send(message.encode())
        elif self.args.command:
            # Receive commands from the client and execute them
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send('BHP: #> '.encode())  # Send command prompt to the client
                    while b'\n' not in cmd_buffer:
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f'server killed {e}')
                    self.socket.close()
                    sys.exit()

if __name__ == '__main__':
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='BHP Net Tool', formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent('''Example:
        netcat.py -t 192.168.1.108 -p 5555 -l -c #command shell
        netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt #uploads to file
        netcat.py -t 192.168.1.108 -p 5555 -l -e='cat /etc/passwd' # executes a command
        echo "ABC" | netcat.py -t 192.169.1.108 -p 135 # echo text to server port 135
        netcat.py -t 192.168.1.108 -p 5555 # connect to a server
    '''))
    parser.add_argument('-c', '--command', action='store_true', help='command shell')  # Corrected argument name
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int, default=5555, help='specified port')
    parser.add_argument('-t', '--target', default='192.168.1.203', help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    args = parser.parse_args()
    if args.command:  # Corrected attribute name
        buffer = ''  # Set buffer to empty string for command shell
    else:
        buffer = sys.stdin.read()

    nc = NetCat(args, buffer.encode())
    nc.run()
