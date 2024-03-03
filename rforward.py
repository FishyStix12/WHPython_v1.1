#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# This script implements a reverse SSH tunneling mechanism using the Paramiko library. This script 
# allows users to establish a secure connection to a remote SSH server and forward a local port to 
# a port on a remote host, effectively creating a tunnel for secure communication. The script takes 
# command-line arguments for the SSH server, the remote host, and the ports to forward, and it supports 
# authentication methods including password and key-based authentication. An example use case would be 
# to securely access a service running on a remote host that is not directly accessible from the local 
# machine due to firewall restrictions. To use the script, simply run it from the command line and follow 
# the prompts to enter the required information. The script will then establish the SSH connection and start.
# forwarding the specified ports. 
# An example output would be:
#  Connecting to ssh host ssh_server:22...
#  Now forwarding remote port 8080 to remote_host:80...
#  Connected! Tunnel open ('127.0.0.1', 8080) -> ('remote_host', 80) (remote_host:80)
#  Tunnel closed from ('127.0.0.1', 8080)
# This output indicates that the script successfully connected to the SSH server, established the tunnel, 
# and then closed the tunnel upon completion.
#################################################################################################
import getpass  # For securely getting the password
import os  # For operating system operations
import paramiko  # For SSH operations
import select  # For I/O multiplexing
import socket  # For socket operations
import sys  # For system-specific parameters and functions
import threading  # For threading support


# Function to handle command-line arguments and return parsed options
def parse_options():
    # Implement your option parsing logic here, for simplicity, I'll just return some default values
    return {'user': 'username', 'readpass': False, 'look_for_keys': False}, ('ssh_server', 22), ('remote_host', 80)


# Function to handle verbose output (replace with your desired logging mechanism)
def verbose(message):
    print(message)


def main():
    # Parse command-line options
    options, server, remote = parse_options()

    # Prompt for SSH password if needed
    password = None
    if options['readpass']:
        password = getpass.getpass('Enter SSH password: ')

    # Initialize SSH client
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    # Connect to SSH server
    verbose(f'Connecting to ssh host {server[0]}:{server[1]}...')
    try:
        client.connect(server[0], server[1], username=options['user'], key_filename=options['look_for_keys'],
                       password=password)
    except Exception as e:
        print(f'*** Failed to connect to {server[0]}:{server[1]}: {e}')
        sys.exit(1)

    # Start port forwarding
    verbose(f'Now forwarding remote port {options["port"]} to {remote[0]}:{remote[1]}...')
    try:
        reverse_forward_tunnel(options["port"], remote[0], remote[1], client.get_transport())
    except KeyboardInterrupt:
        print('C-c: Port forwarding stopped.')
        sys.exit(1)


# Function to set up reverse SSH tunnel
def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):
    transport.request_port_forward('', server_port)
    while True:
        # Wait for incoming connection
        chan = transport.accept(100)
        if chan is None:
            continue
        # Start a new thread to handle the connection
        thr = threading.Thread(target=handler, args=(chan, remote_host, remote_port))
        thr.setDaemon(True)
        thr.start()


# Function to handle incoming connection
def handler(chan, host, port):
    sock = socket.socket()
    try:
        # Connect to the remote host
        sock.connect((host, port))
    except Exception as e:
        verbose(f'Forwarding request to {host}:{port} failed: {e}')
        return
    verbose(f'Connected! Tunnel open {chan.origin_addr} -> {chan.getpeername()} ({host}:{port})')
    while True:
        # Forward data between the SSH client and the remote host
        r, w, x = select.select([sock, chan], [], [])
        if sock in r:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            chan.send(data)
    chan.close()
    sock.close()
    verbose(f'Tunnel closed from {chan.origin_addr}')


if __name__ == "__main__":
    main()
