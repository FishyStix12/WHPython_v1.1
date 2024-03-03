#!/usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# This script allows the user to execute a command on a remote server over SSH.
# It prompts the user for their username, password, server IP, port, and command.
# If no input is provided for the IP, port, or command, default values are used.
# Example usage: python script.py
# Example output:
# Username: user
# Password: 
# Enter Server IP: 192.168.1.203
# Enter port or <CR>: 2222
# Enter command or <CR>: id
# --- Output ---
# uid=0(root) gid=0(root) groups=0(root)
#################################################################################################
# Import the paramiko library for SSH connections
import paramiko

# Function to execute a command over SSH
def ssh_command(ip, port, user, passwd, cmd):
    # Create an SSH client instance
    client = paramiko.SSHClient()
    # Automatically add the server's host key
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Connect to the SSH server using the provided credentials
    client.connect(ip, port=port, username=user, password=passwd)

    # Execute the command on the SSH server
    _, stdout, stderr = client.exec_command(cmd)
    # Read the output and error streams
    output = stdout.readlines() + stderr.readlines()
    # If there is any output, print it
    if output:
        print('--- Output ---')
        for line in output:
            print(line.strip())

# Main block of the script
if __name__ == '__main__':
    import getpass
    # Prompt the user for their username and password
    user = input('Username: ')
    password = getpass.getpass()

    # Prompt the user for the server IP, port, and command
    ip = input('Enter Server IP: ') or '192.168.1.203'
    port = input('Enter port or <CR>: ') or '2222'
    cmd = input('Enter command or <CR>: ') or 'id'
    # Call the ssh_command function with the provided inputs
    ssh_command(ip, port, user, password, cmd)
