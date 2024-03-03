#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# This script allows you to execute commands on a remote server over SSH. 
# It prompts the user for the server's IP address, port number, and the command to execute. 
# The script then establishes an SSH connection to the server, sends the command, 
# executes it on the server, and returns the output to the client.
# Example Usage:
# 1. Enter Server IP: 192.168.1.10
# 2. Enter port: 22
# 3. Enter your password: ********
# 4. The command to execute on the server: ls
# Example Output:
# file1
# file2
# file3
"""
#################################################################################################
import paramiko
import shlex
import subprocess


def ssh_command(ip, port, user, passwd, command):
    """
    Function to execute a command on a remote server over SSH.

    Args:
    - ip (str): The IP address of the remote server.
    - port (int): The port number for the SSH connection.
    - user (str): The username for the SSH connection.
    - passwd (str): The password for the SSH connection.
    - command (str): The command to execute on the remote server.
    """
    try:
        # Create an SSH client instance
        client = paramiko.SSHClient()
        # Automatically add the server's host key
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Connect to the server
        client.connect(ip, port=port, username=user, password=passwd)

        # Open a session on the SSH connection
        ssh_session = client.get_transport().open_session()
        if ssh_session.active:
            # Send the command to the remote server
            ssh_session.exec_command(command)
            # Read and print the output of the command
            while True:
                # Read the output of the command
                command_output = ssh_session.recv(1024).decode()
                # Check if the command is 'exit' to close the connection
                if command_output.strip() == 'exit':
                    break
                # Execute the command on the local machine and send the output back to the server
                cmd_output = subprocess.check_output(shlex.split(command_output), shell=True)
                ssh_session.send(cmd_output)
            # Close the SSH connection
            client.close()
    except Exception as e:
        # Print any exceptions that occur during the execution of the function
        print(f"An error occurred: {e}")


if __name__ == '__main__':
    # Get the current user's username
    import getpass

    user = getpass.getuser()
    # Get the password from the user
    password = getpass.getpass(prompt="Enter your password: ")

    # Get the IP address and port number of the server from the user
    ip = input('Enter Server IP: ')
    port = int(input('Enter port: '))
    # Call the ssh_command function with the provided inputs
    ssh_command(ip, port, user, password, 'ClientConnected')
