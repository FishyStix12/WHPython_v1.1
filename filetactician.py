#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 6th 2024
# Description of the Script:
# The script is a versatile monitoring tool designed to observe file system activities either
# locally or on a remote host. It offers two modes of operation: "monitor" and "client". In 
# "monitor" mode, it actively tracks file system changes within specified directories on the 
# local machine using Windows-specific functionality. Meanwhile, in "client" mode, it connects 
# to a remote host, allowing users to monitor activities on that machine by receiving and 
# printing data transmitted from the remote host. This flexibility enables users to choose
# between monitoring their own system or observing the activities of a remote system,
# enhancing their ability to oversee and manage file operations across different environments.
#################################################################################################
import os
import tempfile
import threading
import win32con
import win32file
import win32clipboard
import time
import psutil  # Process and system utilities (for Linux process monitoring)
import socket

# Define constants for file actions
FILE_CREATED = 1
FILE_DELETED = 2
FILE_MODIFIED = 3
FILE_RENAMED_FROM = 4
FILE_RENAMED_TO = 5
FILE_COPIED = 8  # Custom action for file copy
FILE_PASTED = 9  # Custom action for file paste

# Define constant for monitoring file system changes
FILE_LIST_DIRECTORY = 0x0001

# Directories to monitor
PATHS = ['c:\\WINDOWS\\Temp', tempfile.gettempdir()]

# Global variables to store copied and pasted file paths
copied_file_path = None
pasted_file_path = None

def monitor_windows(path_to_watch):
    """Monitor file changes on Windows."""
    # Create a file handle to the directory for monitoring
    h_directory = win32file.CreateFile(
        path_to_watch,
        FILE_LIST_DIRECTORY,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE |
        win32con.FILE_SHARE_DELETE,  # Share mode for other processes
        None,  # Security attributes (None for default)
        win32con.OPEN_EXISTING,  # Open an existing file or device
        win32con.FILE_FLAG_BACKUP_SEMANTICS,  # Flag for directory access
        None  # Template file (None for directories)
    )

    while True:
        try:
            # Read directory changes
            results = win32file.ReadDirectoryChangesW(
                h_directory,  # Directory handle
                1024,  # Buffer size
                True,  # Watch subtree (True for all subdirectories)
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY |
                win32con.FILE_NOTIFY_CHANGE_SIZE,  # Change filter flags
                None,  # Asynchronous I/O event (None for synchronous)
                None  # Overlapped structure (None for synchronous)
            )

            for action, file_name in results:
                full_filename = os.path.join(path_to_watch, file_name)

                # Handle different file actions
                if action == FILE_CREATED:
                    print(f'[+] Created {full_filename}')
                elif action == FILE_DELETED:
                    print(f'[-] Deleted {full_filename}')
                elif action == FILE_MODIFIED:
                    print(f'[*] Modified {full_filename}')
                    try:
                        print('[vvv] Dumping contents ...')
                        with open(full_filename) as f:
                            contents = f.read()
                        print(contents)
                        print('[^^^] Dump Complete.')
                    except Exception as e:
                        print(f'[!!!] Dump Failed {e}')
                elif action == FILE_RENAMED_FROM:
                    print(f'[>] Renamed from {full_filename}')
                elif action == FILE_RENAMED_TO:
                    print(f'[<] Renamed to {full_filename}')
                elif action == FILE_COPIED:
                    print(f'[+] Copied {full_filename}')
                    global copied_file_path
                    copied_file_path = full_filename
                elif action == FILE_PASTED:
                    print(f'[+] Pasted {full_filename}')
                    global pasted_file_path
                    pasted_file_path = full_filename
                else:
                    print(f'[?] Unknown action on {full_filename}')
        except Exception:
            pass

def client():
    target_ip = input("Enter target host IP address: ")
    target_port = int(input("Enter target port: "))

    # Connect to the remote host
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((target_ip, target_port))
            print(f"Connected to {target_ip}:{target_port}")

            while True:
                # Receive data from the remote host and print it
                data = s.recv(1024).decode()
                if not data:
                    break
                print(data)
        except ConnectionRefusedError:
            print("Connection refused. Make sure the remote host is accepting connections.")
        except Exception as e:
            print(f"An error occurred: {e}")

def main():
    mode = input("Choose mode (monitor/client): ").lower()
    if mode == "monitor":
        # Start monitoring on Windows
        for path in PATHS:
            monitor_thread = threading.Thread(target=monitor_windows, args=(path,))
            monitor_thread.start()  # Start monitoring thread
    elif mode == "client":
        client()
    else:
        print("Invalid mode. Choose 'monitor' or 'client'.")

if __name__ == '__main__':
    main()
