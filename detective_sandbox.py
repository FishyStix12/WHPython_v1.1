#! /usr/bin/bash
#################################################################################################
# Author: Nicholas Fisher
# Date: March 5th 2024
# Important Note:
# Description:
# The script provided is a versatile tool designed to ascertain whether a remote host, 
# specified by the user with an IP address and port, likely operates within a sandbox environment.
# It first checks the local system environment, distinguishing between Ubuntu Sandbox and other
# configurations. Utilizing platform-specific libraries, it monitors user activity, detecting 
# keystrokes, mouse clicks, and double-click events, while also tracking time since the last user
# input. However, its key feature lies in the function `is_sandbox(ip, port)`, which establishes
# a connection to the remote host and scrutinizes its behavior. If the connection succeeds, 
# indicating a responsive host, it deduces that the host is not a sandbox. Conversely, 
# if the connection fails, it suggests the host may be operating within a sandbox environment. 
# This capability enables users to assess the nature of remote systems, aiding in security 
# assessments and network reconnaissance.
#################################################################################################
import os
import platform
import random
import sys
import time
import socket

# Function to check if a given IP address and port belong to a sandbox environment
def is_sandbox(ip, port):
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)  # Set timeout for connection attempt

        # Attempt to connect to the remote host
        s.connect((ip, port))
        
        # Send a dummy message and wait for response
        s.send(b"Hello")
        response = s.recv(1024)

        # Close the socket
        s.close()

        # If the connection was successful and a response was received, it's likely not a sandbox
        return True
        
    except socket.error:
        # If there's an error (e.g., connection refused), it might be a sandbox
        return False

# Check if the system is Linux and if the sandbox configuration file exists
if platform.system() == 'Linux' and os.path.exists('/etc/sandbox.conf'):
    print("You are in an Ubuntu Sandbox.")
else:
    print("You are not in an Ubuntu Sandbox.")

# Check if the system is Windows
if platform.system() == 'Windows':
    # Importing necessary libraries for Windows platform
    from ctypes import byref, c_uint, c_ulong, sizeof, Structure, windll
    import win32api

    # Define structure for storing last input information
    class LASTINPUTINFO(Structure):
        _fields_ = [
            ('cbSize', c_uint),
            ('dwTime', c_ulong)
        ]

    # Function to get the time since the last user input event
    def get_last_input():
        struct_lastinputinfo = LASTINPUTINFO()
        struct_lastinputinfo.cbSize = sizeof(LASTINPUTINFO)
        windll.user32.GetLastInputInfo(byref(struct_lastinputinfo))
        run_time = windll.kernel32.GetTickCount()
        elapsed = run_time - struct_lastinputinfo.dwTime
        print(f"[*] It has been {elapsed} milliseconds since the last event.")
        return elapsed

    # Class for detecting user activity
    class Detective:
        def __init__(self):
            self.double_clicks = 0
            self.keystrokes = 0
            self.mouse_clicks = 0

        def get_key_press(self):
            for i in range(0, 0xff):
                state = win32api.GetAsyncKeyState(i)
                if state & 0x0001:
                    if i == 0x1:
                        self.mouse_clicks += 1
                        return time.time()

                    elif i > 32 and i < 127:
                        self.keystrokes += 1
            return None

        def detect(self):
            previous_timestamp = None
            first_double_click = None
            double_click_threshold = 0.35

            max_double_clicks = 10
            max_keystrokes = random.randint(10, 25)
            max_mouse_clicks = random.randint(5, 25)
            max_input_threshold = 30000

            last_input = get_last_input()
            if last_input >= max_input_threshold:
                sys.exit(0)

            detection_complete = False
            while not detection_complete:
                keypress_time = self.get_key_press()
                if keypress_time is not None and previous_timestamp is not None:
                    elapsed = keypress_time - previous_timestamp

                    if elapsed <= double_click_threshold:
                        self.mouse_clicks -= 2
                        self.double_clicks += 1
                        if first_double_click is None:
                            first_double_click = time.time()
                        else:
                            if self.double_clicks >= max_double_clicks:
                                if (keypress_time - first_double_click <= (max_double_clicks * double_click_threshold)):
                                    sys.exit(0)

                    if (self.keystrokes >= max_keystrokes and self.double_clicks >= max_double_clicks and self.mouse_clicks >= max_mouse_clicks):
                        detection_complete = True

                    previous_timestamp = keypress_time
                elif keypress_time is not None:
                    previous_timestamp = keypress_time

# Entry point of the script
if __name__ == '__main__':
    # Get remote host details from the user
    remote_host = input("Enter remote host IP address: ")
    remote_port = int(input("Enter remote host port: "))

    # Check if the remote host is likely a sandbox
    if is_sandbox(remote_host, remote_port):
        print("The remote host appears to be a sandbox environment.")
    else:
        print("The remote host does not appear to be a sandbox environment.")
