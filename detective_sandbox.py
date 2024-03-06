#! /usr/bin/bash

import os
import platform
import random
import sys
import time

# Check if the system is Linux and if the sandbox configuration file exists
if platform.system() == 'Linux' and os.path.exists('/etc/sandbox.conf'):
    print("You are in an Ubuntu Sandbox.")  # Printing a message indicating the system is in an Ubuntu Sandbox
else:
    print("You are not in an Ubuntu Sandbox.")  # Printing a message indicating the system is not in an Ubuntu Sandbox

# Check if the system is Windows
if platform.system() == 'Windows':
    # Importing necessary libraries for Windows platform
    from ctypes import byref, c_uint, c_ulong, sizeof, Structure, windll  # Importing required modules from ctypes
    import win32api  # Importing the win32api module for Windows API access

    # Define structure for storing last input information
    class LASTINPUTINFO(Structure):
        _fields_ = [
            ('cbSize', c_uint),
            ('dwTime', c_ulong)
        ]

    # Function to get the time since the last user input event
    def get_last_input():
        struct_lastinputinfo = LASTINPUTINFO()  # Creating an instance of the LASTINPUTINFO structure
        struct_lastinputinfo.cbSize = sizeof(LASTINPUTINFO)  # Setting the size of the structure
        windll.user32.GetLastInputInfo(byref(struct_lastinputinfo))  # Calling GetLastInputInfo function from user32.dll
        run_time = windll.kernel32.GetTickCount()  # Getting the tick count since system boot
        elapsed = run_time - struct_lastinputinfo.dwTime  # Calculating elapsed time since last input event
        print(f"[*] It has been {elapsed} milliseconds since the last event.")  # Printing the elapsed time
        return elapsed  # Returning the elapsed time

    # Class for detecting user activity
    class Detective:
        def __init__(self):
            # Initializing counters for tracking user activity
            self.double_clicks = 0  # Counter for double clicks
            self.keystrokes = 0  # Counter for keystrokes
            self.mouse_clicks = 0  # Counter for mouse clicks

        # Function to detect key presses
        def get_key_press(self):
            for i in range(0, 0xff):  # Loop through virtual key codes
                state = win32api.GetAsyncKeyState(i)  # Get the key state
                if state & 0x0001:  # Check if key is pressed
                    if i == 0x1:  # Check if left mouse button is clicked
                        self.mouse_clicks += 1  # Increment mouse click counter
                        return time.time()  # Return current time

                    elif i > 32 and i < 127:  # Check if key corresponds to printable character
                        self.keystrokes += 1  # Increment keystroke counter
            return None  # Return None if no key press is detected

        # Function to detect user activity
        def detect(self):
            previous_timestamp = None  # Initialize variable to store previous timestamp
            first_double_click = None  # Initialize variable to store timestamp of first double click
            double_click_threshold = 0.35  # Threshold for double click in seconds

            # Define maximum thresholds for user activity
            max_double_clicks = 10  # Maximum allowed double clicks
            max_keystrokes = random.randint(10, 25)  # Random maximum keystrokes
            max_mouse_clicks = random.randint(5, 25)  # Random maximum mouse clicks
            max_input_threshold = 30000  # Maximum input threshold in milliseconds

            # Get the time since the last user input event
            last_input = get_last_input()  # Get the time since the last user input event
            if last_input >= max_input_threshold:  # Check if time since last input exceeds threshold
                sys.exit(0)  # Exit the program if threshold is exceeded

            detection_complete = False  # Flag indicating whether detection is complete
            while not detection_complete:  # Loop until detection is complete
                keypress_time = self.get_key_press()  # Get the time of key press
                if keypress_time is not None and previous_timestamp is not None:  # Check if key press is detected and previous timestamp exists
                    elapsed = keypress_time - previous_timestamp  # Calculate elapsed time since last key press

                    if elapsed <= double_click_threshold:  # Check if elapsed time is within double click threshold
                        self.mouse_clicks -= 2  # Decrement mouse click counter (since it was incremented twice)
                        self.double_clicks += 1  # Increment double click counter
                        if first_double_click is None:  # Check if it's the first double click
                            first_double_click = time.time()  # Store timestamp of first double click
                        else:
                            if self.double_clicks >= max_double_clicks:  # Check if maximum double clicks limit is reached
                                if (keypress_time - first_double_click <= (max_double_clicks * double_click_threshold)):  # Check if double clicks occurred within time threshold
                                    sys.exit(0)  # Exit the program if conditions are met

                    if (self.keystrokes >= max_keystrokes and self.double_clicks >= max_double_clicks and self.mouse_clicks >= max_mouse_clicks):  # Check if maximum thresholds are reached
                        detection_complete = True  # Set detection flag to True

                    previous_timestamp = keypress_time  # Update previous timestamp with current timestamp
                elif keypress_time is not None:  # Check if key press is detected
                    previous_timestamp = keypress_time  # Update previous timestamp with current timestamp

    # Entry point of the script
    if __name__ == '__main__':
        # Create Detective object and start detecting user activity
        d = Detective()  # Create Detective object
        d.detect()  # Start detecting user activity
        print('okay.')  # Print "okay" when detection is complete
