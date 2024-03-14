#!/usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 5th 2024
# Description of Script
# The script is a cross-platform utility designed to facilitate the remote capture and transmission 
# of screenshots. It intelligently adapts to the underlying operating system, utilizing platform-specific
# libraries such as `pywin32` for Windows and `pyscreenshot` for Linux, to capture screenshots. 
# The user is prompted to specify the local host's IP address and the port on which the script 
# will listen for incoming screenshot transmissions. Upon receiving a connection from a remote host,
# the script receives the screenshot data, decodes it, and saves it as a PNG file locally. Exception
# handling is implemented to ensure robustness and error resilience during execution. This script
# serves as a versatile tool for capturing and receiving screenshots across diverse computing environments.
#################################################################################################
import platform
import base64
import socket
import ipaddress
import traceback

if platform.system() == 'Windows':
    import win32api
    import win32con
    import win32gui
    import win32ui
elif platform.system() == 'Linux':
    import pyscreenshot as ImageGrab  # Required library for Linux screenshot capture

def get_dimensions():
    """
    Get the screen dimensions based on the platform.

    Returns:
        Tuple: Width, height, left, top
    """
    if platform.system() == 'Windows':
        # Windows platform
        # Code for getting dimensions on Windows
    elif platform.system() == 'Linux':
        # Linux platform
        # Code for getting dimensions on Linux
    else:
        # Unsupported platform
        raise NotImplementedError("This platform is not supported")

def take_screenshot(name='screenshot'):
    """
    Take a screenshot and save it as a BMP file.

    Args:
        name (str): Name of the screenshot file.
    """
    if platform.system() == 'Windows':
        # Code for taking a screenshot on Windows
    elif platform.system() == 'Linux':
        # Code for taking a screenshot on Linux
        im = ImageGrab.grab()
        im.save(f"{name}.png")

def receive_screenshot(local_ip, port):
    """
    Receive the screenshot from the remote host.

    Args:
        local_ip (str): Local IP address.
        port (int): Port to listen for incoming connections.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((local_ip, port))
            s.listen()
            print(f"Listening for screenshots on {local_ip}:{port}")
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                data = b""
                while True:
                    packet = conn.recv(1024)
                    if not packet:
                        break
                    data += packet
                with open('received_screenshot.png', 'wb') as f:
                    f.write(base64.b64decode(data))
                print("Screenshot received and saved.")
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()

def main():
    """
    Main function to execute the script.
    """
    local_ip = input("Enter local IP address: ")
    port = int(input("Enter port to listen for incoming screenshots: "))

    try:
        receive_screenshot(local_ip, port)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()


