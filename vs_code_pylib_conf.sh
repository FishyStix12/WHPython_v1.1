#!/bin/bash
#################################################################################################
# Author: Nicholas Fisher
# Date: March 3rd 2024
# Description of Script
# This script configures a Visual Studio Code environment with Git Bash terminal for 
# Python development. It sets up a virtual environment named `venv`, installs system packages 
# and Python libraries such as `scapy`, `python-nmap`, `requests`, `lxml`, `beautifulsoup4`, 
# `github3.py`, and others using `pip`. Additionally, it includes steps for installing `setuptools`
# and `pynput` if needed, ensuring a complete setup for tasks like network scanning, web requests,
# GUI development, and cryptography.
#################################################################################################
python -m venv venv
source venv/Scripts/activate

# Install necessary system packages
pip install --upgrade pip setuptools wheel libffi-dev libpython3-dev python3-xlib

# Install Python libraries
pip3 install --upgrade pip
pip3 install scapy python-nmap requests lxml beautifulsoup4 github3.py pybase64 \
  importlib-metadata jsonlib2 random sys threading time datetime python-magic \
  pythoncom psutil pynput ctypes platform argparse pycryptodomex smtplib pywin32 \
  idna urllib3 ftplib Flask certifi itsdangerous colorama wmi click Werkzeug \
  MarkupSafe Jinja2 Pillow requests cryptography

# Additional steps for pi library installation (if needed)
pip install setuptools
pip3 install pynput
echo "Python Library Configuration Complete!"
