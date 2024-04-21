#!/bin/bash
#################################################################################################
# Author: Nicholas Fisher
# Date: March 2nd 2024
# Description of Script
#  The script is designed to set up a Python development environment on Kali Linux for ethical 
# hacking purposes. It updates system packages, installs necessary system libraries, 
# and then proceeds to install various Python libraries commonly used by ethical hackers. 
# These libraries include tools for network scanning (scapy, nmap), web scraping and parsing 
# (beautifulsoup4, lxml), interacting with GitHub (github3.py), handling encryption and encoding
# (base64, pycryptodomex), sending emails (smtplib), working with Windows hooks (pywin32, 
# pywinhook), and more.
#################################################################################################
# Update system packages
sudo apt update
sudo apt-get install libpcap-dev
# Install necessary system packages
sudo apt install -y python3 python3-pip libffi-dev libpython3-dev python3-xlib

# Install Python libraries
pip3 install --upgrade pip
pip3 install scapy python-nmap requests lxml beautifulsoup4 github3.py pybase64 \
  importlib-metadata jsonlib2 random sys threading time datetime python-magic \
  pythoncom psutil pynput ctypes platform argparse pycryptodomex smtplib pywin32 \
  idna urllib3 ftplib Flask certifi itsdangerous colorama wmi click Werkzeug \
  MarkupSafe Jinja2

pip install Pillow
pip install pillow requests
# Install pi library using easy_install
pip install setuptools
pip install cryptography

# Additional steps for pywinhook installation (if needed)
pip3 install pywinhook
pip3 install pynput
echo "Python Library Configuration Complete!"

