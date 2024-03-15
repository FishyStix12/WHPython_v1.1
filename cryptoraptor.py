#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 6th 2024
# Important Note:
#  Description of the Script:
# The script is a versatile file encryption tool designed to offer robust security through advanced
# encryption algorithms. It employs a combination of AES and RSA encryption, utilizing key sizes
# optimized for enhanced security. Specifically, RSA keys with a substantial size of 8192 bits are 
# employed for secure key exchange, while AES keys of 512 bits ensure strong symmetric encryption.
# Users can encrypt and decrypt files seamlessly, with the script facilitating key generation and
# transmission for seamless cryptographic operations. With a user-friendly interface and heightened
# security measures, the script provides a reliable solution for safeguarding sensitive data during 
# transmission and storage.
#################################################################################################
import os
import socket
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import base64
import zlib

# Generate new RSA key pair with larger key size
def generate_rsa_keys():
    new_key = RSA.generate(8192)  # Generate a new RSA key pair with a size of 8192 bits for stronger encryption
    private_key = new_key.export_key()  # Export the private key to bytes
    public_key = new_key.public_key().export_key()  # Export the public key to bytes
    return public_key, private_key  # Return the public and private keys

# Create a new directory to store keys
def create_key_directory(directory_name):
    os.makedirs(directory_name, exist_ok=True)  # Create directory if it doesn't exist

# Encrypt a file with stronger AES encryption
def encrypt_file(file_path, key_directory):
    public_key, private_key = generate_rsa_keys()  # Generate new keys for each encryption
    with open(file_path, 'rb') as f:  # Open the file to encrypt in binary mode
        plaintext = f.read()  # Read the plaintext bytes from the file

    compressed_text = zlib.compress(plaintext)  # Compress the plaintext using zlib

    session_key = get_random_bytes(64)  # Generate a random session key of 64 bytes for AES-512
    cipher_aes = AES.new(session_key, AES.MODE_EAX)  # Create an AES cipher object with the session key
    ciphertext, tag = cipher_aes.encrypt_and_digest(compressed_text)  # Encrypt the compressed text

    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))  # Get the RSA cipher object for encryption
    encrypted_session_key = cipher_rsa.encrypt(session_key)  # Encrypt the session key with RSA

    encrypted_data = encrypted_session_key + cipher_aes.nonce + tag + ciphertext  # Combine encrypted data

    with open(f'{file_path}.enc', 'wb') as f:  # Open a file to write the encrypted data
        f.write(base64.b64encode(encrypted_data))  # Encode and write the encrypted data to the file

    # Save the keys to the specified directory
    with open(os.path.join(key_directory, 'public_key.pem'), 'wb') as f:
        f.write(public_key)
    with open(os.path.join(key_directory, 'private_key.pem'), 'wb') as f:
        f.write(private_key)

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

# Send keys to local host
def send_keys_to_local(public_key, target_host, target_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((target_host, target_port))
        s.sendall(public_key)

if __name__ == '__main__':
    key_directory_name = input("Enter the name for the directory to store keys: ")
    create_key_directory(key_directory_name)
    
    target_host = input("Enter the target host IP address: ")
    target_port = int(input("Enter the target port: "))
    
    while True:  # Infinite loop to provide menu until user chooses to exit
        print("Choose an option:")  # Prompt user to choose an option
        print("1. Encrypt file(s)")  # Option to encrypt files
        print("2. Decrypt file(s)")  # Option to decrypt files
        print("3. Exit")  # Option to exit the program
        choice = input("Enter your choice: ")  # Ask user for their choice

        if choice == '1':  # If user chooses to encrypt files
            num_files = int(input("Enter the number of files to encrypt: "))  # Ask user for the number of files
            for _ in range(num_files):  # Loop over the number of files
                file_path = input("Enter the file path to encrypt: ")  # Ask user for file path to encrypt
                encrypt_file(file_path, key_directory_name)  # Encrypt the file
                print(f"Encryption of {file_path} complete.")  # Print message indicating encryption is complete
        elif choice == '2':  # If user chooses to decrypt files
            num_files = int(input("Enter the number of files to decrypt: "))  # Ask user for the number of files
            for _ in range(num_files):  # Loop over the number of files
                file_path = input("Enter the file path to decrypt: ")  # Ask user for file path to decrypt
                private_key_path = input("Enter the path to the private key: ")  # Ask user for private key path
                decrypt_file(file_path, private_key_path)  # Decrypt the file
                print(f"Decryption of {file_path} complete.")  # Print message indicating decryption is complete
        elif choice == '3':  # If user chooses to exit
            print("Exiting...")  # Print message indicating program is exiting
            break  # Break out of the loop and exit the program
        else:  # If user enters an invalid choice
            print("Invalid choice. Please try again.")  # Print error message
