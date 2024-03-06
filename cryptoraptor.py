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
# This script is a versatile encryption and decryption tool utilizing AES and RSA algorithms. 
# Upon execution, the script presents the user with a menu offering options to either encrypt or 
# decrypt files. For encryption, the script generates new RSA key pairs for each file, encrypts the 
# file using AES, and saves the encrypted data along with the corresponding public and private keys. 
# Decryption requires the user to provide the path to the private key associated with the encrypted file. 
# The script then decrypts the file using the specified private key and outputs the decrypted content. 
# For instance, a user can encrypt a sensitive document by selecting the "Encrypt file(s)" option, 
# providing the file path, and subsequently decrypt it using the "Decrypt file(s)" option with the 
# corresponding private key path. Example output might include messages confirming successful encryption 
# or decryption operations, along with any errors encountered during execution.
#################################################################################################
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import base64
import zlib
import os

# Generate new RSA key pair
def generate_rsa_keys():
    new_key = RSA.generate(4096)  # Generate a new RSA key pair with a size of 4096 bits
    private_key = new_key.export_key()  # Export the private key to bytes
    public_key = new_key.public_key().export_key()  # Export the public key to bytes
    return public_key, private_key  # Return the public and private keys

# Encrypt a file
def encrypt_file(file_path):
    public_key, private_key = generate_rsa_keys()  # Generate new keys for each encryption
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

    # Save the keys
    with open(f'{file_path}_public_key.pem', 'wb') as f:  # Save the public key to a text file
        f.write(public_key)
    with open(f'{file_path}_private_key.pem', 'wb') as f:  # Save the private key to a text file
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

if __name__ == '__main__':
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
                encrypt_file(file_path)  # Encrypt the file
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


