#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# This script defines a function get_environment_variables that retrieves and returns the 
# environment variables of the system. It first prints a message indicating that it is in 
# the environment module, then uses the os.environ dictionary to fetch the environment variables. 
# Finally, it iterates over the dictionary and prints each environment variable along with its 
# corresponding value. This script can be used to quickly view the environment variables set on a 
# system, which can be useful for debugging or understanding the current system configuration.
# Example output:
# [*] In environment module.
# PATH: /usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
# LANG: en_US.UTF-8
# HOME: /Users/user

#################################################################################################
import os  # Import the os module for interacting with the operating system

def get_environment_variables():  # Define a function to retrieve environment variables
    """Retrieve and return the environment variables."""  # Docstring describing the function
    print("[*] In environment module.")  # Print a message indicating the module is running
    return os.environ  # Return the dictionary containing the environment variables

if __name__ == "__main__":  # Check if the script is being run directly
    environment_variables = get_environment_variables()  # Call the function to get environment variables
    for key, value in environment_variables.items():  # Iterate over the environment variables dictionary
        print(f"{key}: {value}")  # Print each environment variable and its value
