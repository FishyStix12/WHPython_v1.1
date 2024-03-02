#!/bin/bash
#################################################################################################
# Author: Nicholas Fisher
# Date: March 2nd 2024
# Description of Script
# This script is used to create new python 3.0 Venv Environments in Kali Linux. In order for this
# script to work please download venv by using the following command in quotes "sudo apt-get install 
# python3-venv". This code will also install up to one module for python, and test to make sure you
# are using python3.
#################################################################################################
#upgrades python
sudo apt-get upgrade python3

#Asks user to create directory for the new python environmental directory
echo -n "enter a pattern for the new python environment directory: "

#Saves the users input as a variable named "env_dir"
read env_dir

#Makes python environmental directory
mkdir $env_dir

#Changes the current working directory to the new created directory
cd $env_dir

#Asks the user to create the name of the new environment
echo -n "What would you like to name the new Environment: "

#Saves the user input as a variable called "env_var"
read env_var

#creates the new Environment
python-m venv $env_var

#Activates the new environment
source $env_var/bin/activate

#launches python to ensure we are using python 3
python

#Exits python
exit()

#Reads user input to search for python 3 module
echo "Please enter one module you would like to install for python3: "

#Saves user input as a variable named "mod_var"
read mod_var

#Installs the module
pip install $mod_var
