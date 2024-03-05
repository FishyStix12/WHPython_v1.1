#!/bin/bash
#################################################################################################
# Author: Nicholas Fisher
# Date: March 5th 2024
# Description of Script
# This script automates the process to push new updates into the active Trojan on Github.
# To ensure this script works please place it in the <trojan_name> directory. You will need your
# Github username and password to push the Trojan update.
#################################################################################################
git add .
echo -n "What is this update for: " # Ex: Adds simple configuration, Adds new modules
read user_input
git commit -m f"{user_input}"
git push origin master
# Enter username:
# Enter password:
