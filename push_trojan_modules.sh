#!/bin/bash
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# This script automates the process to push new features into the active Trojan on Github.
# To ensure this script works please place it in the <trojan_name> directory. You will need your
# Github username and password to push the Trojan update.
#################################################################################################
git add .
git commit -m "Adds New modules"
git push origin master
# Enter username:
# Enter password:
