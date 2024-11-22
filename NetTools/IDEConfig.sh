#!/bin/bash
#################################################################################################
# Author: Nicholas Fisher
# Date: March 3rd 2024
# Description of Script
# This script is used to to install a Visual studio code IDE for Kali Linux. In order for the script
# to work please go to https://code.visualstudio.com/download to download the appropriate files.
# And place this script in the same directory as the downloaded file.
#################################################################################################
apt-get install code
apt-get install -f ./code*
