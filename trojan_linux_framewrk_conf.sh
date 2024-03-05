#!/bin/bash
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4, 2024
# Course #: IS 477
# Description of Script
# This script is used to create the initial structure for the repo. The config directory holds
# unique configuration files for each trojan, so each Trojan can contain a seperate configuration
# file. The modules directory contains any modular code that the trojan should pick up and then
# execute. The data directory is where the trojan will check any collected data. 
#################################################################################################
echo -n "Please enter new Trojan Directory Name: "
read dir_name
mkdir $dir_name
cd $dir_name
git init
mkdir modules
mkdir config
mkdir data
touch .gitignore
git add .
git commit -m "Adds repo structure for Trojan"
echo -n "Please enter your github username: "
read user_input
echo -n "
git remote add origin https://github.com/$user_input/
