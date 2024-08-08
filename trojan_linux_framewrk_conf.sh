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
echo -n "Enter Repository name here: "
read dir_input
git remote add origin https://github.com/$user_input/$dir_input
echo "Please put your modules, and json file into the modules directory."
echo "Please input the github_trojan.py into the config direcotry and run it."
echo "Please run the push_trojan_updates.sh or enter the following commands to update the trojan with the appriopriate modules, and settings."
echo "git add ."
echo "git commit -m f\"{user_input}\""
echo "git push origin master"
