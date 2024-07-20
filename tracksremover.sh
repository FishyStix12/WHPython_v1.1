#!/bin/bash
#################################################################################################
# Author: Nicholas Fisher
# Date: July 19th 2024
# Description of Script
#  This Bash script is designed to securely delete the command history from the current user's 
# shell session. It begins by using the `shred` command to overwrite the `.bash_history` 
# file multiple times and then remove it, ensuring that the deleted data cannot be easily
# recovered. Following this, the script creates a new empty `.bash_history` file and clears
# the current session's history using the `history -c` command. Finally, it exits the shell.
# This sequence of commands ensures both the secure deletion of past command history and the
# prevention of any residual data from the current session, enhancing overall privacy and
# security.
#################################################################################################

shred -/.bash_history&& cat /dev/null > .bash_history && history -c && exit