#################################################################################################
# Author: Nicholas Fisher
# Date: July 19th 2024
# Description of Script
#  The provided script aims to clear the command history in Windows terminals, whether using
# Command Prompt (CMD) or PowerShell. In CMD, the script deletes the command history file located
# at `%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`, reinstalls 
# the `doskey` utility to clear the current session's history, and then exits the terminal.
# This is achieved using the `del` and `doskey /reinstall` commands followed by `exit`.
# For PowerShell, the script removes the same history file using `Remove-Item`, then clears the
# current session's history by overwriting the file with an empty string using `[System.IO.File]::WriteAllText`,
# and finally exits the terminal with the `exit` command. Both scripts ensure that any previously
# entered commands are erased, maintaining privacy and security by removing traces of past 
#activities in the terminal.
#################################################################################################
# Remove the command history file
Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

# Clear the current session's history by overwriting the file with an empty string
[System.IO.File]::WriteAllText("$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt", "")

# Exit PowerShell
exit