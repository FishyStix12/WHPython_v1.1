#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 6th 2024
# Desription of Script:
# The script above is a process monitoring tool designed to run on both Windows and Linux 
# platforms. It continuously tracks and logs information about newly created processes, 
# including their command line, creation time, executable path, parent process ID, process 
# ID, user, and privileges. The script allows users to input the target host's IP address 
# and port, enabling remote monitoring of processes on a specified machine. Leveraging 
# platform-specific APIs such as WMI for Windows and system commands like `ps` for Linux, 
# the script provides a platform-agnostic solution for process monitoring. Additionally, 
# it employs exception handling to ensure robustness and reliability in capturing process 
# information. Overall, this versatile script offers a flexible and accessible means to 
# monitor and analyze system activities across diverse computing environments.
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

def monitor(target_host, port):
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
                c = wmi.WMI(computer=target_host, user="", password="", namespace="root\cimv2")
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
    # Input target host IP address and port
    target_host = input("Enter target host IP address: ")
    port = input("Enter target host port: ")
    # Execute the monitoring function
    monitor(target_host, port)
