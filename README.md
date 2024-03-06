# White Hat Python
# By: Nicholas Fisher

**Import Note: I, Nicholas Fisher, the creator of this Trojan malware, am not responsible for the misuse of these scripts. They are malicious and should only be used in professionally approved White Hat scenarios. You are responsible for any consequences resulting from the misuse of this malware, including all fines, fees, and repercussions. Please read this statement carefully: by downloading any of the scripts in this repository, you, as the user, take full responsibility for storing, using, and testing these malicious scripts and guidelines. You also take full responsibility for any misuse of this malware. Please note that any data the Trojan extracts will be posted to a GitHub repository, and if that repository is public, all the extracted data will be available for the whole world to see.** <br />

**Please Note: Any of these python scripts can be used as the Trojan's Modules. Just place the scripts in the modules directory of the trojan framework, then edit the trojan .json file in the config directory in the format below: (1 underscore + space = 1 tab)** <br />
[ <br />
_ { <br />
_ _ "module" : "script1" <br />
_ }, <br />
_ { <br />
_ _ "module" : "script2" <br />
_ } <br />
] <br />
**Please run the push_trojan_updates.sh file in the config module to push changes into the active trojan!** <br />

**Important Note: These scripts use Python 3.11.x and libraries marked in the important notes for each section** <br />

This is a repository of White hat python codes to be used for Pentesting. <br />

# Network Tools <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/236dbe23-19e8-47ca-b7ef-f99bebacc27c) <br />
**The Following List gives a short description of all the scripts in this group:** <br />
1. VenvConfig.sh - This script creates new python3 environments,loads one module, and tests to see if the enviroment is using python3. To ensure that this script works please install the venv tool. The command to install venv is in the description of this script. <br /> 
2. IDEConfig.sh - This script is used to install and setup the Visual Studio IDE. <br />
3. TCPClient.py - This script is used to help Pentesters to whip up a TCP client. The user inputs an IPv4 address or hostname and TCP port to establish the client connection. <br />
4. UDPClient.py - This script is used to help Pentesters to whip up a UDP client. The user inputs an IPv4 address or hostname and UDP Port to establish the client connection. Runs on Python 3. <br />
5. TCPServer.py - This script is used to help Pentesters to whip up a Threaded TCP Server on python 3. Please provide an IPv4 Address or hostname and the appropriate TCP port for this script to work. <br />
6. netcat.py - A Python implementation of the NetCat tool, offering file transfer, command execution, and interactive command shell functionalities over TCP/IP connections. This tool provides <br />
   a flexible command-line interface for both client and server modes, allowing for easy network operations and troubleshooting. <br />
7. proxy.py - This script implements a basic TCP proxy. It listens on a specified local host and port, forwards incoming connections to a remote host and port, and relays data between the client and the remote server. It can be used for various purposes such as debugging, monitoring, or modifying network traffic. <br />
8. ssh_cmd.py - This script allows the user to execute a command on a remote server over SSH. It prompts the user for their username, password, server IP, port, and command. If no input is provided for the IP, port, or command, default values are used. Please install the paramiko library for Python 3. <br />
9. ssh_remd.py - This script allows you to execute commands on a remote server over SSH. It prompts the user for the server's IP address, port number, and the command to execute. The script then establishes an SSH connection to the server, sends the command, executes it on the server, and returns the output to the client. <br />
10. ssh_server.py - This script sets up an SSH server using the Paramiko library, enabling users to remotely execute commands. It begins by prompting the user for the server's IP address and TCP port. Once configured, the script listens for incoming connections and authenticates users based on their provided username and password. Once authenticated, users can enter commands to be executed on the server. The script continues to accept and execute commands until the user enters 'exit' to close the connection. This script provides a simple way to implement an SSH server for remote command execution. A diagram of this is imaged above. <br />
11. rforward.py - This script implements a reverse SSH tunneling mechanism using the Paramiko library. This script allows users to establish a secure connection to a remote SSH server and forward a local port to a port on a remote host, effectively creating a tunnel for secure communication. The script takes command-line arguments for the SSH server, the remote host, and the ports to forward, and it supports authentication methods including password and key-based authentication. An example use case would be to securely access a service running on a remote host that is not directly accessible from the local machine due to firewall restrictions. To use the script, simply run it from the command line and follow the prompts to enter the required information. The script will then establish the SSH connection and start. <br />

**Example outputs of some of the scripts!** <br />
1. TCPServer.py output: <br />
[*] Listening on 0.0.0.0:9998 <br />
[*] Accepted Connection from 127.0.0.1:49704 <br />
[*] Received: GET / HTTP/1.1 <br />
Host: google.com <br />
2. proxy.py output: <br />
   ./proxy.py 127.0.0.1 9000 10.21.132.1 9000 True <br />
3. ssh_cmd.py output: <br />
    Username: user <br />
    Password: <br />
    Enter Server IP: 192.168.1.203 <br />
    Enter port or <CR>: 2222 <br />
    Enter command or <CR>: id <br />
    --- Output --- <br />
   uid=0(root) gid=0(root) groups=0(root) <br />
4. ssh_remd.py output: <br />
     file1 <br />
     file2 <br />
     file3 <br />
5. ssh_server.py output: <br />
     [+] Listening for connection ... <br />
     [+] Got a connection! <socket>, ('127.0.0.1', 12345) <br />
     [+] Authenticated! <br />
     Welcome to bh_ssh <br />
     Enter command: <br />
6. rforward.py output: <br />
   Connecting to ssh host ssh_server:22... <br />
   Now forwarding remote port 8080 to remote_host:80... <br />
   Connected! Tunnel open ('127.0.0.1', 8080) -> ('remote_host', 80) (remote_host:80) <br />
   Tunnel closed from ('127.0.0.1', 8080) <br />

# Packet Sniffer/Port Scanner <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/faa2eb23-9d2f-4a7e-911a-84fc0b379440) <br />
**Important Note: For mapscan.py to work please install the scapy and nmap python libraries in linux using the following commands below:** <br />
   pip install scapy <br />
   sudo apt-get update <br />
   sudo apt-get install nmap <br />
   pip install python-nmap <br />

**The Following List gives a short description of all the scripts in this group:** <br />
mapscan.py - This script is a Python tool for sniffing network packets and automatically initiating Nmap  port scans on newly discovered hosts. This tool uses the scapy library to sniff packets and the python-nmap library to perform Nmap scans. When a packet with an IP destination different from localhost is captured, NetScanPy checks if the destination IP has already been scanned.  If not, it adds the IP to the list of scanned hosts and launches an Nmap scan for that host. This tool is useful for monitoring network traffic and identifying potentially vulnerable hosts on the network. <br />

**Example outputs of some of the scripts!** <br />
1. mapscan.py output: <br />
   IP source: 192.168.1.10, IP destination: 8.8.8.8 <br />
   Starting Nmap scan for host: 8.8.8.8 <br />
   Nmap scan results for host:  8.8.8.8 <br />
   Host: 8.8.8.8 <br />
   Protocol: tcp < br />
   Port: 53	State: open <br />
   Protocol: udp <br />
   Port: 53	State: open <br />

# Scapy Unleashed: Conquer the Network <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/21d15755-bd6b-496b-8f76-7e624c0b65c1) <br />
**Important Note: For these scripts to work install the appropriate libraries using the commands below:** <br />
  pip install multiprocessing <br />
  pip install scapy <br />
  pip install opencv-python <br />
  
**Important Note: For arp_poiser.py to work: # Please use the script in the following syntax below:** <br />
  python script.py <victim_ip> <gateway_ip> <interface> <br />
   
**The Following List gives a short description of all the scripts in this group:** <br />
1. tport_sniffer.py - # This Python script utilizes the Scapy library to sniff network packets and detect potential email credentials being transmitted in plaintext. It allows the user to specify TCP port filters to focus on specific network traffic. When a packet containing 'user' or 'pass' in its payload is detected, the script prints the destination IP address and the payload, which may include email credentials. This tool can be used for network security auditing or monitoring purposes to identify and mitigate potential credential leaks. <br />
2. arp_poiser.py - The provided Python script implements an ARP poisoning attack tool using Scapy. ARP poisoning is a technique used to intercept traffic on a switched network. The script takes three command-line arguments: the IP address of the victim machine, the IP address of the gateway router, and the network interface to use. It then initiates an ARP poisoning attack by sending spoofed ARP packets to the victim and the gateway, tricking them into sending their traffic through the attacker's machine. The attacker can then sniff the traffic passing through and potentially intercept sensitive information such as passwords or credentials. <br />
3. rcap.py - The provided Python script is designed to extract and save images from HTTP traffic stored in a PCAP file. It utilizes the Scapy library for packet manipulation and extraction. The script reads a PCAP file containing network traffic, filters out HTTP packets, extracts images from the HTTP responses, and saves them to a specified directory. To use the script, you need to specify the input PCAP file path and the output directory for the extracted images. For example, to extract images from a PCAP file named 'example.pcap' located in the 'Downloads' directory and save them to the 'Pictures' directory on the desktop, you would set PCAPS to '/root/Downloads' and OUTDIR to '/root/Desktop/pictures'. After running the script, it will process the PCAP file and save the extracted images to the specified output directory. The output will include one or more image files (e.g., ex_0.jpg, ex_1.png, etc.) containing the extracted images. <br />
4. detect.py - 
The provided Python script uses OpenCV to detect faces in images. It takes a directory containing images as input, detects faces in each image using a pre-trained Haar cascade classifier, highlights the detected faces with rectangles, and saves the modified images in a specified output directory. To use the code, simply run the script, ensuring that the paths to the input images and the Haar cascade classifier are correct. For example, if you have a directory pictures containing images, you can use the following command to detect faces and save the modified images in a directory faces <br />

**Example outputs of some of the scripts!** <br />
1. tport_sniffer.py output: <br />
   [*] Destination: 192.168.1.1 <br />
   [*] USER myemail@example.com <br />

# Web Exploitation Unleashed <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/7e294907-a92a-4ff3-aa09-fc3e38c0c2bc) <br />
**Important Note: For the Web Scripts tp work please use the following linux commands to install the appropriate libraries:** <br />
  pip install requests <br />
  pip install lxml <br />
  pip install beautifulsoup4 <br />

**Important Note: For the ravager.py script to run please enter the following commands in your terminal:** <br />
  cd ~/Downloads <br />
  wget https://www.netsparker.com/s/research/SVNDigger.zip <br />
  unzip SVNDigger.zip <br />

**The Following List gives a short description of all the scripts in this group:** <br />
1. web_pather.py - The provided Python script prompts the user to input a URL and a list of file extensions separated by spaces. It constructs a URL using the input, sets the number of threads to 10, and creates a list of file extensions based on the user input. The script then prints out the constructed URL, the number of threads, and the list of filtered file extensions. This script can be used to quickly set up a web scraping or downloading task with customizable file type filters. For example, after running the script and providing "example.com" as the URL and ".jpg .png .pdf" as the file extensions. <br />
2. ravager.py - This script is a simple tool for performing directory busting on a web server using a wordlist of common directory names and file extensions. It takes a target URL and a wordlist file as inputs, and then iterates through the combinations of words and extensions to construct URLs to check. It uses threading to speed up the process by making multiple HTTP requests simultaneously. <br />
3. login_bruteforce.py - This script is a Python tool designed to aid in testing the security of login systems by performing a brute-force attack. It prompts the user to input the URL of the login form, as well as the paths to files containing lists of usernames and passwords. The script then iterates through each combination of username and password, attempting to log in to the specified URL using HTTP POST requests. If successful login credentials are found, they are printed to the console. <br />

**Example outputs of some of the scripts!** <br />
1. web_pather.py output: <br />
   URL: http://example.com <br />
   Threads: 10 <br />
2. ravager.py output: <br />
   Please input URL here: http://example.com <br />
   Enter path to all.txt file: wordlist.txt <br />
   Press return to continue. <br />
   Success (200: http://example.com/admin.php) <br />
   Success (200: http://example.com/test.bak) <br />
   404 => http://example.com/notfound.php <br />
   Filtered extensions: ['.jpg', '.png', '.pdf'] <br />
3. login_bruteforce.py output: <br />
   Successful login with username: admin and password: password123 <br />
   Failed login attempt with username: admin and password: qwerty <br />
   Failed login attempt with username: admin and password: letmein <br />

# Command and Control Center <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/239280f9-d78f-4e2d-aace-6fb0b4e59177) <br />
**Important Note: I, Nicholas Fisher, the creator of this Trojan malware, am not responsible for the misuse of these scripts. They are malicious and should only be used in professionally approved White Hat scenarios. You are responsible for any consequences resulting from the misuse of this malware, including all fines, fees, and repercussions. Please read this statement carefully: by downloading any of the scripts in this repository, you, as the user, take full responsibility for storing, using, and testing these malicious scripts and guidelines. You also take full responsibility for any misuse of this malware. Please note that any data the Trojan extracts will be posted to a GitHub repository, and if that repository is public, all the extracted data will be available for the whole world to see.** <br />

**Important Note: For this Trojan to work install the appropriate libraries using the commands below, or head to pypi.org/project/github3.py' to automate the process:** <br />
  pip install github3.py <br />
  pip install base64 <br />
  pip install importlib <br />
  pip install json <br />
  pip install random <br />
  pip install sys <br />
  pip install threading <br />
  pip install time <br />
  pip install datetime <br />

**Please Note: Any of these python scripts can be used as the Trojan's Modules.** <br />

**Important Note to use github_trojan.py, Please get the necassary token input by doing the following settings:** <br />
1. Click on user Profile on left hand side. <br />
2. Click on developer settings. <br />
3. Click on Personal Access Tokens. <br />
4. Click on the classic Token. <br />
5. Click Generate New Token. <br />
6. Click on the Generate Classic New Token Option. <br />
7. Finish Generating Token with appropriate settings. <br />
8. Finally, copy the token, and paste it into a text file. <br />

**Important Note: To create the basic structure for this repo enter the following on the Linux Command Line or use the provided configuration Bash file:** <br />
  $ mkdir \<trojan_name\> <br />
  $ cd \<trojan_name\> <br />
  $ git init <br />
  $ mkdir modules <br />
  $ mkdir config <br />
  $ mkdir data <br />
  $ touch .gitignore <br />
  $ git add . <br />
  $ git commit -m "Adds repo structure for trojan" <br />
  $ git remote add origin https://github.com/<yourusername\>/<torjan_github_repository\>.git <br />
  $ git push origin master <br />
  
**Please Note: the ShadowReaper_Trojan Repository for the working Trojan the UAH NCAE-C 2024 Red Team used in competition is in a private repository to keep the server data private!** <br />

**The Following List gives a short description of all the scripts in this group:** <br />
**1. Set up/ 2. Update/ 3. Pull Data: (Run scripts 2 and 3 in the home directory of your Trojan!)** <br />
1. trojan_linux_framewrk_conf.sh - This script is used to create the initial structure for the repo. The config directory holds unique configuration files for each trojan, so each Trojan can contain a seperate configuration file. The modules directory contains any modular code that the trojan should pick up and then execute. The data directory is where the trojan will check any collected data. <br />
2. push_trojan_updates.sh - This script automates the process to push new features into the active Trojan on Github. To ensure this script works please place it in the <trojan_name> directory. You will need your Github username and password to push the Trojan update. <br />
3. data_pull.sh - This script pulls the results of the running Trojan Modules. <br />

**Modules:** <br />
1. dirlister.py - This script implements a directory listener module that recursively lists all files in all directories starting from the current directory. The list_files function uses os.walk to traverse all directories and collect file paths, which are then returned as a list of strings. The run function calls list_files with the current directory and returns the list of files as a string. To use the code, simply import the module and call the run function. <br />
2. environment.py - This script defines a function get_environment_variables that retrieves and returns the environment variables of the system. It first prints a message indicating that it is in the environment module, then uses the os.environ dictionary to fetch the environment variables. Finally, it iterates over the dictionary and prints each environment variable along with its corresponding value. This script can be used to quickly view the environment variables set on a system, which can be useful for debugging or understanding the current system configuration. <br />
3. platformer.py - The provided Python script utilizes the platform module to gather detailed information about the operating system of a target host. This information includes the operating system name (system), network name of the machine (node), operating system release (release), operating system version (version), machine type (machine), and processor type (processor). The get_os_details function collects this information into a dictionary and returns it. When the script is executed, it calls the get_os_details function and then iterates over the dictionary to print each key-value pair in a readable format. <br />

**Configuration:** <br />
1. modul3s.json - is just a simple list of modules that the remote trojan should run. <br />
2. github_trojan.py - This script  implements a Trojan horse program that can be used for remote execution of tasks on a target machine. It uses GitHub as a repository for storing configuration files and modules. The program continuously checks for updates in the repository, retrieves new modules or configurations, and executes them. This allows for dynamic and remote control of the Trojan's behavior. To use the code, you would need to set up a GitHub repository with the necessary configuration files and modules. You would also need to generate a personal access token for GitHub API access. An example of using the code would be to create a repository with a configuration file specifying which modules to run and their parameters. The Trojan would then fetch this configuration, run the specified modules, and store the results back in the repository.  !!Belongs in the config module of the Trojan Framework!! <br />

**Example outputs of some of the scripts!** <br />
1. environment.py output: <br />
   [*] In environment module. <br />
   PATH: /usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin <br />
   LANG: en_US.UTF-8 <br />
   HOME: /Users/user <br />
2. platformer.py output: <br />
   system: Windows <br />
   node: DESKTOP-ABC123 <br />
   release: 10 <br />
   version: 10.0.19041 <br />
   machine: AMD64 <br />
   processor: Intel64 Family 6 Model 142 Stepping 11, GenuineIntel <br />

**Example Layout of the JSON script below: (1 underscore + space = 1 tab)**
[ <br />
_ { <br />
_ _ "module" : "script1" <br />
_ }, <br />
_ { <br />
_ _ "module" : "script2" <br />
_ } <br />
] <br />
Important Note: Please run the push_trojan_updates.sh file in the config module to push changes into the active trojan! <br />

# Cyber Surveillance Suite <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/219d6c1a-5281-438a-ab31-695c8d685190) <br />
**Important Note: For these scripts to work install the appropriate libraries using the commands below:** <br />
  pip install pythoncom <br />
  pip install pyWinhook <br />
  pip install win32clipboard <br />
  pip install win32gui <br />
  pip install win32process <br />
  pip install psutil <br />
  pip install pynput <br />
  pip install ctypes <br />
  pip install os <br />
  pip install platform <br />
  pip install time <br />
  pip install pywin32 <br />
  pip install python3-xlib <br />

**The Following List gives a short description of all the scripts in this group:** <br />
1. keylogger.py - This script implements a cross-platform keylogger capable of logging keyboard inputs on both Windows and Linux operating systems. It utilizes different libraries and modules depending on the platform, using pyHook for Windows and pynput for Linux. The script continuously monitors keyboard events, logging all key inputs, including printable characters and special keys, while also identifying the active window or process where the input is directed. To use the script, simply run it on the target system, and it will start logging keystrokes in the background. An example usage scenario would involve running the script discreetly on a system to monitor user activity for security or administrative purposes. The script output includes the logged keys along with details such as the process ID, executable name, and window title where the input occurred. For instance, the output might display characters typed in a text editor along with information about the editor's process and window title, providing context for the logged keystrokes. <br />
2. screenshotter.py - This script is a Python program designed to capture screenshots on both Windows and Linux operating systems. It utilizes platform detection to choose the appropriate method for taking screenshots based on the current operating system. On Windows, it utilizes the `win32api`, `win32con`, `win32gui`, and `win32ui` modules to access the system's screen dimensions and capture the screenshot. On Linux, it utilizes the `Xlib` library to achieve similar functionality. The script includes functions to retrieve screen dimensions, capture a screenshot, and encode the resulting image into base64 format. Users can utilize this script by executing it from the command line, and an example usage would be running the script directly using a Python interpreter. The script outputs a screenshot file named 'screenshot.bmp', which can be found in the same directory as the script execution. This file contains the captured screenshot in bitmap format. <br />
3. executer.py - This script is a versatile tool for executing shellcode on both Windows and Linux platforms. It offers users three options: executing a command directly in the shell, running shellcode stored in a local file, or fetching shellcode from a URL and executing it. Users can interactively choose their preferred option by entering 'cmd', 'file', or 'url' when prompted. For instance, if a user wants to execute a command, they would input 'cmd' and then type the desired command. An example command could be 'whoami' to retrieve the current user's username. Upon execution, the script would display the output of the command, providing valuable system information or performing actions as directed. The script empowers users to dynamically interact with their system, execute custom shellcode, and streamline security testing or automation tasks. <br />
4. detective_sandbox - This script is a Python program designed to detect user activity on a Windows system, particularly focusing on mouse clicks and keystrokes. It includes functionalities to check if the system is running in an Ubuntu Sandbox environment. Once executed, the script continuously monitors user interactions such as mouse clicks and keyboard input, keeping track of the frequency of these events. It sets thresholds for the maximum number of mouse clicks, keystrokes, and double clicks that can occur within a certain time frame. If these thresholds are exceeded, the script terminates, indicating potential suspicious activity. An example of using the script would be running it in a Windows environment to monitor user activity, especially in scenarios where detecting excessive or suspicious user input is necessary. <br />

**Example outputs of the detective_sandbox.py script!** <br />
  [\*] It has been 15000 milliseconds since the last event. <br />
  [\*] It has been 20000 milliseconds since the last event. <br />
  [\*] It has been 25000 milliseconds since the last event. <br />
  [\*] It has been 30000 milliseconds since the last event. <br />
  [\*] It has been 35000 milliseconds since the last event. <br />
  [\*] It has been 40000 milliseconds since the last event. <br />
