# White Hat Python
# By: Nicholas Fisher
#
**The creator is not resposible for any damage caused by these programs because YOU AGREE TO THE CONSEQUENCES IF YOU RUN These SCRIPTS!!!!!** <br />

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
**Important Note: For this Trojan to work install the appropriate libraries using the commands below, or head to pypi.org/project/github3.py' to automate the process:** <br />
  pip install github3.py <br />

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
  
**Please Head to the ShadowReaper_Trojan Repository for the working Trojan the UAH NCOE 2024 Red Team used in competition!, the scripts for the trojan will be in this repository. In order to created your own Trojan follow the steps above, and install the following scripts into the correct linux directories that are listed above!** <br />

**The Following List gives a short description of all the scripts in this group:** <br />
**Set up:**
1. trojan_linux_framewrk_conf.sh - This script is used to create the initial structure for the repo. The config directory holds unique configuration files for each trojan, so each Trojan can contain a seperate configuration file. The modules directory contains any modular code that the trojan should pick up and then execute. The data directory is where the trojan will check any collected data. <br />
2. push_trojan_modules.sh - This script automates the process to push new features into the active Trojan on Github. To ensure this script works please place it in the <trojan_name> directory. You will need your Github username and password to push the Trojan update. <br />

**Modules:** <br />
1. dirlister.py - This script implements a directory listener module that recursively lists all files in all directories starting from the current directory. The list_files function uses os.walk to traverse all directories and collect file paths, which are then returned as a list of strings. The run function calls list_files with the current directory and returns the list of files as a string. To use the code, simply import the module and call the run function. <br />
2. environment.py - This script defines a function get_environment_variables that retrieves and returns the environment variables of the system. It first prints a message indicating that it is in the environment module, then uses the os.environ dictionary to fetch the environment variables. Finally, it iterates over the dictionary and prints each environment variable along with its corresponding value. This script can be used to quickly view the environment variables set on a system, which can be useful for debugging or understanding the current system configuration. <br />
3. platformer.py - The provided Python script utilizes the platform module to gather detailed information about the operating system of a target host. This information includes the operating system name (system), network name of the machine (node), operating system release (release), operating system version (version), machine type (machine), and processor type (processor). The get_os_details function collects this information into a dictionary and returns it. When the script is executed, it calls the get_os_details function and then iterates over the dictionary to print each key-value pair in a readable format. <br />

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
