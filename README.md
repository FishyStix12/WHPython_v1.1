# White Hat Python Version 1.02
# By: Nicholas Fisher

**Python Library Configuration Script:** <br />
pylib_config.sh - The script is designed to set up a Python development environment on Kali Linux for ethical hacking purposes. It updates system packages, installs necessary system libraries, and then proceeds to install various Python libraries commonly used by ethical hackers. These libraries include tools for network scanning (scapy, nmap), web scraping and parsing (beautifulsoup4, lxml), interacting with GitHub (github3.py), handling encryption and encoding (base64, pycryptodomex), sending emails (smtplib), working with Windows hooks (pywin32, pywinhook), and more. <br />

**Disclaimer: These scripts should only be used in cases where the user has permission to use these scripts on the subject systems!** <br />

**Import Note: Please read this statement carefully: By downloading any of the scripts in this repository, you, as the user, take full responsibility for storing, and using these scripts. You also take full responsibility for any misuse of these malicious codes. Finally, Please note that any data the Trojan extracts will be posted to a GitHub repository, and if that repository is public, all the extracted data will be available for the whole world to see.** <br />

**Please Note: Any of these python scripts can be edited and used as the Trojan's Modules. Just place the scripts in the modules directory of the trojan framework, then edit the trojan .json file in the config directory in the format below: (1 underscore + space = 1 tab)** <br />
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
**Important Note, you need to modifiy some of these scripts to change variables like remote_host in the script to your targets IP address. Please edit the scripts that require change to ensure they properly work.** <br />

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
[\*] Listening on 0.0.0.0:9998 <br />
[\*] Accepted Connection from 127.0.0.1:49704 <br />
[\*] Received: GET / HTTP/1.1 <br />
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

# Packet Sniffers and Port/Vulnerability Scanners <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/faa2eb23-9d2f-4a7e-911a-84fc0b379440) <br />
**Important Note: For net_terrorist.py to work please install the scapy and nmap python libraries in linux using the following commands below:** <br />
   pip install scapy <br />
   sudo apt-get update <br />
   sudo apt-get install nmap <br />
   pip install python-nmap <br />

**The Following List gives a short description of all the scripts in this group:** <br />
1. net_terrorizer.py - This script is a tool crafted for ethical hacking endeavors, focusing on network reconnaissance and vulnerability assessment. Leveraging the `python-nmap` library, it orchestrates comprehensive scans on remote hosts, probing for open ports, identifying service versions, and detecting potential security weaknesses. Multithreading capabilities empower the script to concurrently monitor network traffic, triggering Nmap scans upon detecting novel hosts. Users can input either single IP addresses or CIDR notations to specify target ranges for scanning. With integration of the `vulners` script, the tool extends its functionality to include vulnerability detection, highlighting potential threats and associated CVE identifiers. This versatile script equips ethical hackers with essential insights, aiding in the identification and mitigation of security risks within authorized systems. <br />
2. darknet_recon.py - The script provided is a Python tool for conducting network scans using Nmap and searching for Metasploit modules corresponding to identified vulnerabilities. It prompts the user to input remote IP addresses or CIDR notations for scanning. After performing Nmap scans to discover hosts and their open ports along with potential vulnerabilities, the script simulates finding CVE IDs. It then utilizes Metasploit's `msfconsole` command-line tool to search for exploit modules related to the identified CVEs. The user is prompted to enter the superuser password when required for executing commands. Overall, this script serves as a versatile tool for network reconnaissance and vulnerability assessment, seamlessly integrating Nmap and Metasploit functionalities. <br />
3. dark_wizard_gui.py - **Important Note: Please use this script as a superuser for it to work!** This Python script creates a graphical user interface (GUI) application named "Dark Net Wizard" using Tkinter. The application allows users to perform Nmap scans with firewall evasion techniques on specified target IP addresses or CIDR ranges. It includes options for inputting target ports or port ranges, and it displays the scan results, including any found Common Vulnerabilities and Exposures (CVEs) and Metasploit exploit modules if they exist. The GUI features a dark purple background color, an image display at the top (which can be replaced with a custom image link), input fields for IP addresses and ports, buttons for scanning and exiting the application, and an output box for displaying scan results and messages. <br />

**Example outputs of some of the scripts and gui!** <br />
1. dark_wizard_gui.py gui: <br />
 ![image](https://github.com/FishyStix12/WHPython_v1.02/assets/102126354/e91027d1-d1d7-4e23-b818-b7ea187cc533) <br />

3. net_terrorizer.py output: <br />
   Enter the remote IP address or CIDR notation to scan (press Enter to exit): 192.168.0.1 <br />
   Enter the port/ports to scan (leave empty for full scan): 80 <br />
   Scanning IP: 192.168.0.1 <br />
   Starting Nmap scan for host: 192.168.0.1 <br />
   IP source: 192.168.0.2, IP destination: 192.168.0.1 <br />
   Nmap scan results for host: 192.168.0.1 <br />
   Host: 192.168.0.1 <br />
   Protocol: tcp <br />
   Port: 80    State: open    Service: http    Product: Apache    Version: 2.4.29    Extra Info: (Ubuntu) <br />
   Script: vulners <br />
   CVEs Found: CVE-2019-0211, CVE-2018-17199 <br />

   Enter the remote IP address or CIDR notation to scan (press Enter to exit): 192.168.0.0/24 <br />
   Enter the port/ports to scan (leave empty for full scan): <br />
   Scanning IP: 192.168.0.1 <br />
   Starting Nmap scan for host: 192.168.0.1 <br />
   Scanning IP: 192.168.0.2 <br />
   Starting Nmap scan for host: 192.168.0.2 <br />
   IP source: 192.168.0.3, IP destination: 192.168.0.2 <br />
   IP source: 192.168.0.3, IP destination: 192.168.0.1 <br />
   Nmap scan results for host: 192.168.0.1 <br />
   Host: 192.168.0.1 <br />
   Protocol: tcp <br />
   Port: 80    State: open    Service: http    Product: Apache    Version: 2.4.29    Extra Info: (Ubuntu) <br />
   Script: vulners <br />
   CVEs Found: CVE-2019-0211, CVE-2018-17199 <br />

   Nmap scan results for host: 192.168.0.2 <br />
   Host: 192.168.0.2 <br />
   Protocol: tcp <br />
   Port: 22    State: open    Service: ssh    Product: OpenSSH    Version: 7.2p2    Extra Info: Ubuntu Linux; protocol 2.0 <br />
   Script: vulners <br />
   CVEs Found: CVE-2017-15906 <br />

   Enter the remote IP address or CIDR notation to scan (press Enter to exit): <br />
   Exiting... <br />

4. darknet_recon.py output: <br />
   Enter the remote IP address or CIDR notation to scan (press Enter to exit): 192.168.1.0/24 <br />
   Nmap scan results for host: 192.168.1.1 <br />
   Host: 192.168.1.1 <br />
   Protocol: tcp <br />
   Port: 22    State: open    Service: ssh    Product: OpenSSH    Version: 7.6p1 Ubuntu    Extra Info: protocol 2.0 <br />
   Port: 80    State: open    Service: http    Product: nginx    Version: 1.14.0    Extra Info: (Ubuntu) <br />

   Metasploit modules for the found vulnerabilities: <br />

   Vulnerability: CVE-2017-1001000 <br />
   No Metasploit modules found for vulnerability: CVE-2017-1001000 <br />

   Vulnerability: CVE-2019-6977 <br />
   Module: exploit/linux/http/paloalto_traps_unauth_rce (Linux) <br />

   Vulnerability: CVE-2018-1000861 <br />
   No Metasploit modules found for vulnerability: CVE-2018-1000861 <br />


# Scapy Unleashed: Conquer the Network <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/21d15755-bd6b-496b-8f76-7e624c0b65c1) <br />
**Important Note: For these scripts to work install the appropriate libraries using the commands below:** <br />
  pip install multiprocessing <br />
  pip install scapy <br />
  pip install opencv-python <br />
  
**Important Note: For arp_poiser.py to work:  Please use the script in the following syntax below:** <br />
  python script.py <victim_ip> <gateway_ip> <interface> <br />
   
**The Following List gives a short description of all the scripts in this group:** <br />
1. tport_sniffer.py - # The script enables remote packet sniffing on a target host specified by the user. It prompts the user to input the target host's IP address and port, establishes a TCP connection to the remote host, and then allows the user to define packet filters based on port numbers. Once configured, the script initiates packet sniffing on the specified ports, intercepting TCP packets and checking for payload containing sensitive information like usernames or passwords. If such data is detected, it prints out the destination IP address and the payload content for further inspection. <br />
2. arp_poiser.py - The script allows users to initiate an ARP poisoning attack and packet sniffing on a remote host by inputting the target host's IP address, port, gateway IP address, and interface. Leveraging Scapy and multiprocessing, it efficiently handles packet manipulation and parallel processing. Upon execution, it prompts users for necessary information, initializes the attack, and subsequently sniffs packets directed to the target host, providing a seamless and interactive experience. <br />
3. rcap.py - The provided Python script is designed to extract and save images from HTTP traffic stored in a PCAP file. It utilizes the Scapy library for packet manipulation and extraction. The script is a Python tool designed to parse pcap files containing network traffic data, particularly HTTP traffic, and extract images transferred over HTTP from a specified target host. Users can interactively provide inputs such as the path to the pcap file, the target host's IP address, the target port number, and the output directory for saving the extracted images. Leveraging the Scapy library for packet manipulation, the script identifies relevant packets based on the specified target IP address and port number. It then extracts images from HTTP responses, considering content type and encoding, and saves them to the designated output directory. With its interactive nature and capability to process pcap files, this script offers a flexible and efficient solution for extracting images from network traffic data. <br />
4. detect.py -This script utilizes OpenCV for remote face detection and processing. Upon establishing a connection with a remote host specified by the user, it scans a designated directory for JPEG images. Employing a convolutional neural network (CNN)-based face detection model, it accurately identifies faces within each image. Extracted faces are then combined into a single composite image. Upon completion of processing all images, the composite image is transmitted back to the local host. This script is particularly useful for scenarios requiring distributed face detection tasks across networked devices, ensuring efficient and accurate processing of image data. <br />

**Example outputs of some of the scripts!** <br />
1. tport_sniffer.py output: <br />
Enter the target host IP address: 192.168.1.100 <br />
Enter the target host port: 80 <br />
Do you want to add more filters? (yes/no): yes <br />
Enter the port number: 443 <br />
Do you want to add more filters? (yes/no): no <br />
Applying filter: tcp port 80 or tcp port 443 <br />
[*] Destination: 192.168.1.100 <br />
[*] POST /login HTTP/1.1 <br />
Host: 192.168.1.100 <br />
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0 <br />
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8 <br />
Accept-Language: en-US,en;q=0.5 <br />
Accept-Encoding: gzip, deflate <br />
Content-Type: application/x-www-form-urlencoded <br />
Content-Length: 29 <br />
Connection: close <br />
Cookie: sessionid=abcdef1234567890 <br />
Upgrade-Insecure-Requests: 1 <br />

username=admin&password=secretpass <br />

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
1. web_pather.py - This script performs directory busting on a remote web server specified by the user. It starts the enumeration from the root directory of the server and recursively explores all directories and files. The script generates URLs for common file types and checks if they exist on the server. Additionally, it parses HTML content from directory listings to discover subdirectories and continues enumeration. After completing the directory busting, the script prompts the user to enter a file name to save the discovered URLs. It then appends the results to the specified file, allowing the user to review the findings conveniently. This script provides a straightforward and automated approach to identify potentially sensitive or vulnerable directories and files on a web server.
2. ravager.py - This script is a directory busting tool designed to enumerate directories and files on a web server. It prompts the user to input the target host IP address, port, and the path to a wordlist file containing potential directory and file names. Utilizing threading for concurrent requests, it sends HTTP requests to the specified host, attempting to access each directory and file combination generated from the provided wordlist. If a directory or file is found, it outputs a success message along with the corresponding URL. This tool is commonly used in security testing to identify hidden or unprotected resources on web servers. <br />
3. login_bruteforce.py - The script is a Python automation tool designed to perform brute-force login attempts on a web application's login form hosted on a remote server. It prompts the user for the target host's IP address, port, and the paths to files containing usernames and passwords. Using the provided information, it constructs the login URL and reads in the username and password lists from the specified files. The script then iterates through each combination of username and password, attempting to log in using HTTP POST requests. If a successful login is detected, it outputs the credentials used. This script provides a basic framework for automating the testing of login forms for security vulnerabilities. <br />

**Example outputs of some of the scripts!** <br />
1. web_pather.py output: <br />
   URL: http://example.com <br />
   Threads: 10 <br />
2. ravager.py output: <br />
   Please input target host IP address: 192.168.1.100 <br />
   Please input target port: 80 <br />
   Enter path to all.txt file: /path/to/wordlist.txt <br />
   Resuming wordlist from resume_word <br />
   Press return to continue. <br />
   Success (200: http://192.168.1.100:80/admin/) <br />
   Success (200: http://192.168.1.100:80/css/) <br />
   Success (200: http://192.168.1.100:80/js/) <br />
   Success (200: http://192.168.1.100:80/images/) <br />
   .... <br />

3. login_bruteforce.py output: <br />
   Please enter the target host IP address: 192.168.1.100 <br />
   Please enter the target port: 8080 <br />
   Please enter the path to your usernames dictionary in Linux: /path/to/usernames.txt <br />
   Please enter the path to your passwords dictionary in Linux: /path/to/passwords.txt <br />

   Successful login with username: admin and password: password123 <br />
   Failed login attempt with username: admin and password: 123456 <br />
   Failed login attempt with username: user1 and password: password123 <br />
   ... <br />


# Trojan Framework <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/239280f9-d78f-4e2d-aace-6fb0b4e59177) <br />

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

**The Following List gives a short description of all the scripts in this group:** <br />
**1. Set up/ 2. Update/ 3. Pull Data: (Run scripts 2 and 3 in the home directory of your Trojan!)** <br />
1. trojan_linux_framewrk_conf.sh - This script is used to create the initial structure for the repo. The config directory holds unique configuration files for each trojan, so each Trojan can contain a seperate configuration file. The modules directory contains any modular code that the trojan should pick up and then execute. The data directory is where the trojan will check any collected data. <br />
2. push_trojan_updates.sh - This script automates the process to push new features into the active Trojan on Github. To ensure this script works please place it in the <trojan_name> directory. You will need your Github username and password to push the Trojan update. <br />
3. data_pull.sh - This script pulls the results of the running Trojan Modules. <br />

**Configuration:** <br />
1. modul3s.json - is just a simple list of modules that the remote trojan should run. <br />
2. github_trojan.py - This script  implements a Trojan horse program that can be used for remote execution of tasks on a target machine. It uses GitHub as a repository for storing configuration files and modules. The program continuously checks for updates in the repository, retrieves new modules or configurations, and executes them. This allows for dynamic and remote control of the Trojan's behavior. To use the code, you would need to set up a GitHub repository with the necessary configuration files and modules. You would also need to generate a personal access token for GitHub API access. An example of using the code would be to create a repository with a configuration file specifying which modules to run and their parameters. The Trojan would then fetch this configuration, run the specified modules, and store the results back in the repository.  !!Belongs in the config module of the Trojan Framework!! <br />

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

# Trojan Modules <br />
![image](https://github.com/FishyStix12/ShadowReaper_Trojan/assets/102126354/3bde6b1e-407f-47e8-b68c-d246ee637887) <br />
**Important Note: Please pay attention to the top comments of some of these Trojan Modules as you will need to make edits to the scripts such as inputing the target IP Address, or entering the desired port on the target to connect to.** <br />

**Important Note: Please put these scripts in the Modules Directory of the Torjan Framework, and update the JSON File in the config directory.** <br />

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
  pip install python-magic <br />

**Modules:** <br />
1. auto_bruteforce.py - **Important note update the script to just run on the target ip address so it doesn't ask for an input!** The script is a multi-platform Python tool designed for automating the brute force login process on web applications. It prompts the user to input the login URL, as well as the paths to files containing lists of usernames and passwords. The script then iterates through all combinations of usernames and passwords, attempting to log in to the specified URL. It utilizes multiprocessing to parallelize the login attempts, enhancing efficiency. Upon successful login, the script outputs the corresponding credentials, while also providing feedback on failed attempts. This versatile tool can be used across both Windows and Linux operating systems, providing a flexible solution for testing and securing web applications. <br />
2.  grimreaperexecutor.py - This script serves as a clandestine tool for remote command execution, designed for covert operations. It operates as a Trojan, silently awaiting commands from a centralized control and command server (C&C). Once deployed, the Trojan continuously polls the C&C server for instructions. It can execute various types of commands, including shell commands ('cmd'), running shellcode from a local file ('file'), or fetching and executing shellcode from a specified URL ('url'). Results of the executed commands are securely transmitted back to the C&C server. To use it, simply deploy the script on the target system, ensuring that the C&C server URL is correctly configured. Through the C&C interface, operatives can remotely control and manipulate the target system with discretion, making it a powerful tool for clandestine operations. <br />
3. blackwidow.py - This script automates various dark tasks including email exfiltration, brute force attacks, FTP operations, and file transmission. It utilizes various modules to perform tasks such as sending test emails, extracting emails from a Gmail account, brute forcing FTP credentials, uploading files via FTP, transmitting files over TCP/IP, and extracting files from directories recursively. The script is designed to execute all tasks automatically, providing a streamlined approach to conducting various dark operations without user intervention. <br />
4. grimrelay.py - This script designed to facilitate secure and covert file transmission across networks. Utilizing a combination of FTP brute force tactics and direct TCP/IP communication, ensures efficient and discreet data transfer between endpoints. With platform compatibility for Windows, Linux, and macOS, this script empowers users to transmit sensitive files with ease, offering a clandestine solution for clandestine operations. <br />
5.  phantomlock.py - The provided code is a Python script designed to automate the encryption, transmission to a remote server, and decryption of files. Upon execution, the script encrypts all files within the current directory using AES encryption with a randomly generated session key and then encrypts this session key with RSA. The encrypted files are then sent to a specified server URL using HTTP POST requests. After successful transmission, the script instructs the user on how to access the files from the server, emphasizing the importance of keeping this information secure. Additionally, the script includes functionality to decrypt files using a backdoor private key. To use the script, simply run it on the target system. Ensure that the appropriate libraries (Cryptodome and requests) are installed and configured correctly, and modify the SERVER_URL variable to match the URL of your server. Optionally, provide the path to the backdoor private key (backdoor_private_key.pem) for decryption purposes. <br />
6. shadowsender.py - This script, is designed to automate the process of sending emails from a target email address to a host email address in a covert manner. The script utilizes the smtplib library to establish a connection to the SMTP server and send emails. The user needs to specify the SMTP server details, such as the server address and port, as well as the target email address, host email address, and the host email's password. Once the necessary details are provided, the script automatically sends an email from the target email address to the specified host email address without any user interaction. This script can be used for various purposes, including data exfiltration, communication in covert operations, or as a part of a malicious attack. To use the script, simply modify the necessary variables such as the SMTP server details, target email address, host email address, and password, and then run the script. <br />
7. abyssalobserver.py - This script is a system monitoring tool designed to track and analyze processes running on various operating systems. It provides insight into process creation, resource usage, and user privileges, offering a comprehensive overview of system activity. With a focus on efficiency and accuracy, the script operates seamlessly across different platforms, ensuring robust performance and facilitating informed decision-making for system administrators and security professionals. <br />
8. phantomfile.py - This script provides comprehensive monitoring of file system changes and clipboard activities across different operating systems. It employs platform-specific techniques to track file creations, deletions, modifications, renames, copies, and pastes, ensuring heightened awareness of file-related actions. Designed to operate seamlessly on Windows, macOS, and Linux, it offers a vigilant approach to observe and record file events, enhancing security and facilitating forensic analysis when necessary. <br />
9. dirlister.py - This script implements a directory listener module that recursively lists all files in all directories starting from the current directory. The list_files function uses os.walk to traverse all directories and collect file paths, which are then returned as a list of strings. The run function calls list_files with the current directory and returns the list of files as a string. To use the code, simply import the module and call the run function. <br />
10. environment.py - This script defines a function get_environment_variables that retrieves and returns the environment variables of the system. It first prints a message indicating that it is in the environment module, then uses the os.environ dictionary to fetch the environment variables. Finally, it iterates over the dictionary and prints each environment variable along with its corresponding value. This script can be used to quickly view the environment variables set on a system, which can be useful for debugging or understanding the current system configuration. <br />
11. platformer.py - The provided Python script utilizes the platform module to gather detailed information about the operating system of a target host. This information includes the operating system name (system), network name of the machine (node), operating system release (release), operating system version (version), machine type (machine), and processor type (processor). The get_os_details function collects this information into a dictionary and returns it. When the script is executed, it calls the get_os_details function and then iterates over the dictionary to print each key-value pair in a readable format. <br />

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

# Cyber Surveillance Suite <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/219d6c1a-5281-438a-ab31-695c8d685190) <br />
**Important Note: For these scripts to work install the appropriate libraries using the commands below:** <br />
  pip install pythoncom <br />
  pip install pyWinhook <br />
  pip install psutil <br />
  pip install pynput <br />
  pip install ctypes <br />
  pip install os <br />
  pip install platform <br />
  pip install time <br />
  pip install pywin32 <br />
  pip install python3-xlib <br />
  pip install argsparce <br />

**The Following List gives a short description of all the scripts in this group:** <br />
1. keylogger.py - This script implements a keylogger, a tool designed to capture keystrokes on a target system. The script is platform-independent, capable of running on both Windows and Linux operating systems. Upon execution, the user is prompted to input a remote target IP address where the captured keystrokes will be sent. Once the IP address is provided, the keylogger begins monitoring keyboard input in the foreground, logging each keystroke along with details about the active window. For Windows systems, it utilizes modules like `pyHook` and `win32gui` to capture keyboard events, while for Linux systems, it employs `pynput`. This script is designed for ethical hacking scenarios, aiding in penetration testing on approved systems within legal boundaries. <br />
2. screenshotter.py - The script is a cross-platform utility designed to facilitate the remote capture and transmission of screenshots. It intelligently adapts to the underlying operating system, utilizing platform-specific libraries such as `pywin32` for Windows and `pyscreenshot` for Linux, to capture screenshots. The user is prompted to specify the local host's IP address and the port on which the script will listen for incoming screenshot transmissions. Upon receiving a connection from a remote host, the script receives the screenshot data, decodes it, and saves it as a PNG file locally. Exception handling is implemented to ensure robustness and error resilience during execution. This script serves as a versatile tool for capturing and receiving screenshots across diverse computing environments. <br />
3. executer.py - The provided script offers a versatile toolkit for executing commands, running local files, or deploying shellcode retrieved from a URL on a remote host. It employs Python's subprocess and socket modules to enable seamless communication between the user's machine and the target system. Users can input commands directly, execute local files by specifying their paths, or fetch shellcode from a URL for remote execution. The script validates inputs, ensuring proper execution and safeguarding against potential errors. With its modular design and robust error handling, this script serves as a flexible solution for remote management and execution tasks across various platforms. <br />
4. detective_sandbox.py - The script provided is a versatile tool designed to ascertain whether a remote host, specified by the user with an IP address and port, likely operates within a sandbox environment. It first checks the local system environment, distinguishing between Ubuntu Sandbox and other configurations. Utilizing platform-specific libraries, it monitors user activity, detecting keystrokes, mouse clicks, and double-click events, while also tracking time since the last user input. However, its key feature lies in the function `is_sandbox(ip, port)`, which establishes a connection to the remote host and scrutinizes its behavior. If the connection succeeds, indicating a responsive host, it deduces that the host is not a sandbox. Conversely, if the connection fails, it suggests the host may be operating within a sandbox environment. This capability enables users to assess the nature of remote systems, aiding in security assessments and network reconnaissance. <br />

**Example outputs of the detective_sandbox.py script!** <br />
You are not in an Ubuntu Sandbox. <br />
Enter remote host IP address: 192.168.1.100 <br />
Enter remote host port: 22 <br />
The remote host appears to be a sandbox environment. <br />


# Extract-o-Mania <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/f92ae210-0c3a-461c-87bb-203b35d92b86) <br />
**Important Note: For most of this scripts to work you will need a usernames list and passwords list text files for brute forcing!** <br />

**Important Note: For these scripts to work install the appropriate libraries using the commands below:** <br />
pip install pycryptodomex <br />
pip install smtplib <br />
pip install pywin32 <br />
pip install ftplib <br />
pip install flask <br />

**The Following List gives a short description of all the scripts in this group:** <br />
1. cryptoraptor.py - The script is a versatile file encryption tool designed to offer robust security through advanced encryption algorithms. It employs a combination of AES and RSA encryption, utilizing key sizes optimized for enhanced security. Specifically, RSA keys with a substantial size of 8192 bits are employed for secure key exchange, while AES keys of 512 bits ensure strong symmetric encryption. Users can encrypt and decrypt files seamlessly, with the script facilitating key generation and transmission for seamless cryptographic operations. With a user-friendly interface and heightened security measures, the script provides a reliable solution for safeguarding sensitive data during transmission and storage. <br />
2. sneakysender.py - The script is a versatile tool designed to facilitate various email-related tasks and FTP brute-force attacks. It features a user-friendly menu interface that allows users to choose from several options. These options include sending test emails, exfiltrating emails from Gmail accounts, and brute-forcing FTP servers. The script prompts users for necessary details such as SMTP server settings, email addresses, and passwords, enabling seamless execution of chosen tasks. Additionally, it has been enhanced to ensure exfiltrated emails are sent to a specified local host email address, ensuring efficient and centralized management of retrieved data. Overall, the script offers a comprehensive solution for email-related operations and FTP security assessments. <br />
3. transmittron.py - The provided Python script facilitates file transmission and FTP server interaction, offering a versatile toolkit for network operations. The script boasts a user-friendly interface where users can select various functionalities from a main menu. Notably, it enables direct file transmission to a specified client IP address and port via TCP/IP. Moreover, it supports FTP server interaction, allowing users to upload files to a target FTP server. Additionally, the script includes a robust FTP brute-force mechanism, leveraging provided username and password dictionaries to attempt login credentials systematically. This combination of features empowers users with flexible and efficient tools for managing file transfers and interacting with FTP servers securely. <br />
5. codeninja.py - The upgraded script facilitates remote execution by allowing users to input the target host's IP address and port. It employs the Flask framework to create an HTTP server for handling various actions such as transmitting files, brute-forcing FTP servers, sending emails, and exfiltrating email contents. Users interact with the script through a command-line interface, selecting options from the main menu. Each choice triggers a corresponding function, enabling tasks like transmitting files directly to a client, brute-forcing FTP credentials, sending test emails, or exfiltrating emails from Gmail or Outlook accounts. This script empowers users with remote control capabilities, making it adaptable for diverse cybersecurity scenarios. <br />

**Example outputs of some of the scripts!** <br />
    1. cryptoraptor.py output: <br />
       Enter the name for the directory to store keys: encryption_keys <br />
       Enter the target host IP address: 192.168.1.100 <br />
       Enter the target port: 12345 <br />
<br />
       Choose an option: <br />
       1. Encrypt file(s) <br />
       2. Decrypt file(s) <br />
       3. Exit <br />
       Enter your choice: 1 <br />
<br />
       Enter the number of files to encrypt: 1 <br />
       Enter the file path to encrypt: /path/to/file.txt <br />
       Encryption of /path/to/file.txt complete. <br />
<br />
       Choose an option: <br />
       1. Encrypt file(s) <br />
       2. Decrypt file(s) <br />
       3. Exit <br />
       Enter your choice: 2 <br />
<br />
       Enter the number of files to decrypt: 1 <br />
       Enter the file path to decrypt: /path/to/file.txt.enc <br />
       Enter the path to the private key: /path/to/private_key.pem <br />
       Decryption of /path/to/file.txt.enc complete. <br />
<br />
       Choose an option: <br />
       1. Encrypt file(s) <br />
       2. Decrypt file(s) <br />
       3. Exit <br />
       Enter your choice: 3 <br />
<br />
       Exiting... <br />


# Hacky Hierarchy <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/41065611-8c4a-4e78-8550-91478c6a7538) <br />
**Important Note: For these scripts to work install the appropriate libraries using the commands below:** <br />
pip install pywin32 wmi pyinstaller <br />
pip install psutil <br />

**Important note: Please visit http://timgolden.me.uk/python/win32_how_do_i/watch_directory_for_changes.html to help you learn how to use filetactician.py**

**The Following List gives a short description of all the scripts in this group:** <br />
1. tasktactician.py - The script above is a process monitoring tool designed to run on both Windows and Linux platforms. It continuously tracks and logs information about newly created processes, including their command line, creation time, executable path, parent process ID, process ID, user, and privileges. The script allows users to input the target host's IP address and port, enabling remote monitoring of processes on a specified machine. Leveraging platform-specific APIs such as WMI for Windows and system commands like `ps` for Linux, the script provides a platform-agnostic solution for process monitoring. Additionally, it employs exception handling to ensure robustness and reliability in capturing process information. Overall, this versatile script offers a flexible and accessible means to monitor and analyze system activities across diverse computing environments. <br />
2. filetactician.py - The script is a versatile monitoring tool designed to observe file system activities either locally or on a remote host. It offers two modes of operation: "monitor" and "client". In "monitor" mode, it actively tracks file system changes within specified directories on the local machine using Windows-specific functionality. Meanwhile, in "client" mode, it connects to a remote host, allowing users to monitor activities on that machine by receiving and printing data transmitted from the remote host. This flexibility enables users to choose between monitoring their own system or observing the activities of a remote system, enhancing their ability to oversee and manage file operations across different environments. <br />

**Example outputs of some of the scripts!** <br />
1. tasktactian.py output: <br />
   CommandLine: /usr/bin/python3 script.py, Create Time: 2024-03-14 10:25:17, Executable: python3, Parent PID: 1234, PID: 5678, User: user1, Privileges: N/A <br />
   CommandLine: /usr/bin/gedit file.txt, Create Time: 2024-03-14 10:30:45, Executable: gedit, Parent PID: 5678, PID: 91011, User: user1, Privileges: N/A <br />
   CommandLine: C:\Windows\System32\notepad.exe file.txt, Create Time: 2024-03-14 11:15:32, Executable: notepad.exe, Parent PID: 12345, PID: 121314, User: user2, Privileges: SeDebugPrivilege|SeAssignPrimaryTokenPrivilege| <br />
2. filetactician.py output: <br />
   In Monitor Mode: <br />
   Choose mode (monitor/client): monitor <br /> 
   [+] Created c:\WINDOWS\Temp\example.txt <br />
   [\*] Modified c:\WINDOWS\Temp\example.txt <br />
   [vvv] Dumping contents ... <br />
   This is an example file. <br />
   [^^^] Dump Complete. <br />
   [+] Copied c:\WINDOWS\Temp\example.txt <br />
   [+] Pasted c:\WINDOWS\Temp\example_copy.txt <br />
   [-] Deleted c:\WINDOWS\Temp\example_copy.txt <br />


# Cyber Sherlock: Investigating Digital Misdeeds <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/78679002-4467-48aa-b43d-72e6e3228d8f) <br />
**Important Note: Please run the script below to setup the Volatility Python Framework:** <br />
1. volat_conf.sh - This Bash script automates the configuration process for the Volatility Python framework, a powerful tool used for memory forensics analysis. When executed, the script first checks for the presence of essential dependencies such as Git, Python 3, and pip. If any of these dependencies are missing, the script prompts the user to install them. Next, it installs necessary system dependencies and clones the Volatility repository from GitHub. After cloning the repository, the script navigates into the Volatility directory and installs the required Python dependencies using pip. Finally, it displays a completion message indicating that the Volatility configuration is complete. To use the script, simply save it to a file (e.g., `configure_volatility.sh`), make it executable using the command `chmod +x configure_volatility.sh`, and then execute it using `./configure_volatility.sh`. Then visit https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet to learn about the Volatibility tool. Please note, I did not create the Volatility Python framework only this automation script to automatically set up the framework in your host Linux Environment. <br />
