# White Hat Python
# By: Nicholas Fisher
# 
**The creator is not resposible for any damage caused by these programs because YOU AGREE TO THE CONSEQUENCES IF YOU RUN These SCRIPTS!!!!!** <br />

This is a repository of White hat python codes to be used for Pentesting. <br />

# Network Tools <br />
![image](https://github.com/FishyStix12/WHPython/assets/102126354/236dbe23-19e8-47ca-b7ef-f99bebacc27c) <br />
**The Following List gives a short description of all the scripts in this repository:** <br />
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
   pip3 install scapy <br />
   sudo apt-get update <br />
   sudo apt-get install nmap <br />
   pip3 install python-nmap <br />

**The Following List gives a short description of all the scripts in this repository:** <br />
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
**Important Note: For arg_poiser.py to work please install the multiprocessing library using the command below:** <br />
pip3 install multiprocessing <br />

**Important Note: For mapscan.py to work please install the scapy library using the command below:!** <br />
   pip3 install scapy <br />
   
**Important Note: When using arp.poiser.py use the following syntax to run the code:** <br />
  python script.py <victim_ip> <gateway_ip> <interface> <br />
  
**The Following List gives a short description of all the scripts in this repository:** <br />
1. tport_sniffer.py - # This Python script utilizes the Scapy library to sniff network packets and detect potential email credentials being transmitted in plaintext. It allows the user to specify TCP port filters to focus on specific network traffic. When a packet containing 'user' or 'pass' in its payload is detected, the script prints the destination IP address and the payload, which may include email credentials. This tool can be used for network security auditing or monitoring purposes to identify and mitigate potential credential leaks. <br />
2. arp_poiser.py - The provided Python script implements an ARP poisoning attack tool using Scapy. ARP poisoning is a technique used to intercept traffic on a switched network. The script takes three command-line arguments: the IP address of the victim machine, the IP address of the gateway router, and the network interface to use. It then initiates an ARP poisoning attack by sending spoofed ARP packets to the victim and the gateway, tricking them into sending their traffic through the attacker's machine. The attacker can then sniff the traffic passing through and potentially intercept sensitive information such as passwords or credentials. <br />
    
**Example outputs of some of the scripts!** <br />
1. tport_sniffer output: <br />
   [*] Destination: 192.168.1.1 <br />
   [*] USER myemail@example.com <br />
