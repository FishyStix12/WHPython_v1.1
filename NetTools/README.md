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
