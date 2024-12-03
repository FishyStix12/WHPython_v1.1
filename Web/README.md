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
