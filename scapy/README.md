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
