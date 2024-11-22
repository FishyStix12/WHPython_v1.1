#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 25th 2024
# Description of Script
# This Python script creates a graphical user interface (GUI) application named "Dark Net Wizard" 
# using Tkinter. The application allows users to perform Nmap scans with firewall evasion techniques
# on specified target IP addresses or CIDR ranges. It includes options for inputting target ports or 
# port ranges, and it displays the scan results, including any found Common Vulnerabilities and 
# Exposures (CVEs) and Metasploit exploit modules if they exist. The GUI features a dark purple
# background color, an image display at the top (which can be replaced with a custom image link),
# input fields for IP addresses and ports, buttons for scanning and exiting the application, and 
# an output box for displaying scan results and messages.
# Important Note:
# Must run this script as superuser
#################################################################################################
import subprocess
import re
import tkinter as tk
from PIL import Image, ImageTk
import requests
from io import BytesIO  # Import BytesIO for handling image data

# Function to perform Nmap scan with firewall evasion techniques
def nmap_scan():
    host = ip_entry.get()
    port_range = port_entry.get()
    try:
        if port_range:
            # Add firewall evasion techniques
            arguments = f'-T2 -sS -sV -O --version-all --script=banner -A --script vulners -p {port_range} --mtu 16 --badsum --data-length 500'
        else:
            arguments = '-T2 -sS -sV -O --version-all --script=banner -A --script vulners --mtu 16 --badsum --data-length 500'

        command = f"nmap {arguments} {host}"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        vuln_output.delete(1.0, tk.END)  # Clear previous output
        vuln_output.insert(tk.END, stdout.decode() + "\n")  # Display scan output
        vuln_output.insert(tk.END, stderr.decode() + "\n")  # Display any errors

        # Extract CVEs and Metasploit modules if they exist
        cves = re.findall(r"CVE-\d+-\d+", stdout.decode())
        if cves:
            vuln_output.insert(tk.END, "\nFound CVEs:\n")
            for cve in cves:
                vuln_output.insert(tk.END, f"{cve}\n")

        metasploit_modules = re.findall(r"exploit/(.*?)/", stdout.decode())
        if metasploit_modules:
            vuln_output.insert(tk.END, "\nFound Metasploit modules:\n")
            for module in metasploit_modules:
                vuln_output.insert(tk.END, f"{module}\n")

    except Exception as e:
        vuln_output.insert(tk.END, f"Error during Nmap scan: {e}\n")


# Function to handle button click event for exiting the application
def exit_app():
    root.destroy()

# Create the main GUI window
root = tk.Tk()
root.title("Dark Net Wizard")
root.configure(bg="#330033")  # Set darker purple background color

# Load and display the image at the top
image_link = "https://animerants.net/wp-content/uploads/2024/01/frieren-episode-08-fern.png?w=1024"  # Replace with your image link
response = requests.get(image_link)
image_data = response.content
image = Image.open(BytesIO(image_data))
photo = ImageTk.PhotoImage(image)
image_label = tk.Label(root, image=photo)
image_label.image = photo  # Keep a reference to the image to prevent garbage collection
image_label.pack()

# IP label and entry
ip_label = tk.Label(root, text="Target IP Address/CIDR:", bg="#330033", fg="white")
ip_label.pack()

ip_entry = tk.Entry(root, bg="#000000", fg="#ffffff")  # Dark background, white text
ip_entry.pack()

# Port label and entry
port_label = tk.Label(root, text="Target Port/Port Range (optional):", bg="#330033", fg="white")
port_label.pack()

port_entry = tk.Entry(root, bg="#000000", fg="#ffffff")  # Dark background, white text
port_entry.pack()

# Scan button
scan_button = tk.Button(root, text="Scan", command=nmap_scan, bg="#004d00", fg="#ffffff")  # Dark green background, white text
scan_button.pack()

# Output box for vulnerability scan results
vuln_output = tk.Text(root, height=20, width=80, bg="#000000", fg="#ffffff")  # Dark background, white text
vuln_output.pack()

# Exit button
exit_button = tk.Button(root, text="Exit", command=exit_app, bg="#660000", fg="#ffffff")  # Dark red background, white text
exit_button.pack()

# Main loop
root.mainloop()
