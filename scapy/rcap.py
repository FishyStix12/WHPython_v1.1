#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# The script is a Python tool designed to parse pcap files containing network traffic data,
# particularly HTTP traffic, and extract images transferred over HTTP from a specified target 
# host. Users can interactively provide inputs such as the path to the pcap file, the target 
# host's IP address, the target port number, and the output directory for saving the extracted
# images. Leveraging the Scapy library for packet manipulation, the script identifies relevant
# packets based on the specified target IP address and port number. It then extracts images 
# from HTTP responses, considering content type and encoding, and saves them to the designated
# output directory. With its interactive nature and capability to process pcap files, this 
# script offers a flexible and efficient solution for extracting images from network traffic data. 
#################################################################################################
from scapy.all import TCP, IP, rdpcap  
import collections  
import os  
import re  
import sys 
import zlib  
import argparse 
import logging  

# Named tuple for representing a response with header and payload
Response = collections.namedtuple('Response', ['header', 'payload'])

# Function to extract header from payload
def get_header(payload):
    try:
        # Find the end of the header section (end of headers is marked by '\r\n\r\n')
        header_raw = payload[:payload.index(b'\r\n\r\n')+2]
    except ValueError:
        # If '\r\n\r\n' is not found, return None
        logging.warning('Header not found in payload.')
        return None
    # Parse the header into a dictionary
    header = dict(re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', header_raw.decode()))
    # Check if Content-Type header is present
    if 'Content-Type' not in header:
        return None
    return header

# Function to extract content from a response
def extract_content(response, content_name='image'):
    content, content_type = None, None
    # Check if the content name is in the Content-Type header
    if content_name in response.header.get('Content-Type', ''):
        # Get the content type (e.g., 'image/jpeg')
        content_type = response.header['Content-Type'].split('/')[1]
        # Extract the content after the header
        content = response.payload[response.payload.index(b'\r\n\r\n')+4:]

        # Handle content encoding (gzip or deflate)
        if 'Content-Encoding' in response.header:
            if response.header['Content-Encoding'] == "gzip":
                content = zlib.decompress(content, zlib.MAX_WBITS | 32)
            elif response.header['Content-Encoding'] == "deflate":
                content = zlib.decompress(content)
    return content, content_type

# Class to process pcap files
class Rcap:
    def __init__(self, fname, target_ip, target_port, output_dir):
        # Read pcap file and extract sessions
        self.fname = fname
        pcap = rdpcap(fname)
        self.sessions = pcap.sessions()
        self.responses = []
        self.target_ip = target_ip
        self.target_port = target_port
        self.output_dir = output_dir

    # Method to extract responses from sessions
    def get_responses(self):
        for session in self.sessions:
            payload = b''
            for packet in self.sessions[session]:
                try:
                    # Check if packet is HTTP (port 80)
                    if packet.haslayer(TCP) and packet.haslayer(IP):
                        if packet[IP].dst == self.target_ip and packet[TCP].dport == self.target_port:
                            payload += bytes(packet[TCP].payload)
                        elif packet[IP].src == self.target_ip and packet[TCP].sport == self.target_port:
                            payload += bytes(packet[TCP].payload)
                except IndexError:
                    # If index error occurs, log a warning
                    logging.warning('IndexError occurred while processing packet.')
            # If payload is not empty, extract header and add response to list
            if payload:
                header = get_header(payload)
                if header is None:
                    continue
                self.responses.append(Response(header=header, payload=payload))

    # Method to write extracted content to files
    def write(self, content_name):
        for i, response in enumerate(self.responses):
            content, content_type = extract_content(response, content_name)
            if content and content_type:
                # Construct file name using index and content type
                fname = os.path.join(self.output_dir, f'ex_{i}.{content_type}')
                # Print message and write content to file
                logging.info(f'Writing {fname}')
                with open(fname, 'wb') as f:
                    f.write(content)

# Main section
if __name__ == '__main__':
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # User input for target host IP address and port
    pcap_file = input("Enter the path to the pcap file: ")
    target_ip = input("Enter the target host IP address: ")
    target_port = input("Enter the target port number: ")
    output_dir = input("Enter the output directory for extracted files (press Enter for default): ") or '/root/Desktop/pictures'

    # Validate output directory
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Initialize Rcap instance with user inputs
    rcap = Rcap(pcap_file, target_ip, int(target_port), output_dir)
    # Extract responses from pcap file
    rcap.get_responses()
    # Write extracted content to files
    rcap.write('image')

