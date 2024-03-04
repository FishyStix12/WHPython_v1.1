#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# The provided Python script is designed to extract and save images from HTTP traffic stored in a 
# PCAP file. It utilizes the Scapy library for packet manipulation and extraction. The script 
# reads a PCAP file containing network traffic, filters out HTTP packets, extracts images 
# from the HTTP responses, and saves them to a specified directory. To use the script, you need 
# to specify the input PCAP file path and the output directory for the extracted images. For 
# example, to extract images from a PCAP file named 'example.pcap' located in the 'Downloads' 
# directory and save them to the 'Pictures' directory on the desktop, you would set 
# PCAPS to '/root/Downloads' and OUTDIR to '/root/Desktop/pictures'. After running the script,
# it will process the PCAP file and save the extracted images to the specified output directory. 
# The output will include one or more image files (e.g., ex_0.jpg, ex_1.png, etc.) containing the 
# extracted images.
#################################################################################################

from scapy.all import TCP, rdpcap  # Import necessary modules from scapy
import collections  # Import collections module for namedtuple
import os  # Import os module for file operations
import re  # Import re module for regular expressions
import sys  # Import sys module for system-specific parameters and functions
import zlib  # Import zlib module for compression and decompression

OUTDIR = '/root/Desktop/pictures'  # Output directory for extracted files
PCAPS = '/root/Downloads'  # Directory containing pcap files

# Named tuple for representing a response with header and payload
Response = collections.namedtuple('Response', ['header', 'payload'])

# Function to extract header from payload
def get_header(payload):
    try:
        # Find the end of the header section (end of headers is marked by '\r\n\r\n')
        header_raw = payload[:payload.index(b'\r\n\r\n')+2]
    except ValueError:
        # If '\r\n\r\n' is not found, return None
        sys.stdout.write('-')
        sys.stdout.flush()
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
    def __init__(self, fname):
        # Read pcap file and extract sessions
        pcap = rdpcap(fname)
        self.sessions = pcap.sessions()
        self.responses = []

    # Method to extract responses from sessions
    def get_responses(self):
        for session in self.sessions:
            payload = b''
            for packet in self.sessions[session]:
                try:
                    # Check if packet is HTTP (port 80)
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        payload += bytes(packet[TCP].payload)
                except IndexError:
                    # If index error occurs, print 'x'
                    sys.stdout.write('x')
                    sys.stdout.flush()
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
                fname = os.path.join(OUTDIR, f'ex_{i}.{content_type}')
                # Print message and write content to file
                print(f'Writing {fname}')
                with open(fname, 'wb') as f:
                    f.write(content)

# Main section
if __name__ == '__main__':
    # Specify pcap file path
    pfile = os.path.join(PCAPS, 'pcap.pcap')
    # Initialize Rcap instance with pcap file
    rcap = Rcap(pfile)
    # Extract responses from pcap file
    rcap.get_responses()
    # Write extracted content to files
    rcap.write('image')
