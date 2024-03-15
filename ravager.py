#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# This script is a directory busting tool designed to enumerate directories and files on a web 
# server. It prompts the user to input the target host IP address, port, and the path to a 
# wordlist file containing potential directory and file names. Utilizing threading for concurrent
# requests, it sends HTTP requests to the specified host, attempting to access each directory and 
# file combination generated from the provided wordlist. If a directory or file is found, it outputs
# a success message along with the corresponding URL. This tool is commonly used in security
# testing to identify hidden or unprotected resources on web servers.
#################################################################################################
import queue  
import requests  
import threading  
import sys  

# Set user agent for HTTP requests
AGENT = "Mozilla/5.0 (x11; Linux x86_64; rv:19.0) Gecko/20100101 Firefox/19.0"
# Common file extensions to append to URLs
EXTENSIONS = ['.php', '.bak', '.orig', '.inc']
# Get target host IP address and port from user input
HOST = input("Please input target host IP address: ")
PORT = input("Please input target port: ")
# Number of threads for concurrent requests
THREADS = 50
# Get wordlist file path from user input
WORDLIST = input("Enter path to all.txt file: ")


# Function to generate a queue of words from a wordlist file
def get_words(resume=None):
    words = queue.Queue()

    # Function to add file extensions to a word
    def add_extensions(word):
        for extension in EXTENSIONS:
            words.put(f'/{word}{extension}')

    # Read wordlist file and process each word
    with open(WORDLIST) as f:
        raw_words = f.read().split()

    found_resume = resume is None
    for word in raw_words:
        if found_resume:
            add_extensions(word)
        elif word == resume:
            found_resume = True
            print(f'Resuming wordlist from {resume}')
        else:
            print(word)
            words.put(f'/{word}/')
            add_extensions(word)
    return words


# Function to perform directory busting
def dir_buster(words):
    headers = {'User-Agent': AGENT}
    while not words.empty():
        url = f'http://{HOST}:{PORT}{words.get()}'
        try:
            r = requests.get(url, headers=headers)
            if r.status_code == 200:
                print(f'\nSuccess ({r.status_code}: {url})')
            elif r.status_code == 404:
                sys.stderr.write('.')
            else:
                print(f'{r.status_code} => {url}')
        except requests.exceptions.ConnectionError:
            sys.stderr.write('x')
        sys.stderr.flush()


# Main entry point of the script
if __name__ == '__main__':
    # Generate wordlist
    words = get_words()

    # Wait for user input to start the threads
    print('Press return to continue.')
    sys.stdin.readline()

    # Start the threads for directory busting
    for _ in range(THREADS):
        t = threading.Thread(target=dir_buster, args=(words,))
        t.start()
