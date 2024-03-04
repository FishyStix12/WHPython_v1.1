#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# This Python script is a simple tool for performing directory busting on a web server using a 
# wordlist of common directory names and file extensions. It takes a target URL and a wordlist 
# file as inputs, and then iterates through the combinations of words and extensions to construct 
# URLs to check. It uses threading to speed up the process by making multiple HTTP requests 
# simultaneously.
# Example output:
# Please input URL here: http://example.com
# Enter path to all.txt file: wordlist.txt
# Press return to continue.
# Success (200: http://example.com/admin.php)
# Success (200: http://example.com/test.bak)
# 404 => http://example.com/notfound.php
#################################################################################################
# Import necessary libraries
import queue  # For queue data structure
import requests  # For making HTTP requests
import threading  # For threading support
import sys  # For system-specific parameters and functions

# Set user agent for HTTP requests
AGENT = "Mozilla/5.0 (x11; Linux x86_64; rv:19.0) Gecko/20100101 Firefox/19.0"
# Common file extensions to append to URLs
EXTENSIONS = ['.php', '.bak', '.orig', '.inc']
# Get target URL from user input
TARGET = input("Please input URL here: ")
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
        url = f'{TARGET}{words.get()}'
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
