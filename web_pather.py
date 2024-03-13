#! /usr/bin/python
#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# This script prompts the user to input a URL and a list of file extensions 
# separated by spaces. It constructs a URL using the input, sets the number of threads to 10, 
# and creates a list of file extensions based on the user input. The script then prints out the 
# constructed URL, the number of threads, and the list of filtered file extensions. This script 
# can be used to quickly set up a web scraping or downloading task with customizable file type 
# filters. For example, after running the script and providing "example.com" as the URL and ".jpg 
# .png .pdf" as the file extensions, the output would be:
# Copy code
# URL: http://example.com
# Threads: 10
# Filtered extensions: ['.jpg', '.png', '.pdf']
#################################################################################################
import os
import queue
import requests
import sys
import threading
import time

TARGET_IP = input("Please enter the IP address of the website: ")  # Asking the user to input the IP address
THREADS = 10  # Setting the number of threads to 10

print("IP Address:", TARGET_IP)  # Printing the IP address
print("Threads:", THREADS)  # Printing the number of threads

answers = queue.Queue()  # Creating a queue for storing answers
web_paths = queue.Queue()  # Creating a queue for storing web paths

def gather_paths(start_path='/'):  # Defining a function to gather paths
    for root, _, files in os.walk(start_path):  # Walking through the directory
        for fname in files:  # Looping through the files
            path = os.path.join(root, fname)  # Creating the path
            if path.startswith('.'):  # Checking if the path starts with a dot
                path = path[1:]  # Removing the dot
            print(path)  # Printing the path
            web_paths.put(path)  # Putting the path in the web paths queue

            # Here, instead of calling run(), we directly spawn threads for testing remote URLs
            if web_paths.qsize() >= THREADS:
                run_threads()

    # After gathering all paths, if there are still paths left, spawn threads
    if not web_paths.empty():
        run_threads()

def run_threads():
    mythreads = []  # Creating a list for storing threads
    for _ in range(THREADS):  # Looping through the number of threads
        t = threading.Thread(target=test_remote)  # Creating a thread
        mythreads.append(t)  # Adding the thread to the list
        t.start()  # Starting the thread

    for thread in mythreads:  # Looping through the threads
        thread.join()  # Waiting for the thread to finish

def test_remote():  # Defining a function to test remote URLs
    while not web_paths.empty():  # Checking if the web paths queue is not empty
        path = web_paths.get()  # Getting a path from the queue
        url = f'http://{TARGET_IP}/{path}'  # Creating the URL with IP address
        headers = {'User-Agent': 'Mozilla/5.0', 'Referer': 'http://www.google.com'}  # Adding headers to bypass firewall detection
        r = requests.get(url, headers=headers)  # Sending a GET request to the URL with headers
        if r.status_code == 200:  # Checking if the request was successful
            answers.put(url)  # Putting the URL in the answers queue
            sys.stdout.write('+')  # Printing a plus sign
        else:  # If the request was not successful
            sys.stdout.write('x')  # Printing a cross sign
        sys.stdout.flush()  # Flushing the stdout buffer

if __name__ == '__main__':  # Checking if the script is being run directly
    gather_paths('/')  # Calling the gather_paths function with root directory
    input('Press return to continue!')  # Waiting for the user to press return

    # After gathering all paths and spawning threads, append results to a file
    file_name = input("Enter the name of the file to save the results: ")  # Asking the user for the file name
    with open(file_name, 'a') as f:  # Opening a file for appending
        while not answers.empty():  # Checking if the answers queue is not empty
            f.write(f'{answers.get()}\n')  # Writing an answer to the file
        print('Results appended to', file_name)  # Printing confirmation

