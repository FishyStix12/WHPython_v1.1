#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# This script performs directory busting on a remote web server specified by the user. 
# It starts the enumeration from the root directory of the server and recursively explores all 
# directories and files. The script generates URLs for common file types and checks if they exist on 
# the server. Additionally, it parses HTML content from directory listings to discover subdirectories 
# and continues enumeration. After completing the directory busting, the script prompts the user to 
# enter a file name to save the discovered URLs. It then appends the results to the specified file,
# allowing the user to review the findings conveniently. This script provides a straightforward
# and automated approach to identify potentially sensitive or vulnerable directories 
# and files on a web server.
#################################################################################################
import requests
import threading
from queue import Queue
from urllib.parse import urljoin

TARGET_IP = input("Please enter the IP address of the web server: ")  # IP address of the web server
THREADS = 10  # Number of threads

print("Web Server IP:", TARGET_IP)
print("Threads:", THREADS)

file_types = [".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl", ".html", ".txt", ".bak", ".zip", ".tar", ".gz", ".sql"]  # Common file types

directories = Queue()  # Queue for storing directories
results = Queue()  # Queue for storing results

def dirbust():
    while not directories.empty():
        directory = directories.get()
        for file_type in file_types:
            url = urljoin(f"http://{TARGET_IP}/", directory) + f"/index{file_type}"
            response = requests.get(url)
            if response.status_code == 200:
                results.put(url)

        # Enumerate subdirectories
        response = requests.get(urljoin(f"http://{TARGET_IP}/", directory))
        if response.status_code == 200:
            for line in response.text.splitlines():
                if line.startswith("<a href="):
                    subdir = line.split('"')[1]
                    if subdir != "../" and subdir.endswith("/"):  # Ignore parent directory and non-directories
                        directories.put(urljoin(directory, subdir))

def run_threads():
    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=dirbust)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

def main():
    # Start enumeration from the root directory
    directories.put('')

    run_threads()

    if not results.empty():
        # Ask user for file name to save results
        file_name = input("Enter the name of the file to save the results: ")
        if not file_name.strip():
            print("Invalid file name. Results not saved.")
            return

        with open(file_name, "a") as f:
            while not results.empty():
                f.write(results.get() + "\n")
            print("Results appended to", file_name)
    else:
        print("No results found.")

if __name__ == "__main__":
    main()

