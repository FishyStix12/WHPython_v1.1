import os  # Importing the os module for interacting with the operating system
import queue  # Importing the queue module for implementing queues
import requests  # Importing the requests module for sending HTTP requests
import sys  # Importing the sys module for interacting with the Python interpreter
import threading  # Importing the threading module for creating and managing threads
import time  # Importing the time module for working with time

TARGET = input("Please enter the target URL: ")  # Asking the user to input the target URL
THREADS = 10  # Setting the number of threads to 10
FILTERED = input("Please enter file extensions separated by spaces: ").split()  # Asking the user to input filtered file extensions

print("URL:", TARGET)  # Printing the target URL
print("Threads:", THREADS)  # Printing the number of threads
print("Filtered extensions:", FILTERED)  # Printing the filtered file extensions

answers = queue.Queue()  # Creating a queue for storing answers
web_paths = queue.Queue()  # Creating a queue for storing web paths

def gather_paths():  # Defining a function to gather paths
    for root, _, files in os.walk('.'):  # Walking through the directory
        for fname in files:  # Looping through the files
            if os.path.splitext(fname)[1] in FILTERED:  # Checking if the file extension is in the filtered list
                continue  # Skipping the file
            path = os.path.join(root, fname)  # Creating the path
            if path.startswith('.'):  # Checking if the path starts with a dot
                path = path[1:]  # Removing the dot
            print(path)  # Printing the path
            web_paths.put(path)  # Putting the path in the web paths queue

def test_remote():  # Defining a function to test remote URLs
    while not web_paths.empty():  # Checking if the web paths queue is not empty
        path = web_paths.get()  # Getting a path from the queue
        url = f'{TARGET}{path}'  # Creating the URL
        userinput = int(input("Please enter the sleep time: "))  # Asking the user to input the sleep time
        time.sleep(userinput)  # Sleeping for the specified time
        r = requests.get(url)  # Sending a GET request to the URL
        if r.status_code == 200:  # Checking if the request was successful
            answers.put(url)  # Putting the URL in the answers queue
            sys.stdout.write('+')  # Printing a plus sign
        else:  # If the request was not successful
            sys.stdout.write('x')  # Printing a cross sign
        sys.stdout.flush()  # Flushing the stdout buffer

def run():  # Defining a function to run the threads
    mythreads = []  # Creating a list for storing threads
    for i in range(THREADS):  # Looping through the number of threads
        print(f'Spawning thread {i}')  # Printing a message
        t = threading.Thread(target=test_remote)  # Creating a thread
        mythreads.append(t)  # Adding the thread to the list
        t.start()  # Starting the thread

    for thread in mythreads:  # Looping through the threads
        thread.join()  # Waiting for the thread to finish

if __name__ == '__main__':  # Checking if the script is being run directly
    hm_dir = input("Please enter your home directory: ")  # Asking the user to input the home directory
    nw_dir = input("Please enter directory path without including \"/home/*/\"")  # Asking the user to input the directory path
    with contextlib.suppress(FileNotFoundError):  # Suppressing the FileNotFoundError
        os.chdir(f"/home/{hm_dir}/{nw_dir}")  # Changing the current directory

    gather_paths()  # Calling the gather_paths function
    input('Press return to continue!')  # Waiting for the user to press return

    run()  # Calling the run function
    with open('myanswers.txt', 'w') as f:  # Opening a file for writing
        while not answers.empty():  # Checking if the answers queue is not empty
            f.write(f'{answers.get()}\n')  # Writing an answer to the file
        print('done')  # Printing 'done' when finished
