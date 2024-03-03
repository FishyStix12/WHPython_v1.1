#! /usr/bin/python
# imports the python modules needed for the tool to run
# The subprocess library provides powerful process-creation interfaces that gives a number of ways to interact with client programs
import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading

# This creates a command to run a command on the local operating system and then returns the output from that command
def execute(cmd):
	cmd = cmd.strip()
	if not cmd:
		return
	output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
	return output.decode()

# Client Code
# The scripts initializes the NetCat object with the arguments from the command line and the buffer, and then we create the socket object.
# The run method is the entry point for managing the NetCat object, simply by delegating its execution into two methods: a Listener
# or a Sender.
class NetCat:
	def __init__(self, args, buffer=None):
		self.args = args
		self.buffer = buffer
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Uses IPv4 and TCP for socket library
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	def run(self):
		if self.args.listen:
			self.listen()
		else:
			self.send()

# Here we connect to the target and TCP port, and if we have a buffer the script send it to the target first. Then we setup a try/catch block so we can
# manually close the connection with the keys CTRL-C. Next the script starts a loop to recieve data from the selected target. If there
# is no more data, we break out of the loop, otherwise we print the response data and pause to get interactive input, and send that input,
# and continue the loop.
# Note: The loop will continue until the KeyboardInterrupt occurs, which will close the socket.
	def send(self):
		self.socket.connect((self.args.target, self.args.port))
		if self.buffer:
			self.socket.send(self.buffer)

		try:
			while True:
				recv_len = 1
				response = ''
				while recv_len:
					data = self.socket.recv(4096)
					recv_len = len(data)
					response += data.decode()
					if recv_len < 4096:
						break
				if response:
					print(response)
					buffer = input('> ')
					buffer += '\n'
					self.socket.close()
					sys.exit()
		except KeyboardInterrupt:
			print('User terminated.')
			self.socket.close()
			sys.exit()
# Here is the code that executes when we run the program as a listener. The listen method binds to the target and port
# and starts listening in a loop, passing the connected socket to the handle method
	def listen(self):
		self.socket.bind((self.args.target, self.args.port))
		self.socket.listen(5)
		while True:
			client_socket, _ = self.socket.accept()
			client_thread = threading.Thread(target=self.handle, args=(client_socket,))
			client_thread.start()

# Logic to upload Files, execute commands, and create interactive shells. The script can perform these tasks while acting as a listener.
	def handle(self, client_socket):
		if self.args.execute:
			output = execute(self.args.execute)
			client_socket.send(output.encode())

		elif self.args.upload:
			file_buffer = b''
			while True:
				data = client_socket.recv(4096)
				if data:
					file_buffer += data
				else:
					break
			with open(self.args.upload, 'wb') as f:
				f.write(file_buffer)
			message = f'Saved file {self.args.upload}'
			client_socket.send(message.encode())
		elif self.args.command:
			cmd_buffer = b''
			while True:
				try:
					client_socket.send('BHP: \#> ')
					while '\n' not in cmd_buffer.decode():
						cmd_buffer += client_socket.recv(64)
					response = execute(cmd_buffer.decode())
					if response:
						client_socket.send(response.encode())
					cmd_buffer = b''
				except Exception as e:
					print(f'server killed {e}')
					self.socket.close()
					sys.exit()

# This is our main block for the script and is responsible for handling the command line arguments and calling the rest of
# our functions
# The script uses the argparse module from the standard library to create the command line interface. We have provided arguments so it can be
# Invoked to upload a file, execute a command, or start a command shell.
# When the user invokes the program with --help the code will display Parser Example. And the 6 arguments for -c, -u, -p, etc.
# If we are setting up a listener, we invoke the NetCat object with an empty buffer string. Otherwise we send the buffer from
# stdin, and finally we call the run method to start it up.
if __name__=='__main__':
	parser = argparse.ArgumentParser( description='BHP Net Tool', formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent('''Example:
		netcat.py -t 192.168.1.108 -p 5555 -l -c #command shell
		netcat.py -t 192.168.1.108 -p 5555  -l -u=mytest.txt #uploads to file
		netcat.py -t 192.168.1.108 -p 5555 -l -e=\'cat /etc/passwd\' # executes a command
		echo "ABC" | netcat.py -t 192.169.1.108 -p 135 # echo text to server port 135
		netcat.py -t 192.168.1.108 -p 5555 # connect to a server
	'''))
parser.add_argument('-c', '--comand', action='store_true', help='command shell')
parser.add_argument('-e', '--execute', help='execute specified command')
parser.add_argument('-l', '--listen', action='store_true', help='listen')
parser.add_argument('-p', '--port', type=int, default=5555, help='specified port')
parser.add_argument('-t', '--target', default='192.168.1.203', help='specified IP')
parser.add_argument('-u', '--upload', help='upload file')
args = parser.parse_args()
if args.listen:
	buffer = ''
else:
	buffer = sys.stdin.read()

nc = NetCat(args, buffer.encode())
nc.run()
