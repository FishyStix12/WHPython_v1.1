#!/usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 3rd 2024
# This script implements a basic TCP proxy. It listens on a specified local host and port, forwards incoming
# connections to a remote host and port, and relays data between the client and the remote server.
# It can be used for various purposes such as debugging, monitoring, or modifying network traffic.
# Usage:
# ./proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]
# Example:
# ./proxy.py 127.0.0.1 9000 10.21.132.1 9000 True
#################################################################################################
import sys
import socket
import threading

# HEX_FILTER is a string containing ASCII printable characters or a dot (.) if not printable.
HEX_FILTER = ''.join([(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

def hexdump(src, length=16, show=True):
    """
    Hexdump function to print packet details in hexadecimal and ASCII printable characters.
    """
    if isinstance(src, bytes):
        src = src.decode()  # Convert bytes to string
    results = []
    for i in range(0, len(src), length):
        word = str(src[i:i+length])
        printable = word.translate(HEX_FILTER)
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length*3
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')
    if show:
        for line in results:
            print(line)
    else:
        return results

def receive_from(connection):
    """
    Receive data from a connection.
    """
    buffer = b""
    connection.settimeout(5)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception as e:
        pass
    return buffer

def request_handler(buffer):
    """
    Handle requests and perform packet modifications.
    """
    # Modify the buffer here if needed
    return buffer

def response_handler(buffer):
    """
    Handle responses and perform packet modifications.
    """
    # Modify the buffer here if needed
    return buffer

def proxy_handler(client_socket, remote_host, remote_port, receive_first, remote_buffer=None):
    """
    Handle proxy communication between client and remote host.
    """
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print("[<==] Sending %d bytes to client." % len(remote_buffer))
        client_socket.send(remote_buffer)

    while True:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            print("[==>] Received %d bytes from client." % len(local_buffer))
            hexdump(local_buffer)

            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print("[<==] Received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to client.")

        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    """
    Main server loop to listen for incoming connections and start proxy threads.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print('Problem on bind: %r' % e)
        print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)

    print("[*] Listening on %s:%d" % (local_host, local_port))
    server.listen(5)
    while True:
        client_socket, addr = server.accept()
        print("[*] Received incoming connection from %s:%d" % (addr[0], addr[1]))
        proxy_thread = threading.Thread(target=proxy_handler,
                                        args=(client_socket, remote_host, remote_port, receive_first))
        proxy_thread.start()

def main():
    """
    Main function to parse command line arguments and start the proxy server.
    """
    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.21.132.1 9000 True")
        sys.exit(0)

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    receive_first = sys.argv[5].lower() in ['true', 'yes', '1']

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == '__main__':
    main()
