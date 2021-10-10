#!/usr/bin/python

import sys
import socket

if not (len(sys.argv) == 4):
    print("Syntax:")
    print("  python test-server.py <ipprotocol> <server-ip> <port>")
    print("    <ipprotocol> - T for TCP, U for UDP")
    print("    <server-ip> - The IP Address of this machine")
    print("    <port> - The TCP/UDP Port Number")
    exit()

# Create Socket
if sys.argv[1] == 'T':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
elif sys.argv[1] == 'U':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
else:
    print("Invalid IP Protocol Specified.  Try again...")
    exit()

# Bind the socket to the port3
server_address = (sys.argv[2], int(sys.argv[3]))
print('Starting Server on %s port %s' % server_address)
sock.bind(server_address)

# Listen for incoming connections
if sys.argv[1] == 'T':
    sock.listen(1)


while True:
    # Wait for a connection
    if sys.argv[1] == 'T':
        print ('Waiting for a Connection')
        connection, client_address = sock.accept()

    try:
        if sys.argv[1] == 'T':
            print('Connection from ', client_address)

        # Receive the data in small chunks and retransmit it
        while True:
            if sys.argv[1] == 'T':
                data = connection.recv(16)
            else:
                data,client_address = sock.recvfrom(48)
            decode = data.decode()
            print('Received "%s"' % decode)
            if data:
                print('Sending data back to the client')
                if sys.argv[1] == 'T':
                    connection.sendall(data)
                else:
                    sock.sendto(data,client_address)
            else:
                print('No more data from', client_address)
                break
            
    finally:
        # Clean up the connection
        if sys.argv[1] == 'T':
            connection.close()
        print("Finished")
