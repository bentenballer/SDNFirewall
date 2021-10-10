#!/usr/bin/python

import socket
import sys

if not (len(sys.argv) >= 4):
    print("Syntax:")
    print("  python test-client.py <ipprotocol> <server-ip> <port> <srcport>")
    print("    <ipprotocol> - T for TCP, U for UDP")
    print("    <server-ip> - The IP Address of the Server.  NOT THE CLIENT IP ADDRESS!")
    print("    <port> - The TCP/UDP Port Number")
    print("    <srcport> - Source port (optional) for TCP only")
    exit()

# Create Socket
if sys.argv[1] == 'T':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if (len(sys.argv) == 5):
        sock.bind(('0.0.0.0',sys.argv[4]))
elif sys.argv[1] == 'U':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
else:
    print("Invalid IP Protocol Specified.  Try again...")
    exit()

# Connect the socket to the port where the server is listening
server_address = (sys.argv[2], int(sys.argv[3]))
print('connecting to %s port %s' % server_address)
sock.connect(server_address)

try:
    
    # Send data
    message = 'This is the message.  It will be repeated.'
    print('Sending "%s"' % message)
    encoded = message.encode()
    if sys.argv[1] == 'T':
        sock.sendall(encoded)
    else:
        sock.sendto(encoded,server_address)

    # Look for the response
    amount_received = 0
    amount_expected = len(message)
    
    while amount_received < amount_expected:
        if sys.argv[1] == 'T':
            data = sock.recv(16)
        else:
            data, address = sock.recvfrom(48)
        amount_received += len(data)
        decode = data.decode()
        print('Received "%s"' % decode)
    if amount_received == amount_expected:
        print('Message sent successfully')

finally:
    print('Closing socket')
    sock.close()
