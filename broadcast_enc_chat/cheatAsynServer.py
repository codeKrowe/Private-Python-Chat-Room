
import sys
import os
import socket
import SocketServer
from threading import Thread

if (len(sys.argv) < 2):
    print 'Usage: python server.py port <port>\n'
    sys.exit(0)
else:
    PORT = int(sys.argv[1])

# Takes first argument after scriptname as inout from command line


HOST = '127.0.01'
#PORT = 8802
BUFSIZE = 1024
ADDR = (HOST, PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # allow resuse of the port/socket
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(5)

    # blocking call to accept()
print 'Waiting for partner to join conversation...\n'
(conn, client_addr) = server.accept()

 
def recv():
    while True:
        data = conn.recv(BUFSIZE)
        if not data: sys.exit(0)
        print data

Thread(target=recv).start()
while True:
    data = raw_input('> ')
    if not data: break
    conn.send(data)

server.close()