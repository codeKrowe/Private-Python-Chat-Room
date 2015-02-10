from socket import *
from threading import Thread
import sys

if (len(sys.argv) < 2):
	print 'Usage: python client.py <port>\n'
	sys.exit(0)
else:
    PORT = int(sys.argv[1])

HOST = 'localhost'
#PORT = 8802
BUFSIZE = 1024
ADDR = (HOST, PORT)

client = socket(AF_INET, SOCK_STREAM)
client.connect(ADDR)

def recv():
    while True:
        data = client.recv(BUFSIZE)
        if not data: sys.exit(0)
        print data

Thread(target=recv).start()
while True:
    data = raw_input('> ')
    if not data: break
    client.send(data)

client.close()