
import sys
import os
import socket
import SocketServer
from threading import Thread
import chilkat

if (len(sys.argv) < 2):
    print 'Usage: python server.py port <port>\n'
    sys.exit(0)
else:
    PORT = int(sys.argv[1])


serverSocket = socket.socket()
serverSocket.bind(("localhost",PORT))
serverSocket.listen(10)


client, address = serverSocket.accept()
print address
file_f = open("temp.jpg",'wb') #open in binary      
block = client.recv(1024)
while (block):
        file_f.write(block)
        block = client.recv(1024)

print "File Recieved"
file_f.close()
serverSocket.close()
client.close()

