
import sys
import os
import socket
import SocketServer
from threading import Thread
import chilkat
from AES_Class import *

import binascii
print "started"
if (len(sys.argv) < 2):
    print 'Usage: python server.py port <port>\n'
    sys.exit(0)
else:
    PORT = int(sys.argv[1])

serverSocket = socket.socket()
serverSocket.bind(("localhost",PORT))
serverSocket.listen(10)
#-----Creating AES object--------
a = AESClass("cbc",128,0,"hex")
a.set_sessionkey("8713F1BCC6B6AE832E1195D08636A342")
a.setupAES()
#--------------------------------
client, address = serverSocket.accept()
print address
file_f = open("Rec_kali.jpg",'wb') #open in binary      
block = client.recv(2752)
c=0
while (block):
        block=a.dec_str(block)
        unhexblock=binascii.unhexlify(block)
        print "len-unhexblock",len(unhexblock)
        file_f.write(unhexblock)
        block=client.recv(2752)        
        print "len-hexbloack",len(block)
        c=c+1
        print c
print "File Recieved"
file_f.close()
serverSocket.close()
client.close()

