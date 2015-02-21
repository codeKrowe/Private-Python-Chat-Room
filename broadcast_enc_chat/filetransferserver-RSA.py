
import sys
import os
import socket
import SocketServer
from threading import Thread
import chilkat
from RSAClass import *
import binascii

if (len(sys.argv) < 2):
    print 'Usage: python server.py port <port>\n'
    sys.exit(0)
else:
    PORT = int(sys.argv[1])

serverSocket = socket.socket()
serverSocket.bind(("localhost",PORT))
serverSocket.listen(10)

#-----Creating Rsa object--------
rsa = RSAClass()
privkey = chilkat.CkPrivateKey()
privkey.LoadXmlFile("Serverprivatekey.xml")
ServerPrivateKey = privkey.getXml()

pubKey = chilkat.CkPublicKey()
pubKey.LoadXmlFile("Serverpublickey.xml")
ServerPublicKey = pubKey.getXml()

client, address = serverSocket.accept()
print address
file_f = open("temp.jpg",'wb') #open in binary      

#--the encrypted blocks are of size -4608
#--receiveing 4608 bytes from the client
block=client.recv(4608)
#----receiving & decrypting-------
while (block): 
        block = rsa.decrypt_text(block, ServerPrivateKey)
        print len(block)
        unhexblock=binascii.unhexlify(block)
        print len(unhexblock)
        file_f.write(unhexblock)
        block=client.recv(4608)
print "file Recieved"
file_f.close()
serverSocket.close()
client.close()

