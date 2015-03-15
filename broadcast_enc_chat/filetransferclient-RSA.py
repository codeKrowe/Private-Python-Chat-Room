from socket import *
from threading import Thread
import sys
import os
import chilkat
from RSAClass import *
import binascii

#----creating a RSA object-rsa
rsa=RSAClass()


if (len(sys.argv) < 2):
	print 'Usage: python client.py <port>\n'
	sys.exit(0)
else:
    PORT = int(sys.argv[1])
#-----file to be sent----------------
file_f = open("kali_linux.jpg", "rb")
# fileSize =  os.stat("kali_linux.jpg").st_size

HOST = 'localhost'
BUFSIZE = 1024
ADDR = (HOST, PORT)
client = socket(AF_INET, SOCK_STREAM)
client.connect(ADDR)

# ---- generating keys-----------
pubKey = chilkat.CkPublicKey()
pubKey.LoadXmlFile("Serverpublickey.xml")
ServerPublicKey = pubKey.getXml()


#--------encrypting & sending--------
block = file_f.read(1024)
while (block):
	hexblock=binascii.hexlify(block)
	block = rsa.encrypt_text(hexblock, ServerPublicKey)
	client.send(block)
	#print len(block)
	block = file_f.read(1024)
print len(block)
file_f.close()
client.close()




