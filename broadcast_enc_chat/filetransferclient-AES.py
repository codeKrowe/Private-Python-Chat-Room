from socket import *
from threading import Thread
import sys
import os
import chilkat
from AES_Class import *
import binascii

#----
if (len(sys.argv) < 2):
	print 'Usage: python client.py <port>\n'
	sys.exit(0)
else:
    PORT = int(sys.argv[1])
#---connect to the server--------
HOST = 'localhost'
BUFSIZE = 1024
ADDR = (HOST, PORT)
client = socket(AF_INET, SOCK_STREAM)
client.connect(ADDR)
# ---- -----------
#using the key which was generated in a previous session
#8713F1BCC6B6AE832E1195D08636A342
#-------------------------------
a = AESClass("cbc",128,0,"hex")
a.set_sessionkey("8713F1BCC6B6AE832E1195D08636A342")
a.setIv("nBPdhiRaT8veTDV+pG0CjqlPGA0=")
a.setupAES()
file_f = open("kali_linux.jpg", "rb")
block = file_f.read(1024)
c=0
while (block): 
    #orig-client.send(block)
    hexblock=binascii.hexlify(block)
    block = a.enc_str(hexblock)
    client.send(block)
    print len(block)
    block = file_f.read(1024)
    #orig-block = file_f.read(1024)
    c=c+1
    print c
print "file sent"
file_f.close()
client.close()






#------------------
'''
block = file_f.read(1024)
while (block):
	hexblock=binascii.hexlify(block)
	block = rsa.encrypt_text(hexblock, ServerPublicKey)
	client.send(block)
	#print len(block)
	block = file_f.read(1024)
print len(block)
'''
