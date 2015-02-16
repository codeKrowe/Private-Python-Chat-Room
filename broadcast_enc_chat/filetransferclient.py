from socket import *
from threading import Thread
import sys
import os
import chilkat


if (len(sys.argv) < 2):
	print 'Usage: python client.py <port>\n'
	sys.exit(0)
else:
    PORT = int(sys.argv[1])

file_f = open("kali_linux.jpg", "rb")
# fileSize =  os.stat("kali_linux.jpg").st_size

HOST = 'localhost'
BUFSIZE = 1024
ADDR = (HOST, PORT)
client = socket(AF_INET, SOCK_STREAM)
client.connect(ADDR)


block = file_f.read(1024)
while (block):
    client.send(block)
    block = file_f.read(1024)
client.close()



