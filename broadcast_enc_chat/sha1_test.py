#hashing the file

from sha1_class import *
#/home/nidhu/ee6032prj/chatclient/ChatClient/test.zip/aes_test.py
#passing the filepath which was generated after runnning 
#zip file generated after running aes
#using the generated zip file for hashing

fpath="/home/nidhu/ee6032prj/chatclient/ChatClient/test.zip"
hash_1=hash_sha1(fpath)
print "generated hash 1"
hone=hash_1.h_sha1()
