#hashing of string (sha-1)
#-160 bit output

import sys
import binascii
import hashlib

from sha1_classString import *

#first hash
#enter the string to be hashed 
get_String=raw_input("enter the string :")
hash_1=hash_sha1(get_String)
hash_1.h_sha1()
print "the hash for the entered string: ",hash_1.dispHash()

#second hash
#enter the string to be hashed 
get_String2=raw_input("enter the string :")
hash_2=hash_sha1(get_String2)
hash_2.h_sha1()
print "the hash for the entered string: ",hash_2.dispHash()

#comparison of the two hash
if hash_1.dispHash() == hash_2.dispHash():
	print "same string"
else:
	print "string modified"