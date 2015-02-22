#hashing of string (sha-1)

from sha1_classString import *

#first hash
#enter the string to be hashed 
get_String=raw_input("enter the string :")
hash_1=hash_sha1(get_String)
hash_1.h_sha1()
hash_1.dispHash()

#second hash
#enter the string to be hashed 
get_String2=raw_input("enter the string :")
hash_3=hash_sha1(get_String2)
hash_3.h_sha1()
hash_3.dispHash()

#comparison of the two hash
if hash_1.dispHash() == hash_3.dispHash():
	print "same string"
else:
	print "string modified"