#class implementaion for hash(sha-1) of a string
# ref-chilkat-http://www.example-code.com/python/crypt_hash_algorithms.asp 
# ref- pytho docs https://docs.python.org/2/library/sha.html
import sys
import chilkat
import base64
crypt = chilkat.CkCrypt2()
success = crypt.UnlockComponent("T12302015Crypt_sHyDCAFgIR1v")

if (success != True):
    print(crypt.lastErrorText())
    sys.exit()


class hash_sha1: 

	# initialsing the attribute 
	def __init__(self,passString):
		self.h_string=passString

	# method to create a hash-sha-1
	def h_sha1(self):
		global crypt
		crypt.put_HashAlgorithm("sha1")
		crypt.put_EncodingMode("hex")
		self.hash = crypt.hashStringENC(self.h_string)
		#print self.hash

	#method to display the created hash	
	def dispHash(self):
		return self.hash

