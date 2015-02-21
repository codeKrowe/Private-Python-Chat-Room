#class implementaion for hash-sha-1

import sys
import chilkat
crypt = chilkat.CkCrypt2()
success = crypt.UnlockComponent("T12302015Crypt_sHyDCAFgIR1v")

if (success != True):
    print(crypt.lastErrorText())
    sys.exit()

#  Any type of file may be hashed.
#  There is  no size limitation because the file is consumed
#  in streaming mode internally.

class hash_sha1:
	#pass the filepath 

	def __init__(self,h_fpath):
		self.h_fpath=h_fpath	
	
	def h_sha1(self):
		global crypt
		crypt.put_HashAlgorithm("sha1")
		crypt.put_EncodingMode("hex")
		self.suc_hash =crypt.hashFileENC(self.h_fpath)
		print self.suc_hash
		'''
	def fun3(self,self.such_hash):
	def disp_hash(self):
		self.thisone=self.a1212
			
'''
