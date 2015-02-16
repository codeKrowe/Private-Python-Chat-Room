#!/usr/bin/python
import sys
import chilkat
import os, binascii 
crypt = chilkat.CkCrypt2()
success = crypt.UnlockComponent("T12302015Crypt_sHyDCAFgIR1v")
if (success != True):
	print(crypt.lastErrorText())
	sys.exit()

zip = chilkat.CkZip()
success = zip.UnlockComponent("T12302015ZIP_uBPbJkarIRCd")
if (success != True):
    print(zip.lastErrorText())
    sys.exit()

class AESClass:
	def __init__(self, mode,keylen,padding,enc_mode):
		self.mode = mode
		if keylen != 128 or 192 or 265:
			self.keylen = 256
		self.padding = padding	
		self.enc_mode = enc_mode
		self.setup = False
		self.ivHex = None
		self.keyHex = None 
		self.keylen = keylen
		self.session_flag = False

	def setupAES(self):
		global crypt
		crypt.put_CryptAlgorithm("aes")
		crypt.put_CipherMode(self.mode)
		crypt.put_PaddingScheme(self.padding)
		if self.mode == "cbc":
			#ivHex = binascii.b2a_hex(os.urandom(16))
			# self.ivHex = crypt.genRandomBytesENC(16)
			#self.ivHex = "6JDLMMXKvbavsnpzwDhquA=="
			crypt.SetEncodedIV(self.ivHex,"hex")

		if (self.keylen == 256):
			binBytes_key_size = 32
		elif (self.keylen == 192):
			binBytes_key_size = 24
		else:
			binBytes_key_size = 16

		if self.session_flag == False:
			self.keyHex = crypt.genRandomBytesENC(binBytes_key_size)
		crypt.SetEncodedKey(self.keyHex,"hex")
		self.setup = True

	def enc_str(self, val):
		global crypt
		encStr = crypt.encryptStringENC(val)
		print "encrypted"
		print encStr
		return encStr

	def set_sessionkey(self,key):
		self.keyHex = key
		self.session_flag = True
		return True

	def dec_str(self, val):
		global crypt
		try:
			decStr = crypt.decryptStringENC(val)
		except:
			print "decrypt error"
		print "decrypted"
		print decStr
		return decStr

	def enc_file(self, orig, new):
		global crypt
		# success = crypt.CkEncryptFile("kali_linux.jpg","kali_linux.dat")
		success = crypt.CkEncryptFile(orig,new)
		if (success != True):
			print(crypt.lastErrorText())
			sys.exit()

	def dec_file(self, orig, new):
		global crypt
		success = crypt.CkDecryptFile(orig,new)
		if (success != True):
			print(crypt.lastErrorText())
			sys.exit()

	def compress_zip(self, filename, zip_name):
		success = zip.NewZip(zip_name)
		if (success != True):
			print(zip.lastErrorText())
			sys.exit()


		saveExtraPath = False
		success = zip.AppendOneFileOrDir(filename,saveExtraPath)
		if (success != True):
			print(zip.lastErrorText())
			sys.exit()

		success = zip.WriteZipAndClose()
		if (success != True):
			print(zip.lastErrorText())
			sys.exit()

		#  A .zip containing "HelloWorld123.txt" with no path information has been created.
		print("Zip Created!")    

	def decompress_zip(self,filename,unzipDir ):

		success = zip.OpenZip("test.zip")
		if (success != True):
			print(zip.lastErrorText())
			sys.exit()

		#  Get the number of files and directories in the .zip
		n = zip.get_NumEntries()
		print(str(n))

		for i in range(0,n):
			entry = zip.GetEntryByIndex(i)
	    	if (entry.get_IsDirectory() == False):
	        #  (the filename may include a path)
	        	print(entry.fileName())

	        #  Your application may choose to unzip this entry
	        #  based on the filename.
	        #  If the entry should be unzipped, then call Extract(unzipDir)	
	        success = entry.Extract(unzipDir)	
	        if (success != True):
	        	print(entry.lastErrorText())
	        	sys.exit()
	
	def get_key(self):
		if self.setup == True:
			return self.keyHex

	def get_mode(self):
		if self.setup == True:
			return self.mode	
				
	def get_keylen(self):
		if self.setup == True:
			return self.keylen

	def get_iv(self):
		if self.setup == True:
			return self.ivHex	

	def setIv(self, iv):
		ivHex = iv
		return True	