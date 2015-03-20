#!/usr/bin/python
import sys
import chilkat
import os, binascii

#AES Class using the Chilkat Library to setup Asynchronous Encryption
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
		self.crypt = chilkat.CkCrypt2()
		self.zip = chilkat.CkZip()
		self.UnlockComponents()

	#redundant and not used - remove
	def getCrypt(self):
		return self.crypt

	def UnlockComponents(self):
		success = self.crypt.UnlockComponent("T12302015Crypt_sHyDCAFgIR1v")
		if (success != True):
			print(self.crypt.lastErrorText())
			sys.exit()

		success = self.zip.UnlockComponent("T12302015ZIP_uBPbJkarIRCd")
		if (success != True):
		    print(self.zip.lastErrorText())
		    sys.exit()

    #setup AES with mode, key size and padding, set an IV which will get overwritten by clients
    # when the generate the same iv
	def setupAES(self):
		self.crypt.put_CryptAlgorithm("aes")
		self.crypt.put_CipherMode(self.mode)
		self.crypt.put_PaddingScheme(self.padding)
		if self.mode == "cbc":
			#ivHex = binascii.b2a_hex(os.urandom(16))
			# self.ivHex = self.crypt.genRandomBytesENC(16)
			#self.ivHex = "6JDLMMXKvbavsnpzwDhquA=="
			self.crypt.SetEncodedIV(self.ivHex,"hex")

		if (self.keylen == 256):
			binBytes_key_size = 32
		elif (self.keylen == 192):
			binBytes_key_size = 24
		else:
			binBytes_key_size = 16

		if self.session_flag == False:
			self.keyHex = self.crypt.genRandomBytesENC(binBytes_key_size)
		self.crypt.SetEncodedKey(self.keyHex,"hex")
		self.setup = True

	#Methods to encrypt and decrypt and (access and mutator methods)
	def enc_str(self, val):
		encStr = self.crypt.encryptStringENC(val)
		return encStr

	def set_sessionkey(self,key):
		self.keyHex = key
		self.session_flag = True
		return True

	def dec_str(self, val):
		try:
			decStr = self.crypt.decryptStringENC(val)
		except:
			print "decrypt error"
		return decStr

	def enc_file(self, orig, new):
		# success = self.crypt.CkEncryptFile("kali_linux.jpg","kali_linux.dat")
		success = self.crypt.CkEncryptFile(orig,new)
		if (success != True):
			print(self.crypt.lastErrorText())
			sys.exit()

	def dec_file(self, orig, new):
		success = self.crypt.CkDecryptFile(orig,new)
		if (success != True):
			print(self.crypt.lastErrorText())
			sys.exit()

	#compress and file
	def compress_zip(self, filename, zip_name):
		success = self.zip.NewZip(zip_name)
		if (success != True):
			print(self.zip.lastErrorText())
			sys.exit()


		saveExtraPath = False
		success = self.zip.AppendOneFileOrDir(filename,saveExtraPath)
		if (success != True):
			print(self.zip.lastErrorText())
			sys.exit()

		success = self.zip.WriteZipAndClose()
		if (success != True):
			print(self.zip.lastErrorText())
			sys.exit()

		#  A .zip containing "HelloWorld123.txt" with no path information has been created.
		print("Zip Created!")

	def decompress_zip(self,filename,unzipDir ):

		success = self.zip.OpenZip("test.zip")
		if (success != True):
			print(self.zip.lastErrorText())
			sys.exit()

		#  Get the number of files and directories in the .zip
		n = self.zip.get_NumEntries()
		print(str(n))

		for i in range(0,n):
			entry = self.zip.GetEntryByIndex(i)
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
		self.ivHex = iv
		return True
