from AES_Class import *

print "Starting test 128\n"

a = AESClass("cbc",128,0,"hex")
a.setupAES()
testenc = a.enc_str("Greetings and Salutations!!")

print "Testing Decyption"
testdec = a.dec_str(testenc)

print "\n256"
b = AESClass("cbc",256,0,"hex")
b.setupAES()
testenc = b.enc_str("Greetings and Salutations!!")

print "Testing Decyption"
testdec = b.dec_str(testenc)


print "testing compression"
b.compress_zip("aes_test.py","test.zip")


#b.decompress_zip("test.zip","/Users/jonathan/Desktop/new")

print "Return Sym Key test"
print b.get_key()