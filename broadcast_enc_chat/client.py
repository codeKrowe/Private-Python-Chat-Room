from socket import *
from threading import Thread
import sys
import chilkat
import struct
import pickle
from time import sleep
from AES_Class import *
from RSAClass import *
import random
random.seed()

if (len(sys.argv) < 2):
    print 'Usage: python client.py <port>\n'
    sys.exit(0)
else:
    PORT = int(sys.argv[1])

rsa = RSAClass()
public_key, private_key = rsa.generate_keys()

pubKey = chilkat.CkPublicKey()
pubKey.LoadXmlFile("Serverpublickey.xml")
ServerPublicKey = pubKey.getXml()

privkey = chilkat.CkPrivateKey()
privkey.LoadXmlFile("Serverprivatekey.xml")
ServerPrivateKey = privkey.getXml()

md5_crypt = chilkat.CkCrypt2()
#  Any string argument automatically begins the 30-day trial.
success = md5_crypt.UnlockComponent("30-day trial")
if (success != True):
    print(md4_crypt.lastErrorText())
    sys.exit()
md5_crypt.put_EncodingMode("hex")
#  Set the hash algorithm:
md5_crypt.put_HashAlgorithm("md5")

hashcrypt = chilkat.CkCrypt2()
success = hashcrypt.UnlockComponent("Anything for 30-day trial.")
if (success != True):
    print(hashcrypt.lastErrorText())
    sys.exit()
hashcrypt.put_EncodingMode("hex")
hashcrypt.put_HashAlgorithm("md5")

dhAlice = chilkat.CkDh()
success = dhAlice.UnlockComponent("Anything for 30-day trial")
if (success != True):
    print(dhAlice.lastErrorText())
    sys.exit()


HOST = 'localhost'
BUFSIZE = 1024
ADDR = (HOST, PORT)
client = socket(AF_INET, SOCK_STREAM)
client.connect(ADDR)
a = AESClass("cbc",128,0,"hex")

# source port of Client
client_src_port = client.getsockname()[1]
nonce = random.randrange(10000000000000,99999999999999)
# print "nonce", nonce

firstID = {'src_port' : client_src_port, 'nonce' : nonce, 'public_key': public_key}
pid = pickle.dumps(firstID)

# print "***********************"
# print pid
# print "***********************"

hashStr = md5_crypt.hashStringENC(str(nonce))

# print "size of the hash" , len(hashStr), hashStr
finalID = pid + hashStr

encyptedpayload = rsa.encrypt_text(finalID, ServerPublicKey)
client.send(encyptedpayload)

# print "lenthgs of payload" , len(encyptedpayload), "encyptedpayload"
# # print encyptedpayload

# print "decrypt_text"
# print rsa.decrypt_text(encyptedpayload, ServerPrivateKey)
# initial setup
# temporary measure to see if 
# a client has already been setup,
# current code generates new keys still
# but this hacky approah makes allows
# poor sharing of server master Session key
# Created with cleint no. (1)

# have to have exact bytes sometimes (sync issues)
inital_setup = client.recv(1)
print "inital_setup has occured before = ", inital_setup
serverKey = None
if inital_setup == "1":
  print "attempt to recv server key"
  serverKey = client.recv(32)
  print "serverSessionKey", serverKey
  print "setting serverSessionKey"
  a.set_sessionkey(serverKey)



# Recieved "Pickled" object on socket - ie serialised to String
# Deserialize Data recieved back into
# Python dictionary then remove the objects
else:
	try:
		pickobject = client.recv(570)
		dictObj = pickle.loads(pickobject)
		p = dictObj["p"]
		g = dictObj["g"]
		g = int(g)
		eBob = dictObj["e"]
	except:
		print "fails to recieve Diffie-hellman data"
		sys.exit(0)

	# use the information for Diffie-hellman cleint side
	success = dhAlice.SetPG(p,g)
	if (success != True):
	    print("P is not a safe prime")
	    sys.exit()
	eAlice = dhAlice.createE(256)

	# print "size of eAlice", len(str(eAlice))
	client.send(eAlice)

	#Alice's shared secret 
	kAlice = dhAlice.findK(eBob)
	print("Alice's shared secret (should be equal to Bob's)")
	print(kAlice)

	sessionkey = hashcrypt.hashStringENC(kAlice)
	print "SessionKey", sessionkey
	a.set_sessionkey(sessionkey)
	iv = crypt.hashStringENC(sessionkey)
	a.setIv(iv)


# print "serverKey testing"
# print type(serverKey)
# print len(str(serverKey))
# depending on if this is a first setup or not
# use the key (ie same key)for AES ---- one that is sent in open
# would have to use a digital envelope of the like to achieve this properly

# setup this sides AES object
a.setupAES()

print "-------------AES KEY-----------------"
print a.get_key()




def recv():
    while True:
        data = client.recv(1024)
        if not data: sys.exit(0)
        print "***************************************"
        print "Recv Encypted Broadcast:", data
        data = a.dec_str(data)
        type(data)
        print "Decrypting:", data

Thread(target=recv).start()



while True:
	try:
    # take input from command terminal   -- change to GUI
	    data = raw_input('>> ')
	    if not data: print '>> '
	    data = a.enc_str(data)
	    dictobj = {'src_port' : client_src_port, 'data' : data}
	    pickdump = pickle.dumps(dictobj)
	    # print "size of pickle",sys.getsizeof(pickdump)

	    # concatente serialized message with hash
	    hashStr = md5_crypt.hashStringENC(pickdump)
	    finalmessage = pickdump + hashStr
	    if len(finalmessage) > 1024:
	    	print "message to large"
	    else:
	    	client.send(finalmessage)
	except:
		print "send error"


print "Client Shutdown"
client.close()
sys.exit()





