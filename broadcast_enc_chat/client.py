from socket import *
from threading import Thread
import sys
import chilkat
import struct
import pickle
from time import sleep
from AES_Class import *

if (len(sys.argv) < 2):
    print 'Usage: python client.py <port>\n'
    sys.exit(0)
else:
    PORT = int(sys.argv[1])



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

# initial setup
# temporary measure to see if 
# a client has already been setup,
# current code generates new keys still
# but this hacky approah makes allows
# poor sharing of server master Session key
# Created with cleint no. (1)
inital_setup = client.recv(8)
print "inital_setup has occured before = ", inital_setup

# Recieved "Pickled" object on socket - ie serialised to String
# Deserialize Data recieved back into
# Python dictionary then remove the objects
pickobject = client.recv(BUFSIZE)
dictObj = pickle.loads(pickobject)
p = dictObj["p"]
g = dictObj["g"]
g = int(g)
eBob = dictObj["e"]

# use the information for Diffie-hellman cleint side
success = dhAlice.SetPG(p,g)
if (success != True):
    print("P is not a safe prime")
    sys.exit()
eAlice = dhAlice.createE(256)

print "size of eAlice", sys.getsizeof(eAlice)
client.send(eAlice)

#Alice's shared secret 
kAlice = dhAlice.findK(eBob)
print("Alice's shared secret (should be equal to Bob's)")
print(kAlice)


serverKey = None
if inital_setup == "1":
  print "attempt to recv server key"
  serverKey = client.recv(1024)
  print "serverSessionKey", serverKey

sessionkey = hashcrypt.hashStringENC(kAlice)
print "SessionKey", sessionkey


a = AESClass("cbc",128,0,"hex")

#################
# For the moment there is waste execurion and setup
# of a new key
# just doing it this way for testing a breivity 
# when attempting to connect from multiple clients
#

# print "serverKey testing"
# print type(serverKey)
# print len(str(serverKey))
# depending on if this is a first setup or not
# use the key (ie same key)for AES ---- one that is sent in open
# would have to use a digital envelope of the like to achieve this properly
if inital_setup == "0":
  a.set_sessionkey(sessionkey)
else:
  print "setting serverSessionKey"
  a.set_sessionkey(serverKey)


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
        print "Decyping:", data

Thread(target=recv).start()

while True:
    data = raw_input('> ')
    if not data: break
    client.send(data)



print "Client Shutdown"
socket.Close(20000)






