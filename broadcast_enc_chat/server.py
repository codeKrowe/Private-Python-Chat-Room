import asyncore
import collections
import logging
import socket
import chilkat
import struct 
import pickle
from time import sleep
MAX_MESSAGE_LENGTH = 1024
from AES_Class import *


hashcrypt = chilkat.CkCrypt2()
success = hashcrypt.UnlockComponent("Anything for 30-day trial.")
if (success != True):
    print(hashcrypt.lastErrorText())
    sys.exit()

# setting encoding mode for hashing algorithm 
hashcrypt.put_EncodingMode("hex")
hashcrypt.put_HashAlgorithm("md5")

dhBob = chilkat.CkDh()


success = dhBob.UnlockComponent("Anything for 30-day trial")
if (success != True):
    print(dhBob.lastErrorText())
    sys.exit()

# setup data for Diffie Hellman Key exchange
dhBob.UseKnownPrime(2)
p = dhBob.p()
g = dhBob.get_G()
eBob = dhBob.createE(256)
sharedKey = None
sessionkey = None
aesObj = AESClass("cbc",128,0,"hex")
inital_setup = "0"


class RemoteClient(asyncore.dispatcher):
    #Wraps a remote client socket
    def __init__(self, host, socket, address):
        asyncore.dispatcher.__init__(self, socket)
        self.host = host
        #collections.deque()
        #list-like container with fast appends and pops on either end
        self.outbox = collections.deque()

    def say(self, message):
        # appending message to the message queue
        self.outbox.append(message)

    def handle_read(self):
    	# read messages
        client_message = self.recv(MAX_MESSAGE_LENGTH)
        self.host.broadcast(client_message)

    def handle_write(self):
        if not self.outbox:
            return
        message = self.outbox.popleft()
        if len(message) > MAX_MESSAGE_LENGTH:
            raise ValueError('Message too long')
        self.send(message)


class Host(asyncore.dispatcher):
    log = logging.getLogger('Host')
    # asyncore dispatcher listening on localhost random socket
    def __init__(self, address=('localhost', 0)):
        asyncore.dispatcher.__init__(self)
        #bind to socket and listen 
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind(address)
        #print ("Address Server", address)
        self.listen(1)
        #store connected clients in array
        self.remote_clients = []

    def handle_error(self):
        raise

    def auth(self, client, address):
        global dhBob
        global p
        global g
        global eBob
        global sharedKey
        global sessionkey
        global inital_setup

        #send if the this setup has happened from a cleint already
        client.send(inital_setup)

        logging.info('Setup for client', address)


        # serialise objects with dictionary and "pickle"
        dictobj = {'p' : p, 'g' : g,"e" : eBob}
        pickdump = pickle.dumps(dictobj)
        print "size of pickle",sys.getsizeof(pickdump)
        client.send(pickdump)



        ## without this loop will get a resource unavail
        # error crashing the server ---- wait till recieve
        loop = True
        while loop:
            try:
                eAlice = client.recv(297)
                loop = False
            except:
            	"do nothing"
        print "Finished waiting"

        # using the information from Client
        kBob = dhBob.findK(eAlice)  
        sharedKey = kBob
        print "Shared Secret information"
        print(address, "shared secret (should be equal to Bob's)")
        print sharedKey

        # Use a hashing algorithm to generate 128 bit Session key
        sessionkey = hashcrypt.hashStringENC(kBob)

        print ""
        print "-----------sessionkey-------------"
        print sessionkey

        # Use custom AES object 
        # if the setup hasent happen already then
        # use the current new session key
        # and setup the AES object
        global aesObj
        if inital_setup == "0":
            # iv is MD5 hash of session key
            iv = crypt.hashStringENC(sessionkey)
            aesObj.setIv(iv)
            aesObj.set_sessionkey(sessionkey)
            aesObj.setupAES()

        print "---------AES KEY------------------" 
        temp = str(aesObj.get_key())
        print temp
        # if the this is a new cleint then send
        # the Session key
        # this is done with no encyption!!!!!!!!!!!!!!
        # just for testing - broadcast chat room
        if inital_setup == "1":
            client.send(temp)

        # first time setup
        inital_setup = "1"
        return True






    def handle_accept(self):
        # accept on the Asyncore handler
        # getting the remote address
        # and assigning a socket

        socket, addr = self.accept()
        if (socket == None):
            return # For the remote client.
        self.log.info('Accepted client at %s', addr)

        # If setup protocol returns true 
        # add remote socket to room
        # at the moment return True Regardless
        stat = self.auth(socket, addr)
        if stat == True:
            self.remote_clients.append(RemoteClient(self, socket, addr))

    def handle_read(self):
        self.log.info('Received message: %s', self.read())

    def broadcast(self, message):
    	# broadcasts messages to all sockets that are connected
    	# to the server - stored in (remote_cleints)
    	# doesnt currently filter the origin socket
    	# can be done when messages will be "pickled" dictionaries
    	# can set the origin address as lookup + other data
    	# hashes + nounces and the like
        self.log.info('Broadcasting message: %s', message)
        enc_message = aesObj.enc_str(message)
        print "Broadcasting encypted mess :", enc_message
        for remote_client in self.remote_clients:
            remote_client.say(enc_message)


if __name__ == '__main__':
    host = Host()
    print ("server address", host.getsockname())
    print "started"
    asyncore.loop()