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
from RSAClass import *
import random

rsa = RSAClass()

privkey = chilkat.CkPrivateKey()
privkey.LoadXmlFile("Serverprivatekey.xml")
ServerPrivateKey = privkey.getXml()

pubKey = chilkat.CkPublicKey()
pubKey.LoadXmlFile("Serverpublickey.xml")
ServerPublicKey = pubKey.getXml()


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
CLIENT_ID_STORE ={}

class RemoteClient(asyncore.dispatcher):
    #Wraps a remote client socket
    def __init__(self, host, socket, address):
        asyncore.dispatcher.__init__(self, socket)
        self.host = host
        self.address = address
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


     #Called when the asynchronous loop detects that a writable socket can be written. 
    def handle_write(self):
        # if nothing in outbox return
        if not self.outbox:
            return
        # POP a message from the outbox
        message = self.outbox.popleft()
        # message lenght has be a certain size
        # for the recieving sp
        if len(message) > MAX_MESSAGE_LENGTH:
            raise ValueError('Message too long')
        self.send(message)

    def get_address(self):
        return self.address

class Chatroom(asyncore.dispatcher):
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

    def auth(self, client, address, cpub):
        global dhBob
        global p
        global g
        global eBob
        global sharedKey
        global sessionkey
        global inital_setup
        global aesObj
        global rsa
        #send if  this setup has happened from a client already
        #because session key is already generated then
        client.send(inital_setup)
        if inital_setup == "1":
            print 'Setup for client', address
            print ">>>>>>>>>>>>>>>>>>>>>>>Sending Session Key>>>>>>>>>>>>>>>>>"
            print ">>>>>>>>>>>>>>>>>>>>>>>Digital Envelope>>>>>>>>>>>>>>>>>>>>>\n"
            sk = rsa.encrypt_text(aesObj.get_key(), cpub)
            client.send(sk)            
        else:      
            print 'Setup for first client', address
            # serialise objects with dictionary and "pickle"
            dictobj = {'p' : p, 'g' : g,"e" : eBob}
            pickdump = pickle.dumps(dictobj)
            # print "size of pickle",sys.getsizeof(pickdump), len(str(pickdump))
            client.send(pickdump)
            ## without this loop will get a resource unavail
            # error crashing the server ---- wait till recieve
            loop = True
            while loop:
                try:
                    eAlice = client.recv(260)
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
            print "-----------Sessionkey---------------"
            print "------------generated---------------"
            print sessionkey

            print "-----------------------------------"
            # Use custom AES object 
            # if the setup hasent happen already then
            # use the current new session key
            # and setup the AES object

            if inital_setup == "0":
                # iv is MD5 hash of session key
                iv = crypt.hashStringENC(sessionkey)
                aesObj.setIv(iv)
                aesObj.set_sessionkey(sessionkey)
                aesObj.setupAES()

            # if the this is a new cleint then send
            # the Session key
            # this is done with no encyption!!!!!!!!!!!!!!
            # just for testing - broadcast chat room


            # first time setup
            inital_setup = "1"
        return True


    def handle_accept(self):
        global ServerPrivateKey
        global rsa
        global CLIENT_ID_STORE
        # accept on the Asyncore handler
        # getting the remote address
        # and assigning a socket

        # read event handler on listening socket
        socket, addr = self.accept()
        if (socket == None):
            return # For the remote client.
        print 'Accepted client at %s', addr

        sleep(0.1)
        ID = socket.recv(1024)
        client_ID = rsa.decrypt_text(ID, ServerPrivateKey)
        orginal_hash = client_ID[-32:]
        client_ID = client_ID[:-32]

        print "***********************"
        print "***********************"

        dictObj = pickle.loads(client_ID)       
        cnonce = dictObj["nonce"]
        testhash  = hashcrypt.hashStringENC(str(cnonce))

        if orginal_hash == testhash:
            print "\nNONCE Integrity Validated\n"

        cpub = dictObj["public_key"]
        CLIENT_ID_STORE[addr] = cnonce
        random.seed()
        snonce = random.randrange(10000000000000,99999999999999)


        responce =  {"snonce":snonce, "cnonce": cnonce}
        responce = pickle.dumps(responce)
        h = hashcrypt.hashStringENC(str(responce))
        responce = responce + h
        responce = rsa.encrypt_text(responce, cpub)
        socket.send(responce)




        # Using a comnination of nested lists and a dictionary to store nonce data
        client_id_list =[ [cpub, "cpub"], [cnonce, "cnonce"], [snonce, "snonce"], ]
        CLIENT_ID_STORE[addr] = client_id_list



        # If setup protocol returns true 
        # add remote socket to room
        # at the moment return True Regardless
        stat = self.auth(socket, addr, cpub)
        if stat == True:
            self.remote_clients.append(RemoteClient(self, socket, addr))

    #Handle Read
    #Called when the asynchronous loop detects that a read 
    #call on the channels socket will succeed.
    def handle_read(self):
        self.read()

    def broadcast(self, message):
    	# broadcasts messages to all sockets that are connected
    	# to the server - stored in (remote_cleints)
    	# doesnt currently filter the origin socket
    	# can be done when messages will be "pickled" dictionaries
    	# can set the origin address as lookup + other data
    	# hashes + nounces and the like
        #dec_message = aesObj.dec_str()
        try:
            orginal_hash = message[-32:]
            # remove the original serialized object from the concatentated
            # hash
            message = message[:-32]
            #hash the extracted object
            test_hash = hashcrypt.hashStringENC(message)
            # de-serialize and extract data
            dictObj = pickle.loads(message)
            src_port = dictObj["src_port"] 
            src_data = dictObj["data"] 
            # Check the Integrity of recived data vrs the new hash of extraced obj
            if test_hash == orginal_hash:
                "Integrity Verified"
            else:
                print "Integrity fail"
            # test Decyption --- (not nessesary)
            dec_message_test = aesObj.dec_str(src_data)
            print "Test Decypt :", dec_message_test

            print "Broadcasting encypted mess :", src_data , " from 127.0.0.1:", src_port
            for remote_client in self.remote_clients:
                # dont broadcast the message back to source socket
                if not (remote_client.get_address()[1] == src_port):
                    remote_client.say(src_data)
        except Exception, e:
            print "er Broadcasting"
            print str(e)  

if __name__ == '__main__':
    chatroom = Chatroom()
    print ("server address", chatroom.getsockname())
    print "started"
    # polls "channels" only stops only when all these have been closed
    asyncore.loop()