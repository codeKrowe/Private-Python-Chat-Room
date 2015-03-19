#!/usr/bin/python
import asyncore
import collections
import socket
import chilkat
import struct
import pickle
from time import sleep
MAX = 1024
from AES_Class import *
from RSAClass import *
import random

#version 2.0

class RemoteClient(asyncore.dispatcher):
    #Wrapper for client sockets
    def __init__(self, host, socket, address):
        asyncore.dispatcher.__init__(self, socket)
        self.host = host
        self.address = address
        #list-like container with fast appends and pops on either end
        self.outQ = collections.deque()


    #overRidden Handlers for Ayncore 
    #not working as indented (still holds on the port on exit or crash)
    def handle_close(self):
        self.close()
    def handle_expt(self):
        self.close()

    #Append messages to a Python Dictionary Q
    def tx(self, message):
        # appending message to the message queue
        self.outQ.append(message)

    def handle_read(self):
    	# read messages
        client_message = self.recv(MAX)
        self.host.broadcast(client_message)

     #Called when the asynchronous loop detects that a writable socket can be written.
    def handle_write(self):
        # if nothing in outQ return
        if not self.outQ:
            return
        # POP a message from the outbox
        message = self.outQ.popleft()
        # message lenght has be a certain size
        # for the recieving sp
        if len(message) > MAX:
            raise ValueError('Message too long')
        self.send(message)

    #get the address of the client socket in this WRAPPER
    def get_address(self):
        return self.address

    # this fixes the CPU 100% utilisation problem
    # caused by the ayncore polling for avalable data to transfer
    # returning always true (as will be the case when this is not overridden)
    # will cause 100% Cpu utilisiation
    def writable(self):
        return bool(self.outQ)        

class Chatroom(asyncore.dispatcher):
        #asyncore dispatcher listening on localhost random socket
    def __init__(self, address=('localhost', 0)):
        asyncore.dispatcher.__init__(self)
        privkey = chilkat.CkPrivateKey()
        privkey.LoadXmlFile("Serverprivatekey.xml")
        self.ServerPrivateKey = privkey.getXml()
        self.rsa = RSAClass()

        #Chilkat object forCreating hashes
        self.hashcrypt = chilkat.CkCrypt2()
        success = self.hashcrypt.UnlockComponent("Anything for 30-day trial.")
        if (success != True):
            print(hself.ashcrypt.lastErrorText())
            sys.exit()
        # setting encoding mode for hashing algorithm
        self.hashcrypt.put_EncodingMode("hex")
        self.hashcrypt.put_HashAlgorithm("md5")

        # setup data for Diffie Hellman Key exchange
        self.dhBob = chilkat.CkDh()
        success = self.dhBob.UnlockComponent("Anything for 30-day trial")
        if (success != True):
            print(self.dhBob.lastErrorText())
            sys.exit()
        self.dhBob.UseKnownPrime(2)
        self.p = self.dhBob.p()
        self.g = self.dhBob.get_G()
        self.eBob = self.dhBob.createE(256)


        #initially set the the AES object with cipher block chaining 128bit
        self.aesObj = AESClass("cbc",128,0,"hex")
        self.inital_setup = "0"
        #store client IDS and nonces
        # nonces used in replay protection
        self.CLIENT_ID_STORE ={}
        self.CLIENT_ID = []

        #placeholders fo the keys (session and shared the same really)
        self.sharedKey = None
        self.sessionkey = None

        # self.set_reuse_addr()
        #bind to socket and listen
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind(address)
        #print ("Address Server", address)
        # accept with no backlog
        # syncore dispather handles it all
        self.listen(1)
        #store connected clients in LIST
        self.remote_clients = []

    #Authentication Protocol Steps occur here
    #Diffy hellaman, key exchange 
    #digitial signing of messages
    #hashes included in messages 
    #confidentialy provided by the clients public key that was 
    #transmitted to the server on its initial connection in the accept handler 
    #when the challange responce occured
    #the nonces, socket, keys, source address and public keys are passed to this method
    def auth(self, client, address, cpub, snonce, cnonce):
        #send if  this setup has happened already with an initial cleint
        #because the session key was already generated
        #doing otherwise would create different keys!

        #send the flag to the connected client 
        #so they can comply with protocol
        client.send(self.inital_setup)
        #if this has already happened then send the client
        # the symmetric key in a digital envelope using the Public key they submitted 
        if self.inital_setup == "1":
            print 'Setup for new client', address
            print ">>>>>>>>>>>>>>>>>>>>>>>Sending Session Key>>>>>>>>>>>>>>>>>"
            print ">>>>>>>>>>>>>>>>>>>>>>>Digital Envelope>>>>>>>>>>>>>>>>>>>>>\n"
            #create a dictionary of data
            dictobj = {'aes_key':self.aesObj.get_key(),"snonce":snonce, "cnonce":cnonce}
            #serialise it
            pickledump = pickle.dumps(dictobj)
            #!!!!!HASH!!!!! it
            h = self.hashcrypt.hashStringENC(pickledump)
            #concatentate the hash to the serialised data
            pickledump = pickledump + h
            #encypt with the server !!!!!PRIVATE KEY!! for !!!!DIGTIAL SIGNATURE!!
            sk = self.rsa.encrypt_with_private(pickledump, self.ServerPrivateKey)
            #encypt with the clients Public key for !!!!!!CONFIDENTIALITY!!!!!!!!
            sk = self.rsa.encrypt_text(sk, cpub)
            # send it back to the client
            client.send(sk)
        else:
            print 'Setup for first client', address
            # serialise objects with dictionary and "pickle"
            #these are the data requirement for the client to complete the 
            # !!!!!-----diffie hellman-----!!!! mathematical process
            dictobj = {'p' : self.p, 'g' : self.g,"e" : self.eBob, "snonce":snonce, "cnonce":cnonce}
            pickdump = pickle.dumps(dictobj)
            #hash serialised data, concatentate and encypt with the Private key Server for
            #!!!!!Digital Signature!!!!
            h = self.hashcrypt.hashStringENC(pickdump)
            pickdump = pickdump + h
            pickdump = self.rsa.encrypt_with_private(pickdump, self.ServerPrivateKey)

            #Have the split the data and encypt each half seprately with the
            #clients public key 
            # Data was exceeding the MODULUS Size used for the RSA Object
            pk1 = self.rsa.encrypt_text(pickdump[-768:], cpub)
            pk2 = self.rsa.encrypt_text(pickdump[:-768], cpub)
            #Send the FRAGMENTED packet to the client for reassembly
            client.send(pk1)
            client.send(pk2)

            ## without this loop will get a resource unavail
            # error crashing the server ---- wait till recieve
            loop = True
            while loop:
                try:
                    #recieve the cleints "shared value", generated for the Public
                    #diffie hellman components sent to from the server
                    eAlice = client.recv(768)
                    try:
                        #decypt the message with the servers Private key
                        #Confidentialty 
                        #(unessessary!!!!!!!! as this is public data ---  but added anyway)
                        eAlice = self.rsa.decrypt_text(eAlice, self.ServerPrivateKey)
                    except:
                        "nothinf"
                    loop = False
                except:
                	"do nothing"

            # using the information from Client
            kBob = self.dhBob.findK(eAlice)

            #generate the MUTUALLY GENERATED SHARED SECRET

            self.sharedKey = kBob
            print "Shared Secret information"
            print(address, "shared secret (should be equal to Bob's)")
            print self.sharedKey

            # Use a hashing algorithm to generate 128 bit Session key
            self.sessionkey = self.hashcrypt.hashStringENC(kBob)

            print ""   #Console Outputs (testing)
            print "-----------Sessionkey---------------"
            print "------------generated---------------"
            print self.sessionkey
            print "-----------------------------------"
            # Use custom AES object
            # if the setup hasent happen already then
            # use the current new session key
            # and setup the AES object

            if self.inital_setup == "0":
                # iv is MD5 hash of session key
                iv = self.aesObj.getCrypt().hashStringENC(self.sessionkey)
                self.aesObj.setIv(iv)
                self.aesObj.set_sessionkey(self.sessionkey)
                self.aesObj.setupAES()

            # first time setup has occured 
            self.inital_setup = "1"
        return True

    # socket accept event handler of anyncore dispatcher
    # used to accept new Clients connections in a Syncronous manner then after 
    # challage responce and protol wrap them in a approximation of Aysyncronous behavior
    # with Aysncore Dispather which will poll each at timed intervals
    def handle_accept(self):

        # Accept event handler on listening socket
        # Accept a new client then start the Protocol Process
        socket, addr = self.accept()
        if (socket == None):
            return
        print 'Accepted client from port ', addr

        sleep(0.1)

        # remove the client identifer
        ID = socket.recv(1024)
        #decypt with the server Privatekey
        client_ID = self.rsa.decrypt_text(ID, self.ServerPrivateKey)
        #extract and generate hash
        orginal_hash = client_ID[-32:]
        #de-concatenate the cleints ID
        client_ID = client_ID[:-32]

        print "***********************"
        print "***********************"

        dictObj = pickle.loads(client_ID)
        # clients nonce value
        cnonce = dictObj["nonce"]
        #Generate a comparision HASH value
        testhash  = self.hashcrypt.hashStringENC(str(cnonce))

        ###Should disconnect them here if this Chechk fails
        if orginal_hash == testhash:
            print "\nNONCE Integrity Validated\n"

        # exttract the Clients RSA public key
        cpub = dictObj["public_key"]
        #store their  nonce
        self.CLIENT_ID_STORE[addr] = cnonce

        #SERVER generate a random nonce 
        random.seed()
        snonce = random.randrange(10000000000000,99999999999999)

        #respnce the the client with clients nonce and Servers nonce
        responce =  {"snonce":snonce, "cnonce": cnonce}
        #serialize the dictionary
        responce = pickle.dumps(responce)
        #hash it for INTEGRITY
        h = self.hashcrypt.hashStringENC(str(responce))
        #concatenate the hash to serialized data
        responce = responce + h
        # encypt with the Servers Private key for DIGITAL SIGNATURE
        responce = self.rsa.encrypt_with_private(responce, self.ServerPrivateKey)
        # Encrypt with the clients public key for Confidentiality
        responce = self.rsa.encrypt_text(responce, cpub)
        #send message
        socket.send(responce)


        #Replay Protection (If a client nonce has occured Before then dont add them 
        # to the Ayncore Wrapper Chat Room)
        # This would have to be save to a local Database to be really usefull
        # as all nonces as lost once the server is down
        allowed = True
        if self.inital_setup == "1":
            print "previous nonces"
            for c in list(self.CLIENT_ID):
                print c[1]
                if c[1] == cnonce and snonce == c[2]:
                    print "AUTH already occured for ", c[0]
                    allowed = False

        if allowed == True:
            client_id_list =[ (cpub), (cnonce), (snonce)]
            self.CLIENT_ID.append(client_id_list)
            # If setup protocol returns true
            # add remote socket to room
            # at the moment return True Regardless
            stat = self.auth(socket, addr, cpub, snonce, cnonce)
            if stat == True:
                self.remote_clients.append(RemoteClient(self, socket, addr))

    #Handle Read
    #Called when the asynchronous loop detects that a read
    #call on the channels socket will succeed.
    def handle_read(self):
        self.read()

    def broadcast(self, message):

        # Weakness here as the only part of the payload encypted is the 
        # data string

    	# broadcasts messages to all sockets that are connected
    	# to the server - stored in (remote_cleints)
    	# filterS the origin socket of the message (does not return the message)
        try:
            orginal_hash = message[-32:]
            # remove the original serialized object from the concatentated
            # hash
            message = message[:-32]
            #hash the extracted object
            test_hash = self.hashcrypt.hashStringENC(message)
            # de-serialize and extract data
            dictObj = pickle.loads(message)

            #get the source port of the message
            src_port = dictObj["src_port"]
            #data
            src_data = dictObj["data"]
            #is this RSA or AES (only used in the PEER TO PEER message exchange)
            mode = dictObj["FTX_ENC"]

            # IF a <list> command (message) is sent then
            # send back a string of connected ports
            remoteConnectedClients = [] 
            if dictObj["list"] == True:
                connlist = "Conn_list "
                for remote_client in self.remote_clients:
                    if remote_client.get_address()[1] == src_port:
                        # ID this port as comming from the client that requested this LIST
                        connlist = connlist + " : " + str(remote_client.get_address()[1]) + " <-You "
                    else:
                        remoteConnectedClients.append(remote_client.get_address()[1])
                        connlist = connlist + " : " + str(remote_client.get_address()[1])
                connlist = self.aesObj.enc_str(connlist)      
                connlist = {"data" : connlist, "src_port": src_port, "FTX_ENC": mode, "remoteConnectedClients": remoteConnectedClients}
                connlist = pickle.dumps(connlist)
                
            packet = {"data" : src_data, "src_port": src_port, "FTX_ENC": mode, "remoteConnectedClients": None}
            src_data = pickle.dumps(packet)

            # Check the Integrity of recived data vrs the new hash of extraced obj
            # NOT OVERLY USEFUL WITH STRING MESSAGES
            if test_hash == orginal_hash:
                "Integrity Verified"
            else:
                print "Integrity fail"

            # test Decyption --- (not nessesary)
            test =  pickle.loads(src_data)
            dec_message_test = self.aesObj.dec_str(test["data"])
            print "Test Decypt :", dec_message_test

            #console message
            print "Broadcasting encypted mess :", test["data"] , " from 127.0.0.1:", src_port

            #loop through all the connected clients 
            for remote_client in self.remote_clients:
                # dont broadcast the message back to source socket
                if not (remote_client.get_address()[1] == src_port) and (dictObj["tx"] == False):
                    remote_client.send(src_data)
                # send back the LIST data to who requested it (connection list)
                if remote_client.get_address()[1] == src_port and dictObj["list"] == True:
                    remote_client.send(connlist)
                #START A PEER TO PEER FILE TRANSFER HANDSHAKE with a Destination Port
                #Choosen by the source client
                #this will create 2 new THREADS , with new SOCKETS, to send encyted files and strings
                #directly from cleint to cleint by passing the server
                if remote_client.get_address()[1] == int(dictObj["p2p_port"]) and dictObj["tx"] == True:
                    remote_client.send(src_data)
        except Exception, e:
            print "er Broadcasting"
            print str(e)

if __name__ == '__main__':
    #create a chatroom 
    chatroom = Chatroom()
    print ("server address", chatroom.getsockname())
    print "started"
    # polls "channels" only stops only when all these have been closed
    asyncore.loop(timeout=5.0)