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
    	# read messages from a client socket
        client_message = self.recv(MAX)
        #broadcast it or route it tho specific clients
        self.host.broadcast(client_message)

     #Called when the asynchronous loop detects that a writable socket can be written.
    def handle_write(self):
        # if nothing in outQ return
        if not self.outQ:
            return
        # POP a message from the out-box
        message = self.outQ.popleft()
        # message length has be a certain size
        # for the receiving 
        if len(message) > MAX:
            raise ValueError('Message too long')
        self.send(message)

    #get the address of the client socket in this WRAPPER
    def get_address(self):
        return self.address

    # this fixes the CPU 100% utilization problem
    # caused by the ayncore polling for available data to transfer
    # returning always true (as will be the case when this is not overridden)
    # will cause 100% CPU utilization
    def writable(self):
        return bool(self.outQ)        

class Chatroom(asyncore.dispatcher):
        #asyncore dispatcher listening on local-host random socket
    def __init__(self, address=('localhost', 0)):
        asyncore.dispatcher.__init__(self)
        #import the Servers Keys, Saved to XML in FileSystem
        privkey = chilkat.CkPrivateKey()
        privkey.LoadXmlFile("Serverprivatekey.xml")
        self.ServerPrivateKey = privkey.getXml()

        #create RSA object
        self.rsa = RSAClass()

        #Chilkat object forCreating hashes
        self.hashcrypt = chilkat.CkCrypt2()
        success = self.hashcrypt.UnlockComponent("T12302015Crypt_sHyDCAFgIR1v")
        if (success != True):
            print(hself.ashcrypt.lastErrorText())
            sys.exit()
        # setting encoding mode for hashing algorithm
        self.hashcrypt.put_EncodingMode("hex")
        self.hashcrypt.put_HashAlgorithm("md5")

        # setup data for Diffie Hellman Key exchange
        self.dhBob = chilkat.CkDh()
        success = self.dhBob.UnlockComponent("T12302015Diffie_eegQ20BTIR5q")
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
        # syncore dispatcher handles it all
        self.listen(1)
        #store connected clients in LIST
        self.remote_clients = []

    #Authentication Protocol Steps occur here
    #Diffy Hellman, key exchange 
    #digital signing of messages
    #hashes included in messages 
    #confidential provided by the clients public key that was 
    #transmitted to the server on its initial connection in the accept handler 
    #when the challenge response occurred
    #the nonces, socket, keys, source address and public keys are passed to this method
    def auth(self, client, address, cpub, snonce, cnonce):
        #send if  this setup has happened already with an initial client
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
            #serialize it
            pickledump = pickle.dumps(dictobj)
            #!!!!!HASH!!!!! it
            h = self.hashcrypt.hashStringENC(pickledump)
            #concatenate the hash to the serialized data
            pickledump = pickledump + h
            #encrypt with the server !!!!!PRIVATE KEY!! for !!!!DIGTIAL SIGNATURE!!
            sk = self.rsa.encrypt_with_private(pickledump, self.ServerPrivateKey)
            #encrypt with the clients Public key for !!!!!!CONFIDENTIALITY!!!!!!!!
            sk = self.rsa.encrypt_text(sk, cpub)
            # send it back to the client
            client.send(sk)
        else:
            print 'Setup for first client', address
            # serialize objects with dictionary and "pickle"
            #these are the data requirement for the client to complete the 
            # !!!!!-----diffie hellman-----!!!! mathematical process
            dictobj = {'p' : self.p, 'g' : self.g,"e" : self.eBob, "snonce":snonce, "cnonce":cnonce}
            pickdump = pickle.dumps(dictobj)
            #hash serialized data, concatenate and encrypt with the Private key Server for
            #!!!!!Digital Signature!!!!
            h = self.hashcrypt.hashStringENC(pickdump)
            pickdump = pickdump + h
            pickdump = self.rsa.encrypt_with_private(pickdump, self.ServerPrivateKey)

            #Have the split the data and encypt each half separately with the
            #clients public key 
            # Data was exceeding the MODULUS Size used for the RSA Object
            pk1 = self.rsa.encrypt_text(pickdump[-768:], cpub)
            pk2 = self.rsa.encrypt_text(pickdump[:-768], cpub)
            #Send the FRAGMENTED packet to the client for reassembly
            client.send(pk1)
            client.send(pk2)

            ## without this loop will get a resource unavailable
            # error crashing the server ---- wait till receive
            loop = True
            while loop:
                try:
                    #receive the clients "shared value", generated for the Public
                    #Diffie Hellman components sent to from the server
                    eAlice = client.recv(768)
                    try:
                        #decrypt the message with the servers Private key
                        #Confidentiality 
                        #(unnecessary!!!!!!!! as this is public data ---  but added anyway)
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
            print "-----------Session-key---------------"
            print "------------generated---------------"
            print self.sessionkey
            print "-----------------------------------"
            # Use custom AES object
            # if the setup hes not happen already then
            # use the current new session key
            # and setup the AES object

            if self.inital_setup == "0":
                # iv is MD5 hash of session key
                iv = self.aesObj.getCrypt().hashStringENC(self.sessionkey)
                self.aesObj.setIv(iv)
                self.aesObj.set_sessionkey(self.sessionkey)
                self.aesObj.setupAES()

            # first time setup has occurred 
            self.inital_setup = "1"
        return True

    # socket accept event handler of Asyncore dispatcher
    # used to accept new Clients connections in a Synchronous manner then after 
    # challenge response and protocol wrap them in a approximation of Asynchronous behavior
    # with Asyncore Dispatcher which will poll each at timed intervals
    def handle_accept(self):

        # Accept event handler on listening socket
        # Accept a new client then start the Protocol Process
        socket, addr = self.accept()
        if (socket == None):
            return
        print 'Accepted client from port ', addr

        sleep(0.1)

        # remove the client identifier
        ID = socket.recv(1024)
        #decrypt with the server Private-key
        client_ID = self.rsa.decrypt_text(ID, self.ServerPrivateKey)
        #extract and generate hash
        orginal_hash = client_ID[-32:]
        #de-concatenate the clients ID
        client_ID = client_ID[:-32]

        print "***********************"
        print "***********************"

        dictObj = pickle.loads(client_ID)
        # clients nonce value
        cnonce = dictObj["nonce"]
        #Generate a comparison HASH value
        testhash  = self.hashcrypt.hashStringENC(str(cnonce))

        ###Should disconnect them here if this Check fails
        if orginal_hash == testhash:
            print "\nNONCE Integrity Validated\n"

        # extract the Clients RSA public key
        cpub = dictObj["public_key"]
        #store their  nonce
        self.CLIENT_ID_STORE[addr] = cnonce

        #SERVER generate a random nonce 
        random.seed()
        snonce = random.randrange(10000000000000,99999999999999)

        #response the the client with clients nonce and Servers nonce
        responce =  {"snonce":snonce, "cnonce": cnonce}
        #serialize the dictionary
        responce = pickle.dumps(responce)
        #hash it for INTEGRITY
        h = self.hashcrypt.hashStringENC(str(responce))
        #concatenate the hash to serialized data
        responce = responce + h
        # encrypt with the Servers Private key for DIGITAL SIGNATURE
        responce = self.rsa.encrypt_with_private(responce, self.ServerPrivateKey)
        # Encrypt with the clients public key for Confidentiality
        responce = self.rsa.encrypt_text(responce, cpub)
        #send message
        socket.send(responce)


        #Replay Protection (If a client nonce has occurred Before then dont add them 
        # to the Ayncore Wrapper Chat Room)
        # This would have to be save to a local Database to be really useful
        # as all nonces as lost once the server is down
        allowed = True
        if self.inital_setup == "1":
            print "previous nonces"
            for c in list(self.CLIENT_ID):
                print c[1]
                if c[1] == cnonce and snonce == c[2]:
                    print "AUTH already occurred for ", c[0]
                    #set allowed to false
                    #they wont get added to the system
                    allowed = False

        if allowed == True:
            client_id_list =[ (cpub), (cnonce), (snonce)]
            self.CLIENT_ID.append(client_id_list)
            # If setup protocol returns true
            # add remote socket to room
            stat = self.auth(socket, addr, cpub, snonce, cnonce)
            if stat == True:
                self.remote_clients.append(RemoteClient(self, socket, addr))

    #Handle Read
    #Called when the asynchronous loop detects that a read
    #call on the channels socket will succeed.
    def handle_read(self):
        self.read()

    def broadcast(self, message):

    	# broadcasts messages to all sockets that are connected
    	# to the server - stored in (remote_clients)
    	# filterS the origin socket of the message (does not return the message)
        try:
            orginal_hash = message[-32:]
            # remove the original serialized object from the concatenated
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
                        # ID this port as coming from the client that requested this LIST
                        connlist = connlist + " : " + str(remote_client.get_address()[1]) + " <-You "
                    else:
                        remoteConnectedClients.append(remote_client.get_address()[1])
                        connlist = connlist + " : " + str(remote_client.get_address()[1])
                connlist = self.aesObj.enc_str(connlist)      
                connlist = {"data" : connlist, "src_port": src_port, "FTX_ENC": mode, "remoteConnectedClients": remoteConnectedClients}
                connlist = pickle.dumps(connlist)
                
            packet = {"data" : src_data, "src_port": src_port, "FTX_ENC": mode, "remoteConnectedClients": None}
            src_data = pickle.dumps(packet)

            # Check the Integrity of received data vrs the new hash of extracted obj
            # NOT OVERLY USEFUL WITH STRING MESSAGES
            if test_hash == orginal_hash:
                "Integrity Verified"
            else:
                print "Integrity fail"

            # test Decryption --- (not necessary)
            test =  pickle.loads(src_data)
            dec_message_test = self.aesObj.dec_str(test["data"])
            print "Test Decrypt :", dec_message_test

            #console message
            print "Broadcasting encrypted mess :", test["data"] , " from 127.0.0.1:", src_port

            #loop through all the connected clients 
            for remote_client in self.remote_clients:
                # don't broadcast the message back to source socket
                if not (remote_client.get_address()[1] == src_port) and (dictObj["tx"] == False):
                    remote_client.send(src_data)
                # send back the LIST data to who requested it (connection list)
                if remote_client.get_address()[1] == src_port and dictObj["list"] == True:
                    remote_client.send(connlist)
                #START A PEER TO PEER FILE TRANSFER HANDSHAKE with a Destination Port
                #Choose by the source client
                #this will create 2 new THREADS , with new SOCKETS, to send encrypted files and strings
                #directly from client to client by passing the server
                if remote_client.get_address()[1] == int(dictObj["p2p_port"]) and dictObj["tx"] == True:
                    remote_client.send(src_data)
        except Exception, e:
            print "er Broadcasting"
            print str(e)

if __name__ == '__main__':
    #create a Chatroom 
    chatroom = Chatroom()
    print ("server address", chatroom.getsockname())
    print "started"
    # polls "channels" only stops only when all these have been closed
    asyncore.loop(timeout=5.0)