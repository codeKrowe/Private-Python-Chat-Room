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

# version 2.0

# Hard Coded port for testing
# MUST BE CHANGED TO WHATEVER PORT SERVER SETS
PORT=58386
HOST = 'localhost'
BUFSIZE = 1024
ADDR = (HOST, PORT)

class Client:
    """Class for a user of the chat client."""
    def __init__(self):
        self.rsa = RSAClass()
        self.public_key, self.private_key = self.rsa.generate_keys()

        self.pubKey = chilkat.CkPublicKey()
        self.pubKey.LoadXmlFile("Serverpublickey.xml")
        self.ServerPublicKey = self.pubKey.getXml()

        self.md5_crypt = chilkat.CkCrypt2()
        self.hashcrypt = chilkat.CkCrypt2()
        self.dhAlice = chilkat.CkDh()

        # Unlock components above
        self.UnlockComponents()

        self.md5_crypt.put_EncodingMode("hex")
        #  Set the hash algorithm:
        self.md5_crypt.put_HashAlgorithm("md5")

        self.hashcrypt.put_EncodingMode("hex")
        self.hashcrypt.put_HashAlgorithm("md5")

        self.client = socket(AF_INET, SOCK_STREAM)
        self.client.connect(ADDR)

        # setup an AES object with cipher block chaining, 128-bit key, padding size and format
        self.a = AESClass("cbc",128,0,"hex")

        # source port of Client for use in communications later
        self.client_src_port = self.client.getsockname()[1]


    def UnlockComponents(self):
        success = self.md5_crypt.UnlockComponent("30-day trial")
        if (success != True):
            print(self.md4_crypt.lastErrorText())
            sys.exit()

        success = self.hashcrypt.UnlockComponent("Anything for 30-day trial.")
        if (success != True):
            print(self.hashcrypt.lastErrorText())
            sys.exit()

        success = self.dhAlice.UnlockComponent("Anything for 30-day trial")
        if (success != True):
            print(self.dhAlice.lastErrorText())
            sys.exit()


    def setUpClient(self):

        #random nonce generated for the cient
        # seeded (probally with system time) to ensure new nonce generation
        # well as much as pseudorandom can ensure
        random.seed()
        nonce = random.randrange(10000000000000,99999999999999)

        # generate an ID dictionary for the client, passing its
        # public-key and nonce to the server
        # serializing the object
        # hashing it + concatenating the hash to ther serialized data
        # then encypting with the servers public to ensure the nonce
        # cannot be intercepted
        # send to server
        firstID = {'nonce' : nonce, 'public_key': self.public_key}
        pid = pickle.dumps(firstID)
        hashStr = self.md5_crypt.hashStringENC(str(nonce))
        finalID = pid + hashStr
        encyptedpayload = self.rsa.encrypt_text(finalID, self.ServerPublicKey)
        self.client.send(encyptedpayload)

        # recieve the Responce from the server with orginal client nonce
        # and the servers nonce
        challange_Resp = self.client.recv(1024)
        # decypt with the clients public key
        challange_Resp = self.rsa.decrypt_text(challange_Resp,self.private_key)
        # decypt with the servers private - verifys - because nonces will be mangled
        # if there a different private RSA used - It is assumed server only has this key
        challange_Resp = self.rsa.decrypt_with_public(challange_Resp, self.ServerPublicKey)
        # remove the Hash of the orginal serialized object - 32 Characters from end of message
        h = challange_Resp[-32:]
        # remove the serialized object - to the last 32 characters of the data
        challange_Resp = challange_Resp[:-32]
        # rehash this object
        h2 = self.md5_crypt.hashStringENC(challange_Resp)
        # de-serialized the object back to a python dictionary
        challange_Resp = pickle.loads(challange_Resp)


        # extract the returned nonce-1, check if valid, close socket and exit if not
        nonce_1 = challange_Resp["cnonce"]
        if h == h2 and nonce == nonce_1:
            print "\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$"
            print "Challange Integrity Verified"
            print "$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
        else:
            print "Integrity Challange Failed - closing connection"
            client.close()
            sys.exit(0)

        # extract the server nonce
        snonce = challange_Resp["snonce"]


        #check to see if a "Master Client" has setup the CHatroom
        #if not then initate the Diffie-Hellman Key exchange with the server
        # if it has happened retieve the Session-key from the server

        # have to have exact bytes(sync issues) !!!!!!!!!!!!!!!!!!!!
        inital_setup = self.client.recv(1)
        print "inital_setup has occured before = ", inital_setup
        serverKey = None
        if inital_setup == "1":
            print "attempt to recv server key"
            serverKey = self.client.recv(1280)
            serverKey = self.rsa.decrypt_text(serverKey, self.private_key)
            serverKey = self.rsa.decrypt_with_public(serverKey, self.ServerPublicKey)
            h = serverKey[-32:]
            serverKey = serverKey[:-32]
            h2 = self.md5_crypt.hashStringENC(serverKey)
            serverKey = pickle.loads(serverKey)

            if h == h2 and serverKey["cnonce"] == nonce and serverKey["snonce"] == snonce:
                sk  = serverKey["aes_key"]
                print "serverSessionKey", sk
                print "setting serverSessionKey"
                self.a.set_sessionkey(sk)
                iv = self.a.getCrypt().hashStringENC(sk)
                self.a.setIv(iv)
            else:
                print "Integrity Mismatch"
                client.close()
                sys.exit(0)



        # Recieved "Pickled" object on socket - ie serialised to String
        # Deserialize Data recieved back into
        # Python dictionary then remove the objects
        else:
            try:
                pk1 = self.client.recv(1792)
                pk2 = self.client.recv(1792)
                pk1 = self.rsa.decrypt_text(pk1, self.private_key)
                pk2 = self.rsa.decrypt_text(pk2, self.private_key)
                defragment = pk2 + pk1
                defragment = self.rsa.decrypt_with_public(defragment, self.ServerPublicKey)
                h = defragment[-32:]
                defragment = defragment[:-32]
                h2 = self.md5_crypt.hashStringENC(defragment)
                dictObj = pickle.loads(defragment)

                if h == h2 and dictObj["cnonce"] == nonce and dictObj["snonce"] == snonce:
                    p = dictObj["p"]
                    g = dictObj["g"]
                    g = int(g)
                    eBob = dictObj["e"]
                else:
                    print "Integrity Mismatch"
                    client.close()
                    sys.exit(0)

            except:
                print "fails to recieve Diffie-hellman data"
                sys.exit(0)

            # use the information for Diffie-hellman cleint side
            success = self.dhAlice.SetPG(p,g)
            if (success != True):
                print("P is not a safe prime")
                sys.exit()


            eAlice = self.dhAlice.createE(256)
            eAlice = self.rsa.encrypt_text(eAlice, self.ServerPublicKey)
            print "size of eAlice", len(str(eAlice))
            self.client.send(eAlice)

            #Alice's shared secret
            kAlice = self.dhAlice.findK(eBob)
            print("Alice's shared secret (should be equal to Bob's)")
            print(kAlice)

            sessionkey = self.hashcrypt.hashStringENC(kAlice)
            print "SessionKey", sessionkey
            self.a.set_sessionkey(sessionkey)
            iv = self.a.getCrypt().hashStringENC(sessionkey)
            self.a.setIv(iv)

        # print "serverKey testing"
        # print type(serverKey)
        # print len(str(serverKey))
        # depending on if this is a first setup or not
        # use the key (ie same key)for AES ---- one that is sent in open
        # would have to use a digital envelope of the like to achieve this properly

        # setup this sides AES object
        self.a.setupAES()

        print "-------------AES KEY-----------------"
        print self.a.get_key()




        # def recv():
        #     while True:
        #         data = self.client.recv(1024)
        #         if not data: sys.exit(0)
        #         print "***************************************"
        #         print "Recv Encypted Broadcast:", data
        #         data = self.a.dec_str(data)
        #         type(data)
        #         print "Decrypting:", data

        # Thread(target=recv).start()



        # while True:
        #     try:
        #     # take input from command terminal   -- change to GUI
        #         data = raw_input('>> ')
        #         if not data: print '>> '
        #         data = self.a.enc_str(data)
        #         dictobj = {'src_port' : self.client_src_port, 'data' : data}
        #         pickdump = pickle.dumps(dictobj)
        #         # print "size of pickle",sys.getsizeof(pickdump)

        #         # concatente serialized message with hash
        #         hashStr = self.md5_crypt.hashStringENC(pickdump)
        #         finalmessage = pickdump + hashStr
        #         if len(finalmessage) > 1024:
        #             print "message too large for recieve buffer"
        #         else:
        #             self.client.send(finalmessage)
        #     except:
        #         print "send error"


        # print "Client Shutdown"
        # self.client.close()
        # sys.exit()


# def main():
#     c = Client()
#     c.setUpClient()

if __name__ == '__main__':
    main()

