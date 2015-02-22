#!/usr/bin/python

import wx
from wx.lib.pubsub import pub

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
import time


PORT = 56963

# Method to return current system time
def t():
    return "[" + time.strftime("%H:%M:%S") + "] "

class ChatRoomFrame(wx.Frame):
    """"""

    def __init__(self):
        """Constructor"""
        self.performChatSetup()
        wx.Frame.__init__(self, None, -1, "Chat Room")
        panel = wx.Panel(self)

        sizer = wx.BoxSizer(wx.VERTICAL)
        # get rid of readonly to display text
        self.text = wx.TextCtrl(self, style=wx.TE_MULTILINE)
        self.ctrl = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER, size=(300, 25))

        sizer.Add(self.text, 5, wx.EXPAND)
        sizer.Add(self.ctrl, 0, wx.EXPAND)
        self.SetSizer(sizer)
        self.ctrl.Bind(wx.EVT_TEXT_ENTER, self.onSend)

    def onSend(self, event):
        """
        Send a message and close frame
        """
        print "!11111111111"
        try:
            # Get Text Entered
            data = self.ctrl.GetValue()
            print "!22222222"
            # Display the text just entered by client.
            self.text.SetValue(t()+ data)
            self.ctrl.SetValue("")
            print "!33333333"
            print "client src_port is: ", self.client_src_port
            # import pdb; pdb.set_trace()
            data = self.a.enc_str(data)
            print "!44444444"
            dictobj = {'src_port' : self.client_src_port, 'data' : data}
            print "!55555555"
            pickdump = pickle.dumps(dictobj)
            # print "size of pickle",sys.getsizeof(pickdump)

            # concatente serialized message with hash
            hashStr = self.md5_crypt.hashStringENC(pickdump)
            finalmessage = pickdump + hashStr
            if len(finalmessage) > 1024:
                print "message too large for recieve buffer"
            else:
                self.client.send(finalmessage)
        except:
            print "send error"

    def performChatSetup(self):
        rsa = RSAClass()
        public_key, private_key = rsa.generate_keys()

        pubKey = chilkat.CkPublicKey()
        pubKey.LoadXmlFile("Serverpublickey.xml")
        ServerPublicKey = pubKey.getXml()

        self.md5_crypt = chilkat.CkCrypt2()
        #  Any string argument automatically begins the 30-day trial.
        success = self.md5_crypt.UnlockComponent("30-day trial")
        if (success != True):
            print(md4_crypt.lastErrorText())
            sys.exit()
        self.md5_crypt.put_EncodingMode("hex")
        #  Set the hash algorithm:
        self.md5_crypt.put_HashAlgorithm("md5")

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


        # create a socket on the localhost and connect to PASSED port
        HOST = 'localhost'
        BUFSIZE = 1024
        ADDR = (HOST, PORT)
        self.client = socket(AF_INET, SOCK_STREAM)
        self.client.connect(ADDR)

        # setup an AES object with cipher block chaining, 128-bit key, padding size and format
        self.a = AESClass("cbc",128,0,"hex")

        # source port of self.client for use in communications later
        self.client_src_port = self.client.getsockname()[1]
        #random nonce generated for the cient
        # seeded (probally with system time) to ensure new nonce generation
        # well as much as pseudorandom can ensure
        random.seed()
        nonce = random.randrange(10000000000000,99999999999999)


        # generate an ID dictionary for the self.client, passing its
        # public-key and nonce to the server
        # serializing the object
        # hashing it + concatenating the hash to ther serialized data
        # then encypting with the servers public to ensure the nonce
        # cannot be intercepted
        # send to server
        firstID = {'nonce' : nonce, 'public_key': public_key}
        pid = pickle.dumps(firstID)
        hashStr = self.md5_crypt.hashStringENC(str(nonce))
        finalID = pid + hashStr
        encyptedpayload = rsa.encrypt_text(finalID, ServerPublicKey)
        self.client.send(encyptedpayload)

        # recieve the Responce from the server with orginal self.client nonce
        # and the servers nonce
        challange_Resp = self.client.recv(1024)
        # decypt with the self.clients public key
        challange_Resp = rsa.decrypt_text(challange_Resp,private_key)
        # decypt with the servers private - verifys - because nonces will be mangled
        # if there a different private RSA used - It is assumed server only has this key
        challange_Resp = rsa.decrypt_with_public(challange_Resp, ServerPublicKey)
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
            self.client.close()
            sys.exit(0)

        # extract the server nonce
        snonce = challange_Resp["snonce"]


        #check to see if a "Master self.client" has setup the CHatroom
        #if not then initate the Diffie-Hellman Key exchange with the server
        # if it has happened retieve the Session-key from the server

        # have to have exact bytes(sync issues) !!!!!!!!!!!!!!!!!!!!
        inital_setup = self.client.recv(1)
        print "inital_setup has occured before = ", inital_setup
        serverKey = None
        if inital_setup == "1":
            print "attempt to recv server key"
            serverKey = self.client.recv(1024)

            serverKey = rsa.decrypt_text(serverKey, private_key)
            # serverKey = rsa.decrypt_with_public(serverKey, ServerPublicKey)
            h = serverKey[-32:]
            serverKey = serverKey[:-32]
            h2 = self.md5_crypt.hashStringENC(serverKey)
            serverKey = pickle.loads(serverKey)

            if h == h2 and serverKey["cnonce"] == nonce and serverKey["snonce"] == snonce:
                sk  = serverKey["aes_key"]
                print "serverSessionKey", sk
                print "setting serverSessionKey"
                self.a.set_sessionkey(sk)
            else:
                print "Integrity Mismatch"
                self.client.close()
                sys.exit(0)



        # Recieved "Pickled" object on socket - ie serialised to String
        # Deserialize Data recieved back into
        # Python dictionary then remove the objects
        else:
            try:
                pickobject = self.client.recv(570)
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
            self.client.send(eAlice)

            #Alice's shared secret
            kAlice = dhAlice.findK(eBob)
            print("Alice's shared secret (should be equal to Bob's)")
            print(kAlice)

            sessionkey = hashcrypt.hashStringENC(kAlice)
            print "SessionKey", sessionkey
            self.a.set_sessionkey(sessionkey)
            iv = crypt.hashStringENC(sessionkey)
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


        def recv():
            while True:
                data = self.client.recv(1024)
                if not data: sys.exit(0)
                print "***************************************"
                print "Recv Encypted Broadcast:", data
                data = self.a.dec_str(data)
                type(data)
                print "Decrypting:", data

        Thread(target=recv).start()


        # At this point everything should be set up on the server.
        # each time a message is entered we handle it in a similar way to the CLI

        #====================================
        # Jon's CLI Code
        #====================================
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


        # print "self.client Shutdown"
        # self.client.close()
        # sys.exit()


class DirectConnection(wx.Frame):
    """"""

    def __init__(self):
        """Constructor"""
        wx.Frame.__init__(self, None, -1, "Connect To Frame")
        panel = wx.Panel(self)

        self.ipAddr = wx.StaticText(panel, label="Enter an IP Address: ")
        self.port = wx.StaticText(panel, label="Enter a Port: ")
        self.ipText = wx.TextCtrl(panel, value="")
        self.portText = wx.TextCtrl(panel, value="")
        self.connect_button = wx.Button(panel, label="Connect")
        self.connect_button.Bind(wx.EVT_BUTTON, self.onConnect)

        sizer = wx.BoxSizer(wx.VERTICAL)
        flags = wx.ALL|wx.CENTER
        sizer.Add(self.ipAddr, 0, flags, 5)
        sizer.Add(self.ipText, 0, flags, 5)
        sizer.Add(self.port, 0, flags, 5)
        sizer.Add(self.portText, 0, flags, 5)
        sizer.Add(self.connect_button, 0, flags, 5)
        panel.SetSizer(sizer)

    def onConnect(self, event):
        """
        Send a message and close frame
        """
        pass
        # TODO - Open a new frame that shows the chat window
        # TODO - Integrate P2P chat here

class MainPanel(wx.Panel):
    """"""

    def __init__(self, parent):
        """Constructor"""
        wx.Panel.__init__(self, parent=parent)
        self.frame = parent

        # Add a button to join the chatroom
        self.chat_room_button = wx.Button(self, -1, label="Join Chat Room")

        # Add a button to connect to someone
        self.connect_to_button = wx.Button(self, -1, label="Connect To")

        # Add buttons to panel
        # sizer.Add(self.chat_room_button, (0, 1))
        # sizer.Add(self.connect_to_button, (1, 1))

        # self.pubsubText = wx.TextCtrl(self, value="")
        # hideBtn = wx.Button(self, label="Open a new window")
        # hideBtn.Bind(wx.EVT_BUTTON, self.hideFrame)
        self.chat_room_button.Bind(wx.EVT_BUTTON, self.openChatRoom)
        self.connect_to_button.Bind(wx.EVT_BUTTON, self.openConnectTo)

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.chat_room_button, 0, wx.ALL|wx.CENTER, 5)
        sizer.Add(self.connect_to_button, 0, wx.ALL|wx.CENTER, 5)
        self.SetSizer(sizer)


    def openChatRoom(self, event):
        """ Opens the chat room frame """
        self.frame.Hide()
        chat_room = ChatRoomFrame()
        chat_room.Show()

    def openConnectTo(self, event):
        """ Opens the connect to frame """
        self.frame.Hide()
        direct_connection = DirectConnection()
        direct_connection.Show()

class MainFrame(wx.Frame):

    def __init__(self):
        wx.Frame.__init__(self, None, -1, "Chat Client")
        panel = MainPanel(self)

if __name__ == "__main__":
    app = wx.App(False)
    frame = MainFrame()
    frame.Show()
    app.MainLoop()
