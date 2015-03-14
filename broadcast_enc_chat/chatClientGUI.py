#!/usr/bin/python
# version 2.0

import wx
from wx.lib.pubsub import pub

import socket
# from socket import *
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
from client import Client
import traceback
from multiprocessing import Process, Value, Array, Manager
import binascii

# Commands FileTX
# <list>                              - gets list connected scockets
# 6DCC655077693A5E1ED5857314A0F96D    - Inits Tranfser
# use like this (66666 = destination socket)
# 6DCC655077693A5E1ED5857314A0F96D:66666


# Method to return current system time
def t():
    return "[" + time.strftime("%H:%M:%S") + "] "

class ChatRoomFrame(wx.Frame):
    """"""

    def __init__(self):
        """Constructor"""
        self.client = Client()
        self.client.setUpClient()
        # starts a InterProcess Communication Thread

        wx.Frame.__init__(self, None, -1, "Chat Room")
        panel = wx.Panel(self)

        sizer = wx.BoxSizer(wx.VERTICAL)

        # Create a messages display box
        self.text_send = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_LEFT | wx.BORDER_NONE | wx.TE_READONLY)
        self.ctrl = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER, size=(300, 25))

        
        # Create a Shared Memory manager to share object between threads
        self.manager = Manager()
        self.Shared_Mem_Dictionary = self.manager.dict()
        #creat uniuqe Command code that the system can recognise and ititate actions based on
        #such as file transmission 
        self.filetxID = "6DCC655077693A5E1ED5857314A0F96D"
        self.filetxID_Final = "2D56DE9597CFF43DD5C1335D509517C9"
        self.init_File_Server_mode = False
        self.Shared_Mem_Dictionary["p2p_dest"]= 0
        #THE InterProcess Thread - The Main READING THREAD for the chat Client
        #Messages are passed through here 
        #Checks for "Custom Commands" are also performed
        self.IPC = IPC_Read(self.client, self.text_send , self.ctrl, self)
        #create a new READING THREAD with a NEW SOSCKET to bind to
       	self.newSocketRead = None#P2P_READ()
        sizer.Add(self.text_send, 5, wx.EXPAND)
        sizer.Add(self.ctrl, 0, wx.EXPAND)
        self.SetSizer(sizer)
        self.ctrl.Bind(wx.EVT_TEXT_ENTER, self.onSend)
        #FLAG for LISTING connected Cleints from the server and have the server
        #build this list and retunr it to "this" cleint instance
        self.l = False
        self.fileServerMode = False
        #Encrytion mode to use in filetansfer mode (RSA = 2) (AES = 1)

        self.fileTransferEncryption = 1


    def bind_to_new(self, p2p_port):
    	try:
        	self.newSocketRead = P2P_READ(self.fileTransferEncryption, self.client.public_key, self.client.private_key)
        except:
        	print "An Erro Binding a new socket in a new thread"
        sleep(0.1)
        print "************New Socket Binding************"
        print self.newSocketRead.get_address()[1]
        #Attach COMMAND CODE for FILETRANSFER SERVER setup complete
        #gets the client to start a FILETX send Thread when it recieves this 
        #message ( also attached the new port to the message so the client can use the 
        #address)
        data = "2D56DE9597CFF43DD5C1335D509517C9:" + str(self.newSocketRead.get_address()[1])
        #encypt the data
        data = self.client.a.enc_str(str(data))
        # True for AES, False for RSA
        filetx = True
        dictobj = {'src_port' : self.client.client_src_port, "data" : data, "list": self.l,\
         "newSock": self.newSocketRead.get_address()[1], "tx": filetx, "p2p_port":p2p_port, "FTX_ENC" :self.fileTransferEncryption}
        #serialize the data
        pickdump = pickle.dumps(dictobj)
        # concatente serialized message with hash
        hashStr = self.client.md5_crypt.hashStringENC(pickdump)
        finalmessage = pickdump + hashStr
        if len(finalmessage) > 1024:
            print "message too large for recieve buffer"
        else:
            self.client.client.send(finalmessage)
        self.init_File_Server_mode == False

    '''standard send code used by specific funtions'''
    def onSend(self, event):
        def standard_send(data):
            data = self.client.a.enc_str(str(data))
            dictobj = {'src_port' : self.client.client_src_port, 'data' : data, "list": self.l, "tx": False\
            ,"p2p_port":0, "newSock": 0, "FTX_ENC" :self.fileTransferEncryption}
            pickdump = pickle.dumps(dictobj)
            # concatente serialized message with hash
            hashStr = self.client.md5_crypt.hashStringENC(pickdump)
            finalmessage = pickdump + hashStr
            if len(finalmessage) > 1024:
                print "message too large for recieve buffer"
            else:
                self.client.client.send(finalmessage)
                self.l = False
        def list (data):
            self.l = True
            standard_send(data)

        try:
            # Get Text Entered
            data = self.ctrl.GetValue()

            '''TEXT COMMAND INPUTS LIKE IN IRC'''
            # Display the text just entered by client.
            if data == "<list>":
            	self.text_send.AppendText("\n" + t() + data + "\n")
                self.ctrl.SetValue("")
                self.l = True
                standard_send(data)

            # start a HANDSHAKE with another client 
            # routing through the server to a destination client
            # inserts a COMMAND CODE to the message
            elif data[:9] == "<init_tx>":
            	self.text_send.AppendText("\n" + t() + data + "\n")
                data = self.filetxID +":" +data[10:]# + "-" +str(self.client.client_src_port)
                print "data", data
                standard_send(data)
                self.ctrl.SetValue("")

            # lists the port of this instance to the chat window
            elif data == "<myport>":
                print "this port is :", self.client.client_src_port
                self.text_send.AppendText("\n" + t() + "this port is :" + str(self.client.client_src_port) + "\n")
                self.ctrl.SetValue("")

            #changes the filetransfer encyption mode globally
            elif data == "<rsa>":
            	self.text_send.AppendText("\n" + t() + "Entering RSA MODE" + "\n")
            	self.fileTransferEncryption = 2
            	dat ="<Entering RSA MODE>"
            	standard_send(dat)
            	self.ctrl.SetValue("")
 				
            elif data == "<aes>":
            	self.text_send.AppendText("\n" + t() + "Entering AES MODE" + "\n")
            	self.fileTransferEncryption = 1
            	dat ="<Entering AES MODE>"
            	standard_send(dat)
            	self.ctrl.SetValue("")

            # code for a standard message send
            else:
                #append the message to chatwindows with timestamp
                self.text_send.AppendText("\n" + t() + data + "\n")
                #clear the submit box
                self.ctrl.SetValue("")
                #encypt the data
                data = self.client.a.enc_str(str(data))
                # create the packet
                dictobj = {'src_port' : self.client.client_src_port, 'data' : data, "list": self.l, "tx":False , "p2p_port":0\
                ,"newSock": 0, "FTX_ENC" :self.fileTransferEncryption}
                #serialise it
                pickdump = pickle.dumps(dictobj)
                # concatente serialized message with hash
                hashStr = self.client.md5_crypt.hashStringENC(pickdump)
                #make the final message 
                finalmessage = pickdump + hashStr
                if len(finalmessage) > 1024:
                    print "message too large for recieve buffer"
                else:
                    self.client.client.send(finalmessage)

        except Exception, err:
            print "send error"
            print traceback.format_exc()
            print sys.exc_info()[0]


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


class IPC_Read(Thread):
    """Main Socket Reading Thread for the client"""
    def __init__(self, client, text_send, ctrl, caller):
        """Initialize"""
        Thread.__init__(self)
        self.client = client
        self.caller = caller
        self.text_send = text_send
        self.ctrl = ctrl
        self.start()

    def run(self):
        while True:
            #recieve data
            data = self.client.client.recv(1024)
            if not data: sys.exit(0)
            #deserialise the data
            packet = pickle.loads(data)
            data = packet["data"]
            #get the source port of the "packet"
            src_port = packet["src_port"]

            print "MODE IS CURRENTLY", self.caller.fileTransferEncryption

            #set the Filetrasfer mode
            if packet["FTX_ENC"] == 2:
            	self.caller.fileTransferEncryption = 2
            elif packet["FTX_ENC"] == 1:
            	self.caller.fileTransferEncryption = 1
            #decypt the data
            data = self.client.a.dec_str(data)
            #Check for COMMAND to start this instance as a SERVER
            #if command exists take Source port and pass it and create the
            #P2P_SEND thread, which will bind to a new socket and 
            #send the new PORT back to the client that iniated the request
            if (len(data) > 32) and data[:32] == self.caller.filetxID and int(data[33:]) == int(self.client.client_src_port):
                self.caller.init_File_Server_mode = True
                # dst_p2p_port = data[33:]
                print 'dst_p2p_port', src_port
                self.caller.bind_to_new(int(src_port))
                print "value change shared Shared_Mem_Dictionary"
            print "Decrypting:", data
            #if the message has the SERVER SETUP COMPLETE SO SEND COMMAND
            #this will initate a P2P new sending THREAD that will start the file transfer
            if (len(data) > 32) and data[:32] == self.caller.filetxID_Final:
            	newFileServerSocketAddress = int(data[33:])
            	print "Got the new Server Socket - Returned From Server"
            	print newFileServerSocketAddress
            	d2 = "filetx from second Thread - Client!!!!!!!!!!!!!!!!!!!!!!!!!"
            	p2p_send = P2P_SEND(newFileServerSocketAddress, d2, self.caller.fileTransferEncryption)
            #append recieved messages to the GUI chat window
            self.text_send.AppendText("\n" + t() + data + "\n")


"""PEER TO PEER Read Thread
Binds to new Socket, waits for client to connect once it recieves the new port address
(calling funtion sends this port back to the initiating client)"""
class P2P_READ(Thread):
    def __init__(self, mode, public_key, private_key):
        Thread.__init__(self)
        self.socket = None
        self.newReadSocketAddress = None
        self.mode = mode
        self.process = None
        self.public_key = public_key
        self.private_key = private_key
        self.start()

    def run(self):
        print "size of public_key", len(str(self.public_key))
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.bind(('localhost', 0))
        newSocketAddress = s.getsockname()
        self.newReadSocketAddress = newSocketAddress


        if self.mode == 1:
            s.listen(1)
            print "@@@@@@@@@@@@@@@@@@@@@@@@-SECOND SOCKET CREATED AES-@@@@@@@@@@@@@@@@@@@@@@"
            self.socket = s
            sock, addr = self.socket.accept()
            data = sock.recv(1024)
            print data
            sock.close()
            print "@@@@@@@@@@@@@@@@@@@@@@@ new socket closed @@@@@@@@@@@@@@@@@@@@@@@@@@@@"


        if self.mode == 2:
            s.listen(1)
            print "@@@@@@@@@@@@@@@@@@@@@@@@-SECOND SOCKET CREATED RSA-@@@@@@@@@@@@@@@@@@@@@@"
            self.socket = s
            sock, addr = self.socket.accept()
            sock.send(self.public_key)
            rsa = RSAClass()
            file_f = open("temp.jpg",'wb')
            # data = sock.recv(1024)
            block=sock.recv(4608)
            #----receiving & decrypting-------
            blockCounter = len(block)
            while (block): 
                print "RECIEVED", blockCounter, "Bytes"
                block = rsa.decrypt_text(block, self.private_key)
                unhexblock=binascii.unhexlify(block)
                file_f.write(unhexblock)
                block=sock.recv(4608)
                blockCounter += len(block)
            print "!!!!!!!!!!!!!!!!!!  FILETRANSFER COMPLETED !!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            file_f.close()        
            sock.close()
            print "@@@@@@@@@@@@@@@@@@@@@@@ new socket closed @@@@@@@@@@@@@@@@@@@@@@@@@@@@" 

    #termiate this thread once it has been used
    def stop(self):
        print "Trying to stop thread "
        if self.process is not None:
            self.process.terminate()
            self.process = None
    #return the new port so that it can be send back to the client that initiated the handshake
    def get_address(self):
        return self.newReadSocketAddress


class P2P_SEND(Thread):
    def __init__(self, dst_port, data, mode):
        Thread.__init__(self)
        self.data = data
        self.filename = "kali_linux.jpg"
        self.dst_port = dst_port
        self.mode = mode
        self.start()
        self.process = None

    def run(self):
        if self.mode == 1:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('localhost', self.dst_port))
            s.send(self.data)
            print "AES FILETRANSFER COMPLETE"
            s.close()
        if self.mode == 2:
            rsa = RSAClass()
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('localhost', self.dst_port)) 
            FSPUBLIC = s.recv(243)
            print "recieved public_key from FileServerClient"
            print FSPUBLIC
            #get the total size of file in bytes
            filesize = int(os.stat(self.filename).st_size)
            file_f = open("kali_linux.jpg", "rb") 
            block = file_f.read(1024)
            blockCounter = len(block) 
            while (block):
                calc = (float(blockCounter)/float(filesize))*float(100)
                print calc
                hexblock=binascii.hexlify(block)
                block = rsa.encrypt_text(hexblock, FSPUBLIC)
                s.send(block)
                block = file_f.read(1024)
                blockCounter += len(block)
            file_f.close()
            s.close()           
            # s.send(self.data)
            print "RSA FILETRANSFER COMPLETE"           

	def stop(self):
		print "Trying to stop thread "
		if self.process is not None:
			self.process.terminate()
			self.process = None


if __name__ == "__main__":
    app = wx.App(False)
    frame = MainFrame()
    frame.Show()
    app.MainLoop()
