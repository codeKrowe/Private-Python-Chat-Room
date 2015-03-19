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
import copy

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
        #default file path
        self.file_path = "kali_linux.jpg"
        self.client = Client()
        self.client.setUpClient()
        # starts a InterProcess Communication Thread

        # Create a Shared Memory manager to share object between threads
        self.manager = Manager()
        self.Shared_Mem_Dictionary = self.manager.dict()
        #creat uniuqe Command code that the system can recognise and ititate actions based on
        #such as file transmission
        self.filetxID = "6DCC655077693A5E1ED5857314A0F96D"
        self.filetxID_Final = "2D56DE9597CFF43DD5C1335D509517C9"
        self.init_File_Server_mode = False
        self.Shared_Mem_Dictionary["p2p_dest"]= 0
        self.Shared_Mem_Dictionary["choices"] = []
        self.Shared_Mem_Dictionary["mode"] = 0
        self.Shared_Mem_Dictionary["file_path"] = self.file_path
        self.Shared_Mem_Dictionary["private"] = False
        self.Shared_Mem_Dictionary["privatemessage"] = None
        #THE InterProcess Thread - The Main READING THREAD for the chat Client
        #Messages are passed through here
        #Checks for "Custom Commands" are also performed


        wx.Frame.__init__(self, None, -1, "Chat Room")
        panel = wx.Panel(self)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Create a messages display box
        self.text_send = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_LEFT | wx.BORDER_NONE | wx.TE_READONLY)
        self.ctrl = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER, size=(300, 25))
        self.sendFile_Btn = wx.Button(self, 1, 'Send File')

        #Also make a shallow copy of the AES Object
        #to stop of possible simulatnous access issues
        #and saves having to set it up again
        newAes = copy.copy(self.client.a)
        self.IPC = IPC_Read(self.client, self.text_send , self.ctrl, self, newAes, self.Shared_Mem_Dictionary)
        #create a new READING THREAD with a NEW SOSCKET to bind to
       	self.newSocketRead = None#P2P_READ()
        # btn = wx.Button(self, label="Next", pos=(100,100))
        # btn.Bind(wx.EVT_BUTTON, self.onNext)

        self.choose_file = wx.FilePickerCtrl(self)
        clients = self.Shared_Mem_Dictionary["choices"]

        # add port entry box
        self.port = wx.StaticText(self, label="Enter a Port: ")
        self.portText = wx.TextCtrl(self, value="")

        self.rsa_radio = wx.RadioButton(self, label="RSA", style = wx.RB_GROUP)
        self.aes_radio = wx.RadioButton(self, label="AES")

        btn = wx.Button(self, label="Set File Transfer Mode")

        sizer.Add(self.text_send, 5, wx.EXPAND)
        sizer.Add(self.ctrl, 0, wx.EXPAND)
        sizer.Add(self.sendFile_Btn, 0, wx.EXPAND)
        sizer.Add(self.choose_file, 0, wx.EXPAND)
        sizer.Add(self.rsa_radio, 0, wx.EXPAND)
        sizer.Add(self.aes_radio, 0, wx.EXPAND)
        sizer.Add(self.port, 0, wx.EXPAND)
        sizer.Add(self.portText, 0, wx.EXPAND)
        sizer.Add(btn, 0, wx.EXPAND)

        self.SetSizer(sizer)

        self.ctrl.Bind(wx.EVT_TEXT_ENTER, self.onSend)
        self.sendFile_Btn.Bind(wx.EVT_BUTTON, self.sendFile)
        btn.Bind(wx.EVT_BUTTON, self.onSet)


        #FLAG for LISTING connected Cleints from the server and have the server
        #build this list and retunr it to "this" cleint instance
        self.l = False
        self.fileServerMode = False
        #Encrytion mode to use in filetansfer mode (RSA = 2) (AES = 1)
        self.fileTransferEncryption = 1

        self.privatemessage = None
        self.private = False


    def sendFile(self, event):
        """ Send File to Client """
        file_path = self.choose_file.GetPath()
        #set the file path
        self.file_path = file_path
        self.Shared_Mem_Dictionary["file_path"] = str(file_path)

        port = self.portText.GetValue()

        if int(port) == self.client.client_src_port:
             self.text_send.AppendText("\n" + t() + ":This is Your Port! " + "\n")  
             self.text_send.AppendText("\n" + t() + ":Try Again " + "\n")                      
        elif str(port) == "":
             self.text_send.AppendText("\n" + t() + ":Enter a Destination PORT! " + "\n")
        else:
            file_transmisson_cmd = self.filetxID + ":" + str(port)
            self.text_send.AppendText("\n" + t() + ":Filetrasfer Started " + "\n")
            self.ctrl.SetValue("")
            self.standard_send_to(file_transmisson_cmd)
            
    def onSet(self,event):
        if self.rsa_radio.GetValue():
            self.fileTransferEncryption = 2
            dat ="<Entering RSA MODE>"
            self.standard_send_to(dat)
        if self.aes_radio.GetValue():
            dat ="<Entering AES MODE>"
            self.standard_send_to(dat)
            self.fileTransferEncryption = 1

    def bind_to_new(self, p2p_port):
        newaes = copy.copy(self.client.a)
    	try:
        	self.newSocketRead = P2P_READ(self.fileTransferEncryption, self.client.public_key, self.client.private_key, newaes, self.text_send)
        except Exception, err:
            print "Bind method error"
            print traceback.format_exc()
            print sys.exc_info()[0]
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



    def standard_send_to(self, data):
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

            elif data[:9] == "<private>":
                split = data.split(":")
                privateport = split[1]
                self.privatemessage = split[2]
                self.private = True
                self.Shared_Mem_Dictionary["private"] = True
                self.Shared_Mem_Dictionary["privatemessage"] = self.privatemessage
                data = self.filetxID +":"+str(privateport)
                self.fileTransferEncryption = 2
                self.standard_send_to(data)
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
                self.text_send.AppendText("\n" + t() +"<You> " + data + "\n")
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



class MainPanel(wx.Panel):
    """"""

    def __init__(self, parent):
        """Constructor"""
        wx.Panel.__init__(self, parent=parent)
        self.frame = parent
        # Add a button to join the chatroom
        self.chat_room_button = wx.Button(self, -1, label="Join Chat Room")
        self.chat_room_button.Bind(wx.EVT_BUTTON, self.openChatRoom)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.chat_room_button, 0, wx.ALL|wx.CENTER, 5)
        self.SetSizer(sizer)


    def openChatRoom(self, event):
        """ Opens the chat room frame """
        self.frame.Hide()
        chat_room = ChatRoomFrame()
        chat_room.Show()

class MainFrame(wx.Frame):

    def __init__(self):
        wx.Frame.__init__(self, None, -1, "Chat Client")
        panel = MainPanel(self)

class IPC_Read(Thread):
    """Main Socket Reading Thread for the client"""
    def __init__(self, client, text_send, ctrl, caller, aes, sharedMem):
        """Initialize"""
        Thread.__init__(self)
        self.client = client
        self.caller = caller
        self.text_send = text_send
        self.ctrl = ctrl
        self.aes = aes
        self.sharedMem = sharedMem
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

            remoteConnectedClients = packet["remoteConnectedClients"]
            if not remoteConnectedClients == None:
                self.sharedMem["choices"] = remoteConnectedClients
                print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
                print "listing of Client", remoteConnectedClients
                print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
            print "MODE IS CURRENTLY", self.caller.fileTransferEncryption

            #set the Filetrasfer mode
            if packet["FTX_ENC"] == 2:
            	self.caller.fileTransferEncryption = 2
            elif packet["FTX_ENC"] == 1:
            	self.caller.fileTransferEncryption = 1
            #decypt the data
            data = self.client.a.dec_str(data)
            print "Decrypting:", data
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
            #if the message has the SERVER SETUP COMPLETE SO SEND COMMAND
            #this will initate a P2P new sending THREAD that will start the file transfer
            elif (len(data) > 32) and data[:32] == self.caller.filetxID_Final:
                newFileServerSocketAddress = int(data[33:])
            	print "Got the new Server Socket - Returned From Server"
            	print newFileServerSocketAddress
            	d2 = "filetx from second Thread - Client!!!!!!!!!!!!!!!!!!!!!!!!!"
            	p2p_send = P2P_SEND(newFileServerSocketAddress, d2, self.caller.fileTransferEncryption , self.aes, self.sharedMem, self.text_send)
            #append recieved messages to the GUI chat window
            # using wx Callafter to limit the errors introduced in OSX
            # caused by accessing the same object in multiplethreads
            # (stange that it only crashes in osx - windows and linux were unaffected)
            # CallAfter or CallLater is used to schedule a function to be called on the main UI thread
            # (with the actual UI-changing code inside that function
            elif not data[:32]== "6DCC655077693A5E1ED5857314A0F96D" and not data ==  "<list>":
            	wx.CallAfter(self.text_send.AppendText, "\n" + t()+"<" +str(src_port)+"> " + data + "\n")
            # self.text_send.AppendText("\n" + t() + data + "\n")


"""PEER TO PEER Read Thread
Binds to new Socket, waits for client to connect once it recieves the new port address
(a called funtion send this port back to the initiating client |get_address()|)"""
class P2P_READ(Thread):
    def __init__(self, mode, public_key, private_key, aes,text_send):
        Thread.__init__(self)
        self.socket = None
        self.newReadSocketAddress = None
        self.mode = mode
        self.process = None
        self.aes = aes
        self.text_send = text_send
        self.original_file_path = None
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

            self.original_file_path = sock.recv(1024)
            # print "self.original_file_path", self.original_file_path, len(self.original_file_path)
            unpaddedOriginal = self.original_file_path.strip()
            print "unpaddedOriginal", unpaddedOriginal, len(unpaddedOriginal)
            path, filename_ext = os.path.split(unpaddedOriginal)
            filename, extension = os.path.splitext(filename_ext)
            filename = filename + "_txCopy" + extension

            file_f = open(filename,'wb') #open in binary
            block = sock.recv(2752)
            blockCounter = len(block)
            while (block):
                    print "RECIEVED", blockCounter, "Bytes"
                    block=self.aes.dec_str(block)
                    unhexblock=binascii.unhexlify(block)
                    file_f.write(unhexblock)
                    block=sock.recv(2752)
                    blockCounter += len(block)
            wx.CallAfter(self.text_send.AppendText, "\n" + t() + "AES FILETRANSFER RECIEVED" + "\n")
            print "!!!!!!!!!!!!!!!!!!  FILETRANSFER COMPLETED !!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            file_f.close()
            sock.close()
            print "@@@@@@@@@@@@@@@@@@@@@@@ new socket closed @@@@@@@@@@@@@@@@@@@@@@@@@@@@"


        if self.mode == 2:
            s.listen(1)
            print "@@@@@@@@@@@@@@@@@@@@@@@@-SECOND SOCKET CREATED RSA-@@@@@@@@@@@@@@@@@@@@@@"
            self.socket = s
            sock, addr = self.socket.accept()
            sock.send(self.public_key)
            rsa = RSAClass()
            private = sock.recv(1)

            if private == "1":
				print "ENTERING PRIAVTE MODE"
				privatemessage = sock.recv(2048)
				privatemessage = privatemessage.strip()
				privatemessage = rsa.decrypt_text(privatemessage, self.private_key)
				#wx.CallAfter(self.text_send.AppendText, "\n" + t() + "RSA privatemessage RECIEVED" + "\n")
				wx.CallAfter(self.text_send.AppendText, "\n" + t() + "RSA_PRIVATE:"+privatemessage  + "\n")
            else:
				self.original_file_path = sock.recv(1024)
	            # print "self.original_file_path", self.original_file_path, len(self.original_file_path)
				unpaddedOriginal = self.original_file_path.strip()
				print "unpaddedOriginal", unpaddedOriginal, len(unpaddedOriginal)
				path, filename_ext = os.path.split(unpaddedOriginal)
				filename, extension = os.path.splitext(filename_ext)
				filename = filename + "_txCopy" + extension

				file_f = open(filename,'wb')
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
				wx.CallAfter(self.text_send.AppendText, "\n" + t() + "RSA FILETRANSFER RECIEVED" + "\n")
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

    def __init__(self, dst_port, data, mode, aes, sharedMem, text_send):
        Thread.__init__(self)
        self.data = data
        self.filename = "kali_linux.jpg"
        self.dst_port = dst_port
        self.mode = mode
        self.aes = aes
        self.sharedMem = sharedMem
        self.text_send = text_send
        self.start()
        self.process = None

    def run(self):

        file_path = self.sharedMem["file_path"]

        private = self.sharedMem["private"]
		#self.Shared_Mem_Dictionary["privatemessage"] = self.privatemessage

        if self.mode == 1:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('localhost', self.dst_port))
            paddedFile_path = file_path.ljust(1024)
            print "len padded file path ", paddedFile_path
            s.send(paddedFile_path)
            file_f = open(file_path, "rb")
            block = file_f.read(1024)
            filesize = int(os.stat(file_path).st_size)
            blockCounter = len(block)
            while (block):
                calc = (float(blockCounter)/float(filesize))*float(100)
                print calc
                hexblock=binascii.hexlify(block)
                block = self.aes.enc_str(hexblock)
                s.send(block)
                block = file_f.read(1024)
                blockCounter += len(block)
            print "file sent"
            file_f.close()
            print "AES FILETRANSFER COMPLETE"
            wx.CallAfter(self.text_send.AppendText, "\n" + t() + "AES FILETRANSFER COMPLETE" + "\n")
            s.close()


        if self.mode == 2:
            rsa = RSAClass()
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('localhost', self.dst_port))
            FSPUBLIC = s.recv(243) 

            if private == True:
                s.send("1")
                privatemessage = self.sharedMem["privatemessage"]
	            # paddedFile_path = file_path.ljust(1024)
	            # print "len padded file path ", paddedFile_path
                enc_private_message = rsa.encrypt_text(str(privatemessage), FSPUBLIC)
                enc_private_message = enc_private_message.ljust(2048)
                s.send(enc_private_message)        		
                wx.CallAfter(self.text_send.AppendText, "\n" + t() + "RSA privatemessage COMPLETE" + "\n")
                self.sharedMem["private"] = False

            else:
				s.send("0")
	            # s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	            # s.connect(('localhost', self.dst_port))
				paddedFile_path = file_path.ljust(1024)
				print "len padded file path ", paddedFile_path
				s.send(paddedFile_path)

	            #get the total size of file in bytes
				filesize = int(os.stat(file_path).st_size)
				file_f = open(file_path, "rb")
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
				wx.CallAfter(self.text_send.AppendText, "\n" + t() + "RSA FILETRANSFER COMPLETE" + "\n")


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
