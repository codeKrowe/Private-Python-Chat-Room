#!/usr/bin/python

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
        self.sendFile_Btn = wx.Button(self, 1, 'Send File')

        self.IPC = IPC_Read(self.client, self.text_send , self.ctrl)

       	self.newSocketRead = None#P2P_READ()

        sizer.Add(self.text_send, 5, wx.EXPAND)
        sizer.Add(self.ctrl, 0, wx.EXPAND)
        sizer.Add(self.sendFile_Btn, 0, wx.EXPAND)

        self.SetSizer(sizer)

        self.ctrl.Bind(wx.EVT_TEXT_ENTER, self.onSend)
        self.sendFile_Btn.Bind(wx.EVT_BUTTON, self.sendFile)

    def sendFile(self, event):
        """ Send File to Client """

        # Create a new panel
        send_file = SendTo()
        send_file.Show()

    def onSend(self, event):
        """
        Send a message and close frame
        """
        try:
            # Get Text Entered
            data = self.ctrl.GetValue()
            # Display the text just entered by client.
            l = False
            if data == "<list>":
                l = True

            elif data == "<getnewSocket>":
                self.newSocketRead = P2P_READ()
                sleep(0.1)
                print "************New Socket Binding************"
            	print self.newSocketRead.get_address()[1]
                data = "This is Test Message from the New Socket"
                data = self.client.a.enc_str(str(data))
                # True for AES, False for RSA
                filetx = True
                dictobj = {'src_port' : self.client.client_src_port, 'data' : data, "list": l,\
                 "newSock": self.newSocketRead.get_address()[1], "file_TX_enc_type": filetx}

                pickdump = pickle.dumps(dictobj)
                # concatente serialized message with hash
                hashStr = self.client.md5_crypt.hashStringENC(pickdump)
                finalmessage = pickdump + hashStr
                if len(finalmessage) > 1024:
                    print "message too large for recieve buffer"
                else:
                    self.client.client.send(finalmessage)

            elif data == "<send>":
				d2 = "Testing Sending from second Thread - new Socket"
				port = 49961
				p2p_send = P2P_SEND(port, d2)

            else:
                self.text_send.AppendText("\n" + t() + data + "\n")
                self.ctrl.SetValue("")
                data = self.client.a.enc_str(str(data))
                dictobj = {'src_port' : self.client.client_src_port, 'data' : data, "list": l}
                pickdump = pickle.dumps(dictobj)
                # concatente serialized message with hash
                hashStr = self.client.md5_crypt.hashStringENC(pickdump)
                finalmessage = pickdump + hashStr
                if len(finalmessage) > 1024:
                    print "message too large for recieve buffer"
                else:
                    self.client.client.send(finalmessage)

        except Exception, err:
            print "send error"
            print traceback.format_exc()
            print sys.exc_info()[0]

class SendTo(wx.Frame):
    """ Choose who to send file to """

    def __init__(self):
        wx.Frame.__init__(self, None, -1, "Select Recipient", size=(250,150))
        choose = wx.StaticText(self, label="Choose Recipient:")

        # need to get list of connected clients?
        clients = ['12345', '98765', '14785', '25896', '00000']

        # add drop down list of connected clients
        self.client_list = wx.ComboBox(self, -1, choices=clients, style=wx.CB_READONLY)
        self.client_list.Centre()


        btn = wx.Button(self, label="Next")
        btn.Bind(wx.EVT_BUTTON, self.onNext)

        # add box to enter destination port
        # or do it behind the scenes

        sizer = wx.BoxSizer(wx.VERTICAL)
        flags = wx.ALL|wx.CENTER

        sizer.Add(choose, 0, flags, 5)
        sizer.Add(self.client_list, 0, flags, 5)
        sizer.Add(btn, 0, flags, 5)
        self.SetSizer(sizer)

        self.Bind(wx.EVT_COMBOBOX, self.OnSelect)

    def OnSelect(self, event):
        # print selected
        print self.client_list.GetValue()

    def onNext(self, event):
        """ Choose RSA or AES in next panel """
        self.Hide()
        choose_enc_type = FilePanel()
        choose_enc_type.Show()

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

class FilePanel(wx.Frame):
    """ Panel to Select Transfer Mode """

    #----------------------------------------------------------------------
    def __init__(self):
        wx.Frame.__init__(self, None, -1, "Send File", size=(250,150))
        self.choose = wx.StaticText(self, label="Choose File Transfer Mode:")
        self.rsa_radio = wx.RadioButton(self, label="RSA", style = wx.RB_GROUP)
        self.aes_radio = wx.RadioButton(self, label="AES")

        btn = wx.Button(self, label="Next")
        btn.Bind(wx.EVT_BUTTON, self.onNext)

        sizer = wx.BoxSizer(wx.VERTICAL)
        flags = wx.ALL|wx.CENTER

        sizer.Add(self.choose, 0, flags, 5)
        sizer.Add(self.rsa_radio, 0, flags, 5)
        sizer.Add(self.aes_radio, 0, flags, 5)
        sizer.Add(btn, 0, flags, 5)

        self.SetSizer(sizer)

    #----------------------------------------------------------------------
    def onNext(self, event):
        """"""
        print "First radioBtn = ", self.rsa_radio.GetValue()
        print "Second radioBtn = ", self.aes_radio.GetValue()
        self.Hide()
        choose_file = chooseFilePanel()
        choose_file.Show()

class chooseFilePanel(wx.Frame):
    """ Choose the file to send """

    def __init__(self):
        wx.Frame.__init__(self, None, -1, "Select File", size=(250,150))
        self.choose = wx.StaticText(self, label="Select File to Send:")
        btn = wx.Button(self, label="Next", pos=(100,100))
        btn.Bind(wx.EVT_BUTTON, self.onNext)

        choose_file = wx.FilePickerCtrl(self, pos=(125,100))

        sizer = wx.BoxSizer(wx.VERTICAL)
        flags = wx.ALL|wx.CENTER

        sizer.Add(self.choose, 0, flags, 5)
        sizer.Add(btn, 0, flags, 5)
        sizer.Add(choose_file, 0, flags, 5)

        self.SetSizer(sizer)

    def onNext(self, event):
        """ Send File to recipient"""
        pass
        # at this point all file transfer settings have been entered.
        # actually send the file from here.


class IPC_Read(Thread):
    def __init__(self, client, text_send, ctrl):
        """Initialize"""
        Thread.__init__(self)
        self.client = client
        self.start()
        self.text_send = text_send
        self.ctrl = ctrl

    def run(self):
        while True:
            data = self.client.client.recv(1024)
            if not data: sys.exit(0)
            print "***************************************"
            print "Recv Encypted Broadcast:", data
            data = self.client.a.dec_str(data)
            print "Decrypting:", data
            self.text_send.AppendText("\n" + t() + data + "\n")


class P2P_READ(Thread):
	def __init__(self):
		Thread.__init__(self)
		self.socket = None
		self.newReadSocketAddress = None
		self.start()

	def run(self):
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.bind(('localhost', 0))
		newSocketAddress = s.getsockname()
		self.newReadSocketAddress = newSocketAddress
		# print newSocketAddress
		s.listen(1)
		print "second socket exec"
		self.socket = s
		# self.socket.listen(0)
		sock, addr = self.socket.accept()
		data = sock.recv(1024)
		print data
		sock.close()
		print "socket Closed"

	def get_address(self):
		return self.newReadSocketAddress


class P2P_SEND(Thread):
	def __init__(self, dst_port, data):
		Thread.__init__(self)
		self.data = data
		self.dst_port = dst_port
		self.start()

	def run(self):
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.connect(('localhost', self.dst_port))
		s.send(self.data)
		print "tx complete"
		s.close()



if __name__ == "__main__":
    app = wx.App(False)
    frame = MainFrame()
    frame.Show()
    app.MainLoop()
