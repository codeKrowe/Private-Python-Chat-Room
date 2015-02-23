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
        # get rid of readonly to display text
        self.text = wx.TextCtrl(self, style=wx.TE_MULTILINE)
        self.ctrl = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER, size=(300, 25))

        self.IPC = IPC_Read(self.client, self.text, self.ctrl)
        sizer.Add(self.text, 5, wx.EXPAND)
        sizer.Add(self.ctrl, 0, wx.EXPAND)
        self.SetSizer(sizer)
        self.ctrl.Bind(wx.EVT_TEXT_ENTER, self.onSend)

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

            self.text.SetValue(t()+ data)
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


class IPC_Read(Thread):

    def __init__(self, client, text, ctrl):
        """Initialize"""
        Thread.__init__(self)
        self.client = client
        self.start()
        self.text = text
        self.ctrl = ctrl

    def run(self):
        while True:
            data = self.client.client.recv(1024)
            if not data: sys.exit(0)
            print "***************************************"
            print "Recv Encypted Broadcast:", data
            data = self.client.a.dec_str(data)
            type(data)
            print "Decrypting:", data
            self.text.SetValue(data)
            self.ctrl.SetValue("")

if __name__ == "__main__":
    app = wx.App(False)
    frame = MainFrame()
    frame.Show()
    app.MainLoop()
