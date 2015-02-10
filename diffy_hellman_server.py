
import sys
import os
import socket
import SocketServer
import threading
import chilkat

def main():
    if (len(sys.argv) < 2):
        print 'Usage: python server.py port <port>\n'
        return -1
    else:
        Server(sys.argv[1]) 
    return 0


def Server(port):
    print "Server StartUP"
    # dhServer = chilkat.CkDh()
    #  Unlock the component once at program startup...
    # success = dhServer.UnlockComponent("Anything for 30-day trial")
    # if (success != True):
    #     print(dhServer.lastErrorText())
    #     sys.exit()

    # print "Generating Prime"
    # G = dhServer.get_G()
    # print G
    # status = dhServer.GenPG(1024, G)
    # print status
    # print dhServer.get_P()
    # print "here"


    dhBob = chilkat.CkDh()
    #  Unlock the component once at program startup...
    success = dhBob.UnlockComponent("Anything for 30-day trial")
    if (success != True):
        print(dhBob.lastErrorText())
        sys.exit()

    #  Bob will choose to use the 2nd of our 8 pre-chosen safe primes.
    #  It is the Prime for the 2nd Oakley Group (RFC 2409) --
    #  1024-bit MODP Group.  Generator is 2.
    #  The prime is: 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }
    dhBob.UseKnownPrime(2)
    p = dhBob.p()
    g = dhBob.get_G()

    # print p
    # print type(p)
    # print g
    # print type(g)



    host = '127.0.0.1'
    port = int(port)

    listenSocket = chilkat.CkSocket()
    success = listenSocket.UnlockComponent("T12302015Socket_3eA2KAG9IRAU")
    if (success != True):
        print(listenSocket.lastErrorText()) 
        sys.exit()

    # allow resuse of the port/socket
    # server.bind((host, port))
    # server.listen(5)
    success = listenSocket.BindAndListen(port,25)
    if (success != True):
        print(listenSocket.lastErrorText())
        sys.exit()

    
    # # blocking call to accept()
    # print 'Waiting for partner to join conversation...\n'
    # (conn, client_addr) = server.accept()
    # print 'Client connected: ', client_addr[0]
    connectedSocket = listenSocket.AcceptNextConnection(200000)
    if (connectedSocket == None ):
        print(listenSocket.lastErrorText())
        sys.exit()
    
    
    success = connectedSocket.SendString(p)
    if (success != True):
          print(conn.lastErrorText())
          sys.exit()


    success = connectedSocket.SendCount(g)
    if (success != True):
          print(conn.lastErrorText())
          sys.exit()         

    eBob = dhBob.createE(256)



    eAlice = connectedSocket.receiveString()
    if (p == None ):
        print(connectedSocket.lastErrorText())
        sys.exit()


    connectedSocket.SendString(eBob)



    kBob = dhBob.findK(eAlice)

    print "key"
    print kBob



    print "Server Shutdown"
    listenSocket.Close(20000)


# Entry point
if __name__ == "__main__":
    sys.exit(main())






