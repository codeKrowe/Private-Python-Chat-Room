
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
        Client(sys.argv[1]) 
    return 0



def Client(port):
    socket = chilkat.CkSocket()
    success = socket.UnlockComponent("T12302015Socket_3eA2KAG9IRAU")
    if (success != True):
        print(socket.lastErrorText())
        sys.exit()


    dhAlice = chilkat.CkDh()
    success = dhAlice.UnlockComponent("Anything for 30-day trial")
    if (success != True):
        print(dhAlice.lastErrorText())
        sys.exit()

    ssl = False
    maxWaitMillisec = 20000
    success = socket.Connect("localhost",int(port),ssl,maxWaitMillisec)
    if (success != True):
        print(socket.lastErrorText())
        sys.exit()

    socket.put_MaxReadIdleMs(10000)
    socket.put_MaxSendIdleMs(10000)

    # Recieve the Prime number
    p = socket.receiveString()
    if (p == None ):
        print(socket.lastErrorText())
        sys.exit()

    # Recieve the generator
    g = socket.ReceiveCount()
    if (p == None ):
        print(socket.lastErrorText())
        sys.exit()

    # print(p)
    # print "\ng\n"
    # print(g)

    # set them for use
    success = dhAlice.SetPG(p,g)
    if (success != True):
        print("P is not a safe prime")
        sys.exit()

    # Generate Alices "Public-ish Part"
    eAlice = dhAlice.createE(256)

    # send it
    success = socket.SendString(eAlice)
    if (success != True):
          print(socket.lastErrorText())
          sys.exit()   

    # recieve bobs
    eBob = socket.receiveString()

    # Generate the Shared Secret using Bobs and Alices parts
    kAlice = dhAlice.findK(eBob)
    print("Alice's shared secret (should be equal to Bob's)")
    print(kAlice)

    print "Client Shutdown"
    socket.Close(20000)




if __name__ == "__main__":
    sys.exit(main())