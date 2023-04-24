#!/usr/bin/env python3

from socket import*
import shutil
import hashlib
import sys
import threading
from pathlib import Path
import os


printLock = threading.Lock()

NEXT_PEER = ""
PREV_PEER = ""
MY_ADDR = ""

NUM_FINGERS = 5
FINGER_TABLE = []
FINGERS = []
COMMANDS = ['leave', 'get', 'contains', 'insert', 'remove']

listeningPort = None


# Function that helps to print out our finger table nicely
def printFingers():
    myKey = getHashKey(MY_ADDR)
    prevKey = getHashKey(PREV_PEER)
    nextKey = getHashKey(NEXT_PEER)
    print("--------------------------")
    print("-      FINGER TABLE      -")
    print("--------------------------")
    print("My Address")
    print("   {}".format(MY_ADDR))
    print("   {}".format(myKey))
    print("Pred Address")
    print("   {}".format(PREV_PEER))
    print("   {}".format(prevKey))
    print("Succ Address")
    print("   {}".format(NEXT_PEER))
    print("   {}".format(nextKey))
    i = 0
    for finger in FINGER_TABLE:
        if finger[0] != myKey and finger[0] != prevKey and finger[0] != nextKey:
            print("Finger {}".format(i))
            print("   {}".format(finger[1]))
            print("   {}".format(finger[0]))
            i = i+1


def sendUserID(IP, port, sock):
    userID = IP + ":" + str(port) + "\n"
    sock.send(userID.encode())

# Retrieves stuff until we hit a newline
def getLine(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        if ch == b'\n' or len(ch) == 0:
            break
        msg += ch
    return msg.decode()

def recvMsg(sock, numBytes):
    msg = b''
    while(len(msg) < numBytes):
        msg += sock.recv(numBytes - len(msg))
        if len(msg) == 0:
            break
    return msg

def readFile(fileHashPos, dest):
    if readFrom == "local":
        inFile = open(f"{fileHashPos}", "rb")
    else:
        inFile = open(f"dht/{fileHashPos}", "rb")

    fileBytes = []
    byte = inFile.read(1)
    while byte:
        fileBytes.append(byte)
        byte = inFile.read(1)
    return fileBytes

def sendFile(fileHashPos, fileBytes, sock):
    sz = len(fileBytes)
    sz = str(sz) + "\n"
    sock.send(fileHashPos.encode())
    sock.send(sz.encode())
    for byte in fileBytes:
        sock.send(byte)

def recvFile(fileHashPos, sock, dest):
    fileSize = getline(sock)
    fileSize = int(fileSize)
    
    data = recvMsg(sock, fileSize)

    if dest == "local":
        path = Path('./'+ fileHashPos)
    else:
        path = Path('./dht/' + fileHashPos)

    with open(path, 'wb') as outFile:
        outFile.write(data)
    

#FIXME
def transferFiles(sock, connectorHash, Type):
    pass


def listen(listener):
    listener.listen(4)
    running = True
    while running:
        threading.Thread(target=handleRequests, args=(listener.accept(),), daemon=True).start()

#FIXME
def handleRequests(connInfo):
    global PREV_PEER, NEXT_PEER
    sock, connAddr = connInfo
    command = getLine(sock)

###################FIXME######################
    if command == "JOIN_DHT_NOW":
        sock.send(NEXT_PEER.encode())
        sock.send(NUM_FILES.encode())
        for i in range(numFiles):
            fileHashPos = getHashKey(fileName)
            size = fileName.size
            sock.send(fileHashPos)
            sendFile(fileHashPos, size, sock)

        pass

    elif command == "CLOSEST_PEER":
        key = recvMsg(sock, 56).decode()
        closest = closestKey(key)
        sendUserID(closest, sock)

    pass

def getHashKey(key):
    hashedKey = hashlib.sha224(key.encode()).hexdigest()
    return hashedKey


def closestPeer(Addr, key):
    if Addr == MY_ADDR:
        return Addr
    askAddr = Addr
    recvAddr = None
    while askAddr != recvAddr:
        askAddrList = askAddr.split(":")
        closestSock = socket(AF_INET, SOCK_STREAM)
        closestSock.connect(askAddrList[0], int(askAddrList[1]))

        msg = "CLOSEST_PEER"
        closestSock.send(msg.encode())

        closestSock.send(key.encode())
        recvAddr = getline(closestSock)

        closestSock.close()
        if recvAddr == askAddr:
            return recvAddr
        askAddr = recvAddr

    return recvAddr


#FIXME
def join(IP, port):
    global PREV_PEER, NEXT_PEER, FINGERS
    closestSock = socket(AF_INET, SOCK_STREAM)
    closestSock.connect((IP, port))
    closestSock.send(("CLOSEST_PEER").encode())
    key = getHashKey(MY_ADDR)
    closestSock.send(key.encode())

    closestAddr = getline(closestSock)
    IP, port = closestAddr.split(":")

    msg = "JOIN_DHT_NOW"
    closestSock.send(msg.encode())
    sendUserID(IP, port, closestSock)
    
    #receive our new next UserID
    NEXT_PEER = getline()

    #receive the number of files we are taking
    numFiles = int(getline())

    for i in range(numFiles):
        #recieve files hashedPosition
        fileHashPos = recvMsg(joinSock, 56)
        recvFile(fileHashPos, joinSock, "")


    joinSock.send("OK\n".encode())

    
    
#This only works if there is only one person in the dht
#FIXME
def leave():
    msg = "TIME_2_SPLIT"
    #Shuts down the system if only one person is in it
    if MY_ADDR == PREV_PEER:
        print("Goodbye")
        exit(0)


    pass

#FIXME
def updatePeer():
    msg = "UPDATE_PEER_"
    pass

#FIXME
def getData():
    msg = "GET_DATA_NOW"
    pass

#FIXME
def Contains():
    pass

#FIXME
def Insert():
    pass

#FIXME
def Delete():
    pass

def createFingerOffsets(MY_ADDR):
    maxHash = "f" * 56
    maxHash = int(maxHash, 16)
    offset = int(maxHash / (NUM_FINGERS +1))

    key = hashlib.sha224(MY_ADDR.encode()).hexdigest()
    key = int(key,16)

    offsetList = []

    for i in range(NUM_FINGERS):
        if key+(offset *(i+1))> maxHash:
            off = hex((key+ (offset * (i+1))) - maxHash)[2:]
            if len(off) < 56:
                off = off +"0"
            offsetList.append(off)
        else:
            off = hex(key + (offset * (i+1)))[2:]
            if len(off) < 56:
                off = off +"0"
            offsetList.append(off)

    return offsetList


# Finds out who we know that is closest to the key
def closestToKey(key):
    for i in range(len(FINGER_TABLE) - 1):
        if key > FINGER_TABLE[i][0] and key < FINGER_TABLE[i+1][0]:
            return FINGER_TABLE[i][1]

    return FINGER_TABLE[-1][1]


def startNewSystem():
    global PREV_PEER, NEXT_PEER, FINGER_TABLE, FINGERS
    NEXT_PEER = MY_ADDR
    PREV_PEER = MY_ADDR

    fingers = createFingerOffsets(MY_ADDR)
    for i in range(NUM_FINGERS):
        FINGER_TABLE.append((fingers[i], MY_ADDR))
        FINGERS.append((fingers[i], MY_ADDR))

    for i in range(4):
        FINGER_TABLE.append((getHashKey(MY_ADDR), MY_ADDR))
    FINGER_TABLE.sort()
    FINGERS.sort()


#Main code
if __name__ == '__main__':
    if len(sys.argv) < 1 or len(sys.argv) >= 3:
        print("USAGE: <program name> <IP> <PORT> ")
        print("OR")
        print("USAGE: <program name>")
        exit()

# Set up listener
    listener = socket(AF_INET, SOCK_STREAM)
    listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listener.bind(('', 0))
    listeningPort = listener.getsockname()[1]

    #Set my address
    host = gethostname()
    ip = gethostbyname(host)
    MY_ADDR = f"{ip}:{listeningPort}"

    # Check for repository to store files
    folder = Path('./dht')
    if not folder.exists():
        folder.mkdir(parents=True, exist_ok=True)
    else:
        shutil.rmtree(folder)
        folder.mkdir(parents=True, exist_ok=True)

    if len(sys.argv) == 1:
        startNewSystem()
    elif len(sys.argv) == 3:
        IP = sys.argv[1]
        port = sys.argv[2]
        Join(IP, port)
    else:
        print("Wrong amount of arguments were passed")
    
    
    listenThread = threading.Thread(target=listen, args=(listener,),daemon=True).start()
    
    print(f"My key: {getHashKey(MY_ADDR)}")
    printLock.acquire()
    printFingers()
    printLock.release()



    running = True
    while running:
        line = input('> ')
        command = line.split()[0].lower()
        if command not in COMMANDS:
            print(f"{command} is not a valid command")
            continue
        elif command == "leave":
            leave()
            running = False
        else:
            #FIXME
            if command == "get":
                pass
            #FIXME
            elif command == "contains":
                pass
            #FIXME
            elif command == "insert":
                pass
            #FIXME
            elif command == "delete":
                pass
