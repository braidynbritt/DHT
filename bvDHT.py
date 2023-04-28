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
    print("Prev Address")
    print("   {}".format(PREV_PEER))
    print("   {}".format(prevKey))
    print("Next Address")
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
def getline(conn):
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
        print(msg)
        temp = sock.recv(numBytes- len(msg))
        if len(temp) == 0:
            break
        msg += temp

    print(f"final msg: {msg}")
    return msg

def readFile(fileHashPos, dest):
    if dest == "local":
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
    print("send File")
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
    
def getMyFiles():
    fileKeys = os.listdir('./dht')
    return fileKeys

def transferFiles(sock, connectorHash, Type):
    print("Transfer")
    # Retreive files available for sending
    folder = Path("./dht")
    if not folder.exists():
        folder.mkdir(parents=True, exist_ok=True)
    # Retrieve our file hashes
    fileHashes = []
    print(f"{folder.iterdir}")
    for entry in folder.iterdir():
        print(f"i{entry}")
        if not entry.is_dir():
            fileHashes.append(entry.name)
    # Get number of files to send
    filesToSend = []
    prevHash = getHashKey(PREV_PEER)

    if Type == "JOIN":
        # Find which files to transfer considering wrap around
        if prevHash < connectorHash:
            for fileHash in fileHashes:
                if fileHash < prevHash or fileHash > connectorHash:
                    filesToSend.append(fileHash)
        # Find files when no wrap around
        else:
            for fileHash in fileHashes:
                if fileHash > connectorHash:
                    filesToSend.append(fileHash)
    else:
        # Add all files we own
        filesToSend = getMyFiles()

    # Send number of files followed by each file following protocol
    print(filesToSend)
    sz = len(filesToSend)
    sz = str(sz) + '\n'
    sock.send(sz.encode())
    for fileHash in filesToSend:
        fileBytes = readFile(fileHash, "")
        sendFile(fileHash, fileBytes, sock)

    return filesToSend


def deleteFiles(toDelete):
    for f in toDelete:
        try:
            os.remove(f"dht/{f}")
            print(f"Deleted {f}")
            return True
        except:
            print(f"File not deleted {f}")
            return False

def listen(listener):
    running = True
    while running:
        conn, addr = listener.accept()
        handleRequests(conn, addr)


#FIXME
def handleRequests(sock, connAddr):
    global PREV_PEER, NEXT_PEER
    command = recvMsg(sock, 12).decode()

###################FIXME######################
    if command == "JOIN_DHT_NOW":
        senderAddr = getline(sock)

        sock.send((f'{NEXT_PEER}\n').encode())

        files = transferFiles(sock, getHashKey(senderAddr),"JOIN")
        deleteFiles(files)
        NEXT_PEER = senderAddr

        

    elif command == "CLOSEST_PEER":
        key = recvMsg(sock, 56).decode()
        closest = closestToKey(key)
        closestIP, closestPort = closest.split(":")
        sendUserID(closestIP, closestPort, sock)
    elif command == "INSERT_FILE!":
        pass
    elif command == "DELETE_FILE!":
        pass
    elif command == "TIME_2_SPLIT":
        pass
    elif command == "CONTAIN_FILE":
        pass
    elif command == "GET_DATA_NOW":
        fileHashPos = recvAll(sock, 56)
        closest = cloesetToKey(fileHashPos)
        if closest == MY_ADDR:
            sock.send("OK".encode())
            if containedLocal(fileHashPos) == True:
                sock.send("OK".encode())
                fileBytes = rreadFile(fileHashPos, "")
                sendFile(fileHashPos, fileBytes, sock, "get")
            else:
                sock.send("FU".encode())
        else:
            sock.send("FU".encode())

    elif command == "UPDATE_PEER_":
        user = getline(sock)
        NEXT_PEER = user
        #update the finger table
        #will probably make a function for this
        updateFingers(PREV_PEER)

        updateFingerTable()

        sock.send("OK".encode())

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
        closestSock.connect((askAddrList[0], int(askAddrList[1])))

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
    port = int(port)
    closestSock = socket(AF_INET, SOCK_STREAM)
    print("Before connect")
    print(IP)
    print(port)
    closestSock.connect((IP, port))
    closestSock.send(("CLOSEST_PEER").encode())
    print("Sent command")
    key = getHashKey(MY_ADDR)
    closestSock.send(key.encode())

    closestAddr = getline(closestSock)
    print(closestAddr)
    IP, port = closestAddr.split(":")

    msg = "JOIN_DHT_NOW"
    closestSock.send(msg.encode())
    sendUserID(IP, port, closestSock)
    
    #receive our new next UserID
    print("before NEXT")
    NEXT_PEER = getline(closestSock)
    print("NEXT")
    PREV_PEER = closestAddr
    print("PREV")

    #FINGER_TABLE = []
    offsets = createFingerOffsets(MY_ADDR)

    for finger in offsets:
        FINGERS.append((finger, MY_ADDR))

    updateFingers(PREV_PEER)
    updateFingers(NEXT_PEER)

    updateFingerTable()

    printFingers()

    print("FINGERS!!!")
    if PREV_PEER != NEXT_PEER:
        setFingers(PREV_PEER)


    #receive the number of files we are taking
    numFiles = getline(closestSock)

    print(numFiles)
    numFiles = int(numFiles)

    if numFiles > 0:
        for i in range(numFiles):
            #recieve files hashedPosition
            print("before")
            fileHashPos = recvMsg(closestSock, 56).decode()
            print("after")
            print(fileHashPos)
            recvFile(fileHashPos, closestSock, "")


    closestSock.close()

    print("before next")
    nextIP, nextPort = NEXT_PEER.split(":")
    print(f'IP: {nextIP} Port: {nextPort}')
    nextPort = int(nextPort)
    nextSock = socket(AF_INET, SOCK_STREAM)
    nextSock.connect((nextIP, nextPort))
    print("Connected")
    nextSock.send(("UPDATE_PEER_").encode())
    sendUserID(nextIP, nextPort, nextSock)
    ack = getline(nextSock)
    nextSock.close()

    closestSock = socket(AF_INET, SOCK_STREAM)
    closestSock.connect((IP, port))

    if ack == "OK":
        closestSock.send("OK".encode())

    closestSock.close()

    print("JOINED")
    
    
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


def getData(fileName):
    msg = "GET_DATA_NOW"

    key = getHashKey(fileName)
    if containedLocal(key) == True:
        print(f"Copying {fileName} from dht to your local directory")
        shutil.copy(f"dht/{key}", key)
    else:
        if contains(fileName):
            print("The file is here")
            closestAddr = closestToKey(key)
            closest = closest.split(":")
            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect((closest[0], int(closest[1])))
            sock.send(msg.encode())

            sock.send(key.encode())
            ack = recvMsg(sock, 2)
            if ack == "FU":
                getData(fileName)
            else:
                ack = recvMsg(sock, 2)
                if ack == "FU":
                    print(f"{fileName} does not exist anymore.")
                else:
                    recvFile(sock, key, "local")
                    print(f"Received {fileName}")
        else:
            print(f"{fileName} does not exist anymore.")

    sock.close()


#FIXME
def contains():
    pass

#FIXME
def insert():
    pass

#FIXME
def delete():
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


def updateFingerTable():
    global FINGER_TABLE
    FINGER_TABLE = FINGERS
    FINGER_TABLE.append((getHashKey(MY_ADDR), MY_ADDR))
    FINGER_TABLE.append((getHashKey(NEXT_PEER), NEXT_PEER))
    FINGER_TABLE.append((getHashKey(PREV_PEER), PREV_PEER))
    FINGER_TABLE.sort()
    printLock.acquire()
    printFingers()
    printLock.release()


def updateFingers(peerAddr):
    global FINGERS
    peerKey = getHashKey(peerAddr)
    for i in range(len(FINGERS)):
        currFingKey = getHashKey(FINGERS[i][1])
        # i = 1 and wrap around
        if i == 0 and FINGERS[-1][0] > FINGERS[i][0]:
            # is current finger value in keyspace
            if currFingKey > FINGERS[-1][0] or currFingKey < FINGERS[i][0]:
                if currFingKey > FINGERS[-1][0]:
                    if peerKey < FINGERS[i][0] or peerKey > currFingKey:
                        FINGERS[i] = (FINGERS[i][0], peerAddr)
                elif peerKey > currFingKey and peerKey < FINGERS[i][0]:
                    FINGERS[i] = (FINGERS[i][0], peerAddr)
            elif peerKey > currFingKey or peerKey < FINGERS[i][0]:
                FINGERS[i] = (FINGERS[i][0], peerAddr)
        # i != 1 and wrap around
        elif i > 0 and FINGERS[i-1][0] > FINGERS[i][0]:
            # is current finger value in keyspace
            if currFingKey > FINGERS[i-1][0] or currFingKey < FINGERS[i][0]:
                if currFingKey > FINGERS[i-1][0]:
                    if peerKey < FINGERS[i][0] or peerKey > currFingKey:
                        FINGERS[i] = (FINGERS[i][0], peerAddr)
                elif peerKey > currFingKey and peerKey < FINGERS[i][0]:
                    FINGERS[i] = (FINGERS[i][0], peerAddr)
            elif peerKey > currFingKey or peerKey < FINGERS[i][0]:
                FINGERS[i] = (FINGERS[i][0], peerAddr)
        # any i no wrap around
        else:
            # is current finger value in keyspace
            if currFingKey < FINGERS[i][0] and currFingKey > FINGERS[i-1][0]:
                if peerKey < FINGERS[i][0] and peerKey > currFingKey:
                    FINGERS[i] = (FINGERS[i][0], peerAddr)
            else:
                if currFingKey > FINGERS[i][0]:
                    if peerKey > currFingKey or peerKey < FINGERS[i][0]:
                        FINGERS[i] = (FINGERS[i][0], peerAddr)
                else:
                    if peerKey > currFingKey and peerKey < FINGERS[i][0]:
                        FINGERS[i] = (FINGERS[i][0], peerAddr)

def setFingers(Addr):
    global FINGERS

    FINGERS = []
    offsets = createFingerOffsets(MY_ADDR)
    for finger in offsets:
        recvAddress = closestPeer(Addr, finger)
        FINGERS.append((finger, recvAddress))
    updateFingerTable()

def removeFromFingerTable(addr):
    global FINGERS
    for i in range(len(FINGERS)):
        if FINGERS[i][1] == addr:
            FINGERS[i] = (FINGERS[i][0], MY_ADDR)

    updateFingerTable()

# Finds out who we know that is closest to the key
def closestToKey(key):
    for i in range(len(FINGER_TABLE) - 1):
        if key > FINGER_TABLE[i][0] and key < FINGER_TABLE[i+1][0]:
            return FINGER_TABLE[i][1]

    return FINGER_TABLE[-1][1]

def containedLoacl(fileHashPos):
    if fileHash in getMyFiles():
        return True
    return False


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
    if len(sys.argv) < 1 or len(sys.argv) > 3:
        print("USAGE: <program name> <IP> <PORT> ")
        print("OR")
        print("USAGE: <program name>")
        exit()

# Set up listener
    listener = socket(AF_INET, SOCK_STREAM)
    listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listener.bind(('', 0))
    listeningPort = listener.getsockname()[1]
    listener.listen(4)

    #Set my address
    #host = gethostname()
    ip = gethostbyname(gethostname())
    MY_ADDR = f"{ip}:{listeningPort}"
    print(f"Our address: {MY_ADDR}")

    # Check for repository to store files
    folder = Path('./dht')
    if not folder.exists():
        folder.mkdir(parents=True, exist_ok=True)
#    else:
#        shutil.rmtree(folder)
#        folder.mkdir(parents=True, exist_ok=True)

    if len(sys.argv) == 1:
        startNewSystem()
    elif len(sys.argv) == 3:
        IP = sys.argv[1]
        port = sys.argv[2]
        join(IP, port)
    else:
        print("Wrong amount of arguments were passed")
    
    print("Before listen thread")
    listenThread = threading.Thread(target=listen, args=(listener,),daemon=True).start()
    print("after listen thread")
    
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
            try:
                fileName = line.split()[1]
            except:
                print("Need to include a file name")
                continue
            if command == "get":
                getData(fileName)
            elif command == "contains":
                contains(fileName)
            elif command == "insert":
                insert(fileName)
            elif command == "delete":
                delete(fileName)
