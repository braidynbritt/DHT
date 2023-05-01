#!/usr/bin/env python3

from socket import*
import shutil
import hashlib
import sys
import threading
from pathlib import Path
import os

NEXT_PEER = ""
PREV_PEER = ""
MY_ADDR = ""
MY_IP = ""
MY_PORT = 0

NUM_FINGERS = 5
FINGER_TABLE = []
FINGERS = []
COMMANDS = ['leave', 'get', 'contains', 'insert', 'delete']

listeningPort = None

def getLocalIPAddress():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

# Function that helps to print out our finger table nicely
def printFingers():
    myKey = getHashKey(MY_ADDR)
    prevKey = getHashKey(PREV_PEER)
    nextKey = getHashKey(NEXT_PEER)
    print("--------------------------")
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
    print("--------------------------")
    i = 0
    for finger in FINGER_TABLE:
        if finger[0] != myKey and finger[0] != prevKey and finger[0] != nextKey:
            print("Finger {}".format(i))
            print("   {}".format(finger[1]))
            print("   {}".format(finger[0]))
            i = i+1

def getHashKey(key):
    hashedKey = hashlib.sha224(key.encode()).hexdigest()
    return hashedKey

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
        temp = sock.recv(numBytes- len(msg))
        if len(temp) == 0:
            break

        msg += temp

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
    inFile.close()
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
    print("before data")
    data = recvMsg(sock, fileSize)
    print("after data")

    if dest == "local":
        path = Path('./'+ str(fileHashPos))
    else:
        path = Path('./dht/' + str(fileHashPos))

    with open(path, 'wb') as outFile:
        outFile.write(data)

def getMyFiles():
    fileKeys = os.listdir('./dht')
    return fileKeys

def transferFiles(sock, connectorHash, Type):
    # Retreive files available for sending
    folder = Path("./dht")
    if not folder.exists():
        folder.mkdir(parents=True, exist_ok=True)
    # Retrieve our file hashes
    fileHashes = []
    for entry in folder.iterdir():
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

def handleRequests(sock, connAddr):
    global PREV_PEER, NEXT_PEER
    command = recvMsg(sock, 12).decode()
    if command == "JOIN_DHT_NOW":
        senderAddr = getline(sock)
        sock.send((f'{NEXT_PEER}\n').encode())
        NEXT_PEER = senderAddr
        updateFingers(NEXT_PEER)
        updateFingerTable()
        files = transferFiles(sock, getHashKey(senderAddr),"JOIN")
        deleteFiles(files)

    elif command == "CLOSEST_PEER":
        key = recvMsg(sock, 56).decode()
        closest = closestToKey(key)
        closestIP, closestPort = closest.split(":")
        sendUserID(closestIP, closestPort, sock)

    elif command == "INSERT_FILE!":
        key = recvMsg(sock, 56).decode()
        closest = closestToKey(key)
        if closest == MY_ADDR:
            sock.send("OK".encode())
            recvFile(key, sock, "")
            sock.send("OK".encode())

        else:
            sock.send("FU".encode())

    elif command == "DELETE_FILE!":
        key = recvMsg(sock, 56).decode()
        closest = closestToKey(key)
        if closest == MY_ADDR:
            sock.send("OK".encode())
            if deleteFiles([key]) == True:
                sock.send("OK".encode())

            else:
                sock.send("FU".encode())
        else:
            sock.send("FU".encode())

    elif command == "TIME_2_SPLIT":
        fileNum = int(getline(sock))
        for i in range(0, fileNum):
            key = recvMsg(sock, 56).decode()
            recvFile(key, sock, "")

        newNext = getline(sock)
        if PREV_PEER == NEXT_PEER:
            resetFingerTable()

        else:
            NEXT_PEER = newNext
            removeFromFingerTable(NEXT_PEER)
            updatePeer(NEXT_PEER)
            
        sock.send("OK".encode())
        
    elif command == "CONTAIN_FILE":
        key = recvMsg(sock, 56).decode()
        closest = closestToKey(key)
        if closest == MY_ADDR:
            sock.send("OK".encode())
            if containedLocal(key) == True:
                sock.send("OK".encode())

            else:
                sock.send("FU".encode())
        else:
            sock.send("FU".encode())

    elif command == "GET_DATA_NOW":
        key = recvMsg(sock, 56).decode()
        closest = closestToKey(key)
        if closest == MY_ADDR:
            sock.send("OK".encode())

            if containedLocal(key) == True:
                sock.send("OK".encode())
                fileBytes = readFile(key, "")
                sendFile(key, fileBytes, sock)

            else:
                sock.send("FU".encode())
        else:
            sock.send("FU".encode())

    elif command == "UPDATE_PEER_":
        user = getline(sock)
        PREV_PEER = user
        if NEXT_PEER == MY_ADDR:
            NEXT_PEER = PREV_PEER

        updateFingers(PREV_PEER)
        updateFingerTable()
        sock.send("OK".encode())

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


def join(IP, port):
    global PREV_PEER, NEXT_PEER, FINGERS, MY_IP, MY_PORT
    port = int(port)
    addr = IP+":"+str(port)
    closestAddr = closestPeer(addr, getHashKey(addr))
    closestIP, closestPort = closestAddr.split(":")
    closestSock = socket(AF_INET, SOCK_STREAM)
    closestSock.connect((IP, port))
    msg = "JOIN_DHT_NOW"
    closestSock.send(msg.encode())
    sendUserID(MY_IP, MY_PORT, closestSock)
    
    #receive our new next UserID
    NEXT_PEER = getline(closestSock)
    PREV_PEER = closestAddr
    FINGER_TABLE = []
    offsets = createFingerOffsets(MY_ADDR)
    for finger in offsets:
        FINGERS.append((finger, MY_ADDR))

    updateFingers(PREV_PEER)
    updateFingers(NEXT_PEER)
    updateFingerTable()
    if PREV_PEER != NEXT_PEER:
        setFingers(PREV_PEER)

    #receive the number of files we are taking
    numFiles = getline(closestSock)
    numFiles = int(numFiles)
    if numFiles > 0:
        for i in range(numFiles):
            #recieve files hashedPosition
            fileHashPos = recvMsg(closestSock, 56).decode()
            recvFile(fileHashPos, closestSock, "")

    ack = updatePeer(NEXT_PEER)
    if ack == "OK":
        closestSock.send("OK".encode())

    closestSock.close()
    
#This only works if there is only one person in the dht
def leave():
    msg = "TIME_2_SPLIT"
    #Shuts down the system if only one person is in it
    if MY_ADDR == PREV_PEER:
        print("Goodbye")
        exit(0)
    else:
        key = getHashKey(MY_ADDR)
        prevIP, prevPort = PREV_PEER.split(":")
        prevSock = socket(AF_INET, SOCK_STREAM)
        prevSock.connect( (prevIP, int(prevPort)))
        prevSock.send(msg.encode())
        transferFiles(prevSock, key, "")
        prevSock.send((f'{NEXT_PEER}\n').encode())
        ack = recvMsg(prevSock, 2).decode()
        if ack == "OK":
            prevSock.close()
            print("Goodbye")
            exit(0)

def updatePeer(peer):
    IP, Port = peer.split(":")
    Port = int(Port)
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((IP, Port))
    sock.send("UPDATE_PEER_".encode())
    sendUserID(MY_ADDR.split(":")[0], int(MY_ADDR.split(":")[1]), sock)
    ack = recvMsg(sock, 2).decode()
    sock.close()
    return ack

def getData(fileName):
    msg = "GET_DATA_NOW"

    key = getHashKey(fileName)
    if containedLocal(key) == True:
        shutil.copy(f"dht/{key}", key)
    else:
        if contains(fileName):
            closestAddr = closestToKey(key)
            closest = closestAddr.split(":")
            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect((closest[0], int(closest[1])))
            sock.send(msg.encode())
            sock.send(key.encode())
            ack = recvMsg(sock, 2).decode()
            if ack == "FU":
                getData(fileName)
            else:
                ack = recvMsg(sock, 2).decode()
                if ack == "FU":
                    print(f"{fileName} does not exist anymore.")
                else:
                    recvFile(key, sock, "local")
                    print(f"Received {fileName}")
            sock.close()
        else:
            print(f"{fileName} does not exist anymore.")

def contains(fileName):
    msg = "CONTAIN_FILE"
    key = getHashKey(fileName)
    if containedLocal(key) == True:
        print(f"You own {fileName}")
        return True

    else:
        askAddr = closestToKey(key)
        recvAddr = closestPeer(askAddr, key)
        if askAddr == recvAddr:
            askAddr = askAddr.split(":")
            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect((askAddr[0], int(askAddr[1])))
            sock.send(msg.encode())
            sock.send(key.encode())
            ack = recvMsg(sock, 2).decode()
            if ack == "FU":
                contains(fileName)

            ack = recvMsg(sock, 2).decode()
            if ack == "FU":
                print(f"{fileName} was not found")
                return False

            else:
                print(f"{fileName} found")
                return True

def insert(fileName):
    files = os.listdir('.')
    if fileName not in files:
        print(f"You don't have a file named {fileName}")
        return

    msg = "INSERT_FILE!"
    key = getHashKey(fileName)
    storeAddr = closestToKey(key)
    if storeAddr == MY_ADDR:
        print(f"Storing {fileName} locally")
        shutil.copy(fileName, f"dht/{key}")

    else:
        closest = closestPeer(storeAddr, key)
        closest = closest.split(":")
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((closest[0], int(closest[1])))
        sock.send(msg.encode())
        sock.send(key.encode())
        ack = recvMsg(sock, 2).decode()
        if ack == "FU":
            insert(fileName)

        else:
            fileBytes = readFile(fileName, "local")
            sz = len(fileBytes)
            sz = str(sz) + '\n'
            sock.send(sz.encode())
            for byte in fileBytes:
                sock.send(byte)

            print("ack")
            ack = recvMsg(sock, 2).decode()
            if ack == "OK":
                sock.close()
                print(f"{fileName} inserted successfully")
            else:
                insert(fileName)
        



def delete(fileName):
    msg = "DELETE_FILE!"
    key = getHashKey(fileName)

    if containedLocal(key) == True:
        os.remove("dht/"+key)
        print(f"Removing {fileName} locally")

    else:
        if contains(fileName):
            storeAddr = closestToKey(key)
            closest = closestPeer(storeAddr, key)
            closest = closest.split(":")
            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect((closest[0], int(closest[1])))
            sock.send(msg.encode())
            sock.send(key.encode())
            ack = recvMsg(sock, 2).decode()

            if ack == "FU":
                delete(fileName)
            else:
                ack = recvMsg(sock, 2).decode()
                if ack == "FU":
                    print(f"{fileName} is already deleted")
                else:
                    print(f"{fileName} deleted")
        else:
            print(f"This dht system does not have {fileName}") 


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
    global FINGER_TABLE, FINGERS
    FINGER_TABLE = FINGERS
    FINGER_TABLE.sort()
    printFingers()

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

def resetFingerTable():
    global FINGERS, PREV_PEER, NEXT_PEER
    FINGERS = []
    offsets = createFingerOffsets(MY_ADDR)
    for i in range(len(offsets)):
        FINGERS.append((offsets[i], MY_ADDR))
    
    PREV_PEER = MY_ADDR
    NEXT_PEER = MY_ADDR
    updateFingerTable()

# Finds out who we know that is closest to the key
def closestToKey(key):
    for i in range(len(FINGER_TABLE) - 1):
        if key > FINGER_TABLE[i][0] and key < FINGER_TABLE[i+1][0]:
            return FINGER_TABLE[i][1]

    return FINGER_TABLE[-1][1]

def containedLocal(fileHashPos):
    if fileHashPos in getMyFiles():
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
    listener.listen(32)

    #Set my address
    ip = getLocalIPAddress()
    MY_IP = ip
    MY_PORT = listeningPort
    MY_ADDR = f'{ip}:{listeningPort}'
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
        join(IP, port)
    else:
        print("Wrong amount of arguments were passed")
    
    listenThread = threading.Thread(target=listen, args=(listener,),daemon=True).start()
    printFingers()

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
