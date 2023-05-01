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
    print("        FINGER TABLE      ")
    print("--------------------------")
    print("My Address")
    print(f"   {MY_ADDR}")
    print(f"   {myKey}")
    print(f"Prev Address")
    print(f"   {PREV_PEER}")
    print(f"   {prevKey}")
    print(f"Next Address")
    print(f"   {NEXT_PEER}")
    print(f"   {nextKey}")
    print("--------------------------")
    i = 0
    for finger in FINGER_TABLE:
        if finger[0] != myKey and finger[0] != prevKey and finger[0] != nextKey:
            print(f"Finger {i}")
            print(f"   {finger[1]}")
            print(f"   {finger[0]}")
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
    print(f'Command: {command}')
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
        print("BEFORE KEY")
        key = recvMsg(sock, 56).decode()
        print("AFTER KEY")
        closest = closestToKey(key)
        print(f'closest: {closest}')
        print(f'addr: {MY_ADDR}')
        if closest == MY_ADDR:
            print("Sending first ok")
            sock.send("OK".encode())
            recvFile(key, sock, "")
            print("Sending second ok")
            sock.send("OK".encode())

        else:
            print("Sending FU")
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
    
#sends to prev that a user is leaving then transfers correct files
def leave():
    msg = "TIME_2_SPLIT"
    #Shuts down the system if only one person is in it
    if MY_ADDR == PREV_PEER:
        print("Goodbye")
        exit(0)

    else:
        #gets our hash area to transfer files from
        key = getHashKey(MY_ADDR)

        #gets prev peers IP and port then connects to them and send the TIME_TO_SPLIT code
        prevIP, prevPort = PREV_PEER.split(":")
        prevSock = socket(AF_INET, SOCK_STREAM)
        prevSock.connect( (prevIP, int(prevPort)))
        prevSock.send(msg.encode())
        
        #Transfers files to prev peer that we owned
        transferFiles(prevSock, key, "")

        #send to prev our next to allow them to update their next
        prevSock.send((f'{NEXT_PEER}\n').encode())

        #recieve acknowledgement. If OK then exit otherwise do nothing
        ack = recvMsg(prevSock, 2).decode()
        if ack == "OK":
            prevSock.close()
            print("Goodbye")
            exit(0)

#updates the prev peer and next peer on who their next and prev should be after someone leaves or joins
def updatePeer(peer):
    #get peers IP and Port, connect to them, then send update code
    IP, Port = peer.split(":")
    Port = int(Port)
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((IP, Port))
    sock.send("UPDATE_PEER_".encode())

    #Send our address to the peer so they know who next/prev will be
    sendUserID(MY_ADDR.split(":")[0], int(MY_ADDR.split(":")[1]), sock)

    #recieve acknowledgement and close the socket to the peer
    ack = recvMsg(sock, 2).decode()
    sock.close()
    return ack

#gets data of specified filename    
def getData(fileName):
    msg = "GET_DATA_NOW"

    #gets hash of the filename then checks if we already own it or not
    key = getHashKey(fileName)
    if containedLocal(key) == True:
        shutil.copy(f"dht/{key}", key)
    else:
        #if we do not own it check if it exists
        if contains(fileName):
            #connect to the closest peer to that file, ask for the data.
            closestAddr = closestToKey(key)
            closest = closestAddr.split(":")
            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect((closest[0], int(closest[1])))
            sock.send(msg.encode())
            sock.send(key.encode())
            ack = recvMsg(sock, 2).decode()
            #recieve acknowledgemnet, if failure ask for data again
            if ack == "FU":
                getData(fileName)
            else:
                #recieve second acknowedgment if file exists or not or if it was recieved successfully
                ack = recvMsg(sock, 2).decode()
                if ack == "FU":
                    print(f"{fileName} does not exist anymore.")
                else:
                    recvFile(key, sock, "local")
                    print(f"Received {fileName}")
            sock.close()
        else:
            print(f"{fileName} does not exist anymore.")

#check if a given file exists within the dht
def contains(fileName):
    msg = "CONTAIN_FILE"

    #get file hash
    key = getHashKey(fileName)
    #check if file is in our space
    if containedLocal(key) == True:
        print(f'You own {fileName}.')
        return True

    else:
        #find out who we know that is closest to the file.
        askAddr = closestToKey(key)

        #Call closest peer on that closest to get who is closest to the file
        recvAddr = closestPeer(askAddr, key)

        #once we have gotten closest peer to file connect to them and send the contains to them
        if askAddr == recvAddr:
            askAddr = askAddr.split(":")
            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect((askAddr[0], int(askAddr[1])))
            sock.send(msg.encode())
            sock.send(key.encode())

            #recieve acknowedgment, if they dont have the file then run contains again
            ack = recvMsg(sock, 2).decode()
            if ack == "FU":
                contains(fileName)

            #if file does not exist in dht then print fail
            ack = recvMsg(sock, 2).decode()
            if ack == "FU":
                print(f"{fileName} was not found")
                return False

            else:
                print(f"{fileName} found")
                return True

#inserts a file into the dht
def insert(fileName):

    #checks if file is in our local directory
    files = os.listdir('.')
    if fileName not in files:
        print(f"You don't have a file named {fileName}")
        return

    #find who is closest to where the file should be hashed
    msg = "INSERT_FILE!"
    key = getHashKey(fileName)
    storeAddr = closestToKey(key)

    #if our location is closest then store locally in our dht 
    if storeAddr == MY_ADDR:
        print(f"Storing {fileName} locally")
        shutil.copy(fileName, f"dht/{key}")

    else:
        #get closest peer and connect to them. Send msg to insert. Receive if they are ready to insert a file
        closest = closestPeer(storeAddr, key)
        closest = closest.split(":")
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((closest[0], int(closest[1])))
        sock.send(msg.encode())
        ack = recvMsg(sock, 2).decode()

        #if fail try again
        if ack == "FU":
            insert(fileName)

        else:
            #get byte array of the contents of the file and the size
            fileBytes = readFile(fileName, "local")
            sz = len(fileBytes)
            sz = str(sz) + '\n'

            #send size and each byte to the person that will be inserting
            sock.send(sz.encode())
            for byte in fileBytes:
                sock.send(byte)

            #Receive acknowledgement on if insert was successful or not. Otherwise, try again.
            ack = recvMsg(sock, 2).decode()
            if ack == "OK":
                sock.close()
                print(f"{fileName} inserted successfully")
            else:
                insert(fileName)
       
#tells a peer to delete a given file 
def delete(fileName):
    msg = "DELETE_FILE!"
    key = getHashKey(fileName)

    #Check if we own the file. If so, delete it.   
    if containedLocal(key) == True:
        os.remove("dht/"+key)
        print(f"Removing {fileName} locally")

    else:
        #if file exists then connect whoever is closest to that file (the owner)
        if contains(fileName):
            storeAddr = closestToKey(key)
            closest = closestPeer(storeAddr, key)
            closest = closest.split(":")
            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect((closest[0], int(closest[1])))

            #send to delete it 
            sock.send(msg.encode())
            sock.send(key.encode())
            ack = recvMsg(sock, 2).decode()

            #if failure then try again. Otherwise, print it worked or that it was already deleted.
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

#Creates offsets between each finger
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

#updates finger table according to finger list
def updateFingerTable():
    global FINGER_TABLE, FINGERS
    FINGER_TABLE = FINGERS
    FINGER_TABLE.sort()
    printFingers()

#Updates fingers according to passed in address
def updateFingers(peerAddr):
    global FINGERS
    peerKey = getHashKey(peerAddr)
    #for each finger, check if they are higher or lower in the current offset (hashed area)
    for i in range(len(FINGERS)):
        lastFinger = FINGERS[-1][0]
        currFinger = FINGERS[i][0]
        prevFinger = FINGERS[i-1][0]

        currFingKey = getHashKey(FINGERS[i][1])
        if i == 0 and lastFinger > currFinger:
            if currFingKey > lastFinger or currFingKey < currFinger:
                if currFingKey > lastFinger:
                    if peerKey < currFinger or peerKey > currFingKey:
                        #update curr finger with new peer
                        FINGERS[i] = (currFinger, peerAddr)

                elif peerKey > currFingKey and peerKey < currFinger:
                    #update curr finger with new peer
                    FINGERS[i] = (currFinger, peerAddr)

            elif peerKey > currFingKey or peerKey < currFinger:
                #update curr finger with new peer
                FINGERS[i] = (currFinger, peerAddr)

        elif i > 0 and prevFinger > currFinger:
            if currFingKey > prevFinger or currFingKey < currFinger:
                if currFingKey > prevFinger:
                    if peerKey < currFinger or peerKey > currFingKey:
                        #update curr finger with new peer
                        FINGERS[i] = (currFinger, peerAddr)

                elif peerKey > currFingKey and peerKey < currFinger:
                    #update curr finger with new peer
                    FINGERS[i] = (currFinger, peerAddr)

            elif peerKey > currFingKey or peerKey < currFinger:
                #update curr finger with new peer
                FINGERS[i] = (currFinger, peerAddr)

        else:
            if currFingKey < currFinger and currFingKey > prevFinger:
                if peerKey < currFinger and peerKey > currFingKey:
                    #update curr finger with new peer
                    FINGERS[i] = (currFinger, peerAddr)

            else:
                if currFingKey > currFinger:
                    if peerKey > currFingKey or peerKey < currFinger:
                        #update curr finger with new peer
                        FINGERS[i] = (currFinger, peerAddr)

                else:
                    if peerKey > currFingKey and peerKey < currFinger:
                        #update curr finger with new peer
                        FINGERS[i] = (currFinger, peerAddr)

#sets fingers according to whos in the dht to create initial finger table
def setFingers(Addr):
    global FINGERS
    FINGERS = []
    offsets = createFingerOffsets(MY_ADDR)
    #Finds person closest to each offset and adds them to finger list
    for finger in offsets:
        recvAddress = closestPeer(Addr, finger)
        FINGERS.append((finger, recvAddress))

    updateFingerTable()

#removes someone out of a finger table
def removeFromFingerTable(addr):
    global FINGERS
    #checks if finger is equal to given address. If so, remove finger and change address to our address
    for i in range(len(FINGERS)):
        if FINGERS[i][1] == addr:
            FINGERS[i] = (FINGERS[i][0], MY_ADDR)

    updateFingerTable()

#Overwrite old finger table and makes a new one
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

#checks if we own file
def containedLocal(fileHashPos):
    if fileHashPos in getMyFiles():
        return True
    return False

#sets up dht when someone starts up a new one
def startNewSystem():
    global PREV_PEER, NEXT_PEER, FINGER_TABLE, FINGERS
    NEXT_PEER = MY_ADDR
    PREV_PEER = MY_ADDR
    
    #Creates finger table populated with our address
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

    #checks if user has correct arguments
    if len(sys.argv) < 1 or len(sys.argv) > 3 or len(sys.argv) == 2:
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
    # Check for repository to store files. If it already exists then reset it.
    folder = Path('./dht')
    if not folder.exists():
        folder.mkdir(parents=True, exist_ok=True)
    else:
        shutil.rmtree(folder)
        folder.mkdir(parents=True, exist_ok=True)

    #if no args given then start new system. Otherwise, join someone
    if len(sys.argv) == 1:
        startNewSystem()
    elif len(sys.argv) == 3:
        IP = sys.argv[1]
        port = sys.argv[2]
        join(IP, port)
   
    #Create thread to go into the listen function then print out finger table 
    listenThread = threading.Thread(target=listen, args=(listener,),daemon=True).start()
    printFingers()

    #loop to keep checking for commands
    running = True
    while running:
        line = input('> ')
        command = line.split()[0].lower()
        
        #If command is vaild then do that command
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
