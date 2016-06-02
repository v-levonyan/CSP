#!/usr/bin/python

from client import clientSocket

clientSock = clientSocket()
clientSock.connect("127.0.0.1", 8888)
while 1:
    message = clientSock.recieveMessage()
    print message
    clientSock.sendMessage("compute_file_hash")
    clientSock.sendFile("/home/vahanl/workspace/CSP/src/plain_texts/file.txt")
