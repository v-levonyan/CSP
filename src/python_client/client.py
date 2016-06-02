#!/usr/bin/python

import socket

class clientSocket:

    errorMessage = "socket connection broken"
    MSGLEN = 100

    def __init__(self, sock=None):
        if sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock

    def connect(self, host, port):
        self.sock.connect((host, port))

    def sendMessage(self, msg):
        totalsent = 0
        while totalsent < len(msg):
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError(self.errorMessage)
            totalsent = totalsent + sent
            print "totalsent",totalsent


    def readInChunks(self, inputFile, chunkSize=100):
        while True:
            data = inputFile.read(chunkSize)
            if not data:
                break
            yield data

    def sendFile(self, inputFile):
        f = open(inputFile)
        for piece in self.readInChunks(f):
            self.sendMessage(piece)





    def recieveMessage(self):
        print "enter recv"
        chunks = []
        bytes_recd = 0
        while bytes_recd < self.MSGLEN:
            chunk = self.sock.recv(min(self.MSGLEN - bytes_recd, 2048))
            if chunk == '':
                raise RuntimeError(errorMessage)
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)
            print "return message"
            receivedMessage = ''.join(chunks)
            print receivedMessage
        return receivedMessage 

if __name__ == "__main__":
    clientSock = clientSocket()
    clientSock.connect("127.0.0.1", 8888)






