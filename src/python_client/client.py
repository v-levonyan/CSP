#!/usr/bin/python

import socket
import os
from OpenSSL import SSL, crypto

dir = os.curdir

def verify_cb(conn, cert, errnum, depth, ok):
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    print '\n---------------------------------Certificate information---------------------------------\n'
    print'Common name:   ', commonname + '\n'
    print'Country name:  ', certsubject.countryName + '\n'
    print'LocalityName:  ', certsubject.localityName + '\n'
    print'Email Address: ', certsubject.emailAddress + '\n'
    print'------------------------------------------------------------------------------------------\n'
    return ok

class context:

   def __init__(self, method = SSL.SSLv23_METHOD, pr_key_file = 'mycert.pem', cert_file =
   'mycert.pem', CA_cert = 'CA.pem', call_back = verify_cb):
       self.ctx = SSL.Context(method)
       self.ctx.set_options(SSL.OP_NO_SSLv2)
       self.ctx.set_options(SSL.OP_NO_SSLv3)
       self.ctx.set_verify(SSL.VERIFY_PEER, call_back) # Demand a certificate
       self.ctx.use_privatekey_file(os.path.join(dir, pr_key_file))
       self.ctx.use_certificate_file(os.path.join(dir, cert_file))
       self.ctx.load_verify_locations(os.path.join(dir, CA_cert))

class clientSocket:

    errorMessage = "socket connection broken"
    MSGLEN = 100
    
    def __init__(self, ctx, sock=None):
        if sock is None:
	    self.sock = SSL.Connection(ctx.ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        else:
            self.sock = sock

    def connect(self, host, port):
        self.sock.connect((host, port))

    def sendMessage(self, msg):
        totalsent = 0
        while totalsent < len(msg):
            sent = self.sock.send(msg[totalsent:])
           # print "sending", sent, "bytes"
            if sent == 0:
                raise RuntimeError(self.errorMessage)
            totalsent = totalsent + sent
            # print "totalsent",totalsent


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

    def getFile(self):        
        inputFile = raw_input("Enter the path of the file: ")
        return inputFile
            
    def getSHA1File(self):
        f = self.getFile()
        fileSize = os.path.getsize(f)

        seq = ("1", str(fileSize))

        params = ':'.join(seq)
        
        print "sending parameters: ", params

        self.sendMessage(params)
        self.sendFile(f)
        result = self.recieveMessage()
        return result


    def recieveMessage(self):

#        print "enter recv"
#        chunks = []
#        bytes_recd = 0
#        while bytes_recd < self.MSGLEN:
#            print "loop"
#            chunk = self.sock.recv(min(self.MSGLEN - bytes_recd, 2048))
#            print "chunk: ", chunk
#            if chunk == '':
#                raise RuntimeError(errorMessage)
#            chunks.append(chunk)
#            bytes_recd = bytes_recd + len(chunk)
#            print "return message"
#            receivedMessage = ''.join(chunks)
#            print receivedMessage
	             
	try:
            receivedMessage = self.sock.recv(self.MSGLEN)
	except SSL.ZeroReturnError:
	    print 'Received message '
	
	return receivedMessage 

    def shutDownAndClose(self):
        self.sock.shutdown()
	self.sock.close()

    def byteToHex(self, byteStr):
	return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

#if __name__ == "__main__":
#   clientSock = clientSocket()
#    clientSock.connect("127.0.0.1", 8888)

