#!/usr/bin/python

import socket
import os
from OpenSSL import SSL, crypto

dir = os.curdir

def verify_cb(conn, cert, errnum, depth, ok):
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    print'\n---------------------------------Certificate information---------------------------------\n'
    print'Common   name:  ', commonname + '\n'
    print'Country  name:  ', certsubject.countryName + '\n'
    print'Locality Name:  ', certsubject.localityName + '\n'
    print'Email Address:  ', certsubject.emailAddress + '\n'
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
    MSGLEN = 1024
    
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

    def sendFile(self, inputFile, hashOrEnc = 0):
	print "File is being sent ...\n"
        if hashOrEnc == 0:
	   chunkSize = 100
	else:
	   chunkSize = 128
	try:
	    f = open(inputFile)
	except:
	    print "Specified file doesn't exist\n"
	    exit()
	
        for piece in self.readInChunks(f, chunkSize):
            self.sendMessage(piece)

    def getFile(self):        
        inputFile = raw_input("Enter the path of the file: ")
        return inputFile
    
    def get_sha1_string(self):
	return 1

    def get_sha1_file(self, num):
        f = self.getFile()
        fileSize = os.path.getsize(f)

        seq = ("1", str(fileSize))

        params = ':'.join(seq)
        
        print "sending parameters: ", params

        self.sendMessage(params)
        self.sendFile(f)
        result = self.recieveMessage()
        return result
    
    def symmetric_key(self,num):
	
	CorrespondingKey = { '3' : '7', '4' : '21', '5' : '16', '6' : '24', '7' : '32' }
	size = CorrespondingKey.get(num)
	print size,'-', num

	seq = (num, size)
	params = ':'.join(seq)
	
	print "sending parameters: ", params 
        
	self.sendMessage(params)
	result = self.recieveMessage()
	return result
    
    def AES_encryption(self, num):
		
	CorrespondingKey = { '10' : '128', '11' : '192', '12' : '256' }
	size = CorrespondingKey.get(num)
	
	message = 'AESencr_decr:' + str(size)

	self.sendMessage(message)
	rec_message = self.recieveMessage();

	if int(rec_message) == -1:
	   print "First order corresponding key\n"	
	   return -1

        filename = raw_input("Input filename to encrypt\n... ")
	
	fileSize = os.path.getsize(filename)

	self.sendMessage(str(fileSize))

	self.sendFile(str(filename),1)
        
	encrypted_file_name = 'encrypted_' + filename
	index_of_slash = encrypted_file_name.rfind('/')
        
	encr_name = encrypted_file_name[0:10] + encrypted_file_name[index_of_slash+1 : len(encrypted_file_name)]

	print 'encr name: ', encr_name, '\n'
	
	fd = open(encr_name,'w+')
	
	#f_size = self.recieveMessage()
	
	#print 'file size::: ', f_size
	
	while 1:
	  rec_m = self.recieveMessage(fd)
	 
	  if rec_m == 'END' :
	     print 'Encrypted file received \nIt is in your current directory with name ', encr_name,  '\n'
	     return -1
     
	   rec_m = self.recieveMessage()
	   print rec_m
	return 0
    
    def DES_encryption(self, key_size):
	return 1

    def recieveMessage(self, fd = -1):

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
	   # print ' Received message ', receivedMessage
	    if fd != -1:
		fd.write(receivedMessage)
	except SSL.ZeroReturnError:
	    print 'Server disconnected '
	    exit()
	
	return receivedMessage 

    def shutDownAndClose(self):
        self.sock.shutdown()
	self.sock.close()

    def byteToHex(self, byteStr):
	return ''.join( [ "%01X " % ord( x ) for x in byteStr ] ).strip()

#if __name__ == "__main__":
#   clientSock = clientSocket()
#    clientSock.connect("127.0.0.1", 8888)

