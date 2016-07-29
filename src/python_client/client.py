#!/usr/bin/python

import socket
import os
import getpass
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


    def readInChunks(self, inputFile, chunkSize=15):
        while True:
            data = inputFile.read(chunkSize)
            if not data:
                break
            yield data

    def sendFile(self, inputFile, hashOrEnc = 0):
	chunkSize = 100
	if hashOrEnc == 1: #encrypt
	   chunkSize = 15
	if hashOrEnc == 2:   #decrypt
	   chunkSize = 16
	try:
	    f = open(inputFile)
	except:
	    print "Specified file doesn't exist.\n"
	    return -2

	print 'File is being sent ...\n'
        for piece in self.readInChunks(f, chunkSize):
	    self.sendMessage(piece)

    def getFile(self):        
        inputFile = raw_input("Enter the path of the file: ")
        return inputFile
    
    def get_sha1_string(self):
	return 1

    def get_sha1_file(self, num, aux = 0):
        f = self.getFile()
	try:
	    fileSize = os.path.getsize(f)
	except:
	    print "Specified file doesn't exist.\n"
	    return -2
        seq = ("1", str(fileSize))

        params = ':'.join(seq)
        
	self.sendMessage(params)

	if self.sendFile(f) == -2:
	    return -2

	result = self.recieveMessage()
	
	print 'SHA1 : ',self.byteToHex(result)
        return self.byteToHex(result)
    
    def RSA_key(self, num, aux = 0):
	
	seq = (num, '2048')
	params = ':'.join(seq)

	self.sendMessage(params)
	#result = self.recieveMessage()
	
	#print result

	public_RSA = 'public_RSA' + '.txt'
	
#	encr_name = encrypted_file_name[0:10] + encrypted_file_name[index_of_slash+1 : len(encrypted_file_name)]

	fd = open(public_RSA,'w+')
	
	while 1:
	    rec_m = self.recieveMessage(-1)
		
	    if rec_m != "END":
		fd.write(rec_m)
	    else:
		fd.close()
		print 'RSA public key file, is in your current directory with name ', public_RSA,  '\n'
		break   	

	return 1
    
    def RSA_encryption(self, num, aux = 0):
	seq = (num, '-1')
	params = ':'.join(seq)
	
	self.sendMessage(params)
	message = raw_input('Enter the message to encrypt(no more than 200 symbols)\n>>> ')
	self.sendMessage(message)   

	pub_key = raw_input('Enter the public RSA key pathname (.pem format)\n>>> ')
	self.sendFile(pub_key)
	self.sendMessage('##END##')

    def symmetric_key(self,num, aux = 0):
	
	CorrespondingKey = { '3' : '7', '4' : '21', '5' : '16', '6' : '24', '7' : '32' }
	size = CorrespondingKey.get(num)

	seq = (num, size)
	params = ':'.join(seq)
	
	self.sendMessage(params)
	result = self.recieveMessage()
	print 'Key ID: ', result
	return result
    
    def AES_encr_decr(self, num, aux = 0):
		
	CorrespondingKey = { '10' : '128', '11' : '192', '12' : '256',  '15' : '128', '16' : '192', '17' : '256' }
	size = CorrespondingKey.get(num)
	
	message = 'AESencr_decr:' + str(size)

	self.sendMessage(message)

	key_id = raw_input('Enter the key id\n>>> ')
	
	print 'key id: ', key_id + '\n'
	self.sendMessage(key_id)

	rec_message = self.recieveMessage();

	if int(rec_message) == -1:
	    print "First order corresponding key\n"	
	    return -1

	if aux == 0: ## AES encryption
	    self.sendMessage("0") 
	    filename = raw_input("Input filename to encrypt\n... ")
	    try:
		fileSize = os.path.getsize(filename)
	    except OSError:
		print "Specified file doesn't exist!\n"
		self.sendMessage('-1')
		return -1
	    self.sendMessage(str(fileSize))

	    self.sendFile(str(filename),1)
        
	    encrypted_file_name = 'encrypted_' + filename + '.txt'
	    index_of_slash = encrypted_file_name.rfind('/')
        
	    encr_name = encrypted_file_name[0:10] + encrypted_file_name[index_of_slash+1 : len(encrypted_file_name)]

	    fd = open(encr_name,'w+')
	
	    while 1:
		rec_m = self.recieveMessage(-1)
		
		if rec_m != "END":
		    fd.write(rec_m)
		else:
		    fd.close()
		    print 'Encrypted file received, it is in your current directory with name ', encr_name,  '\n'
		    return -1     	

	    return -1
	if aux == 1: ## AES decryption
	    self.sendMessage("1")
	    filename = raw_input("Input filename to decrypt\n... ")
	    try:
		fileSize = os.path.getsize(filename)
	    except OSError:
		print "Specified file doesn't exist!\n"
		self.sendMessage('-1')
		return -1

	    self.sendMessage(str(fileSize))

	    self.sendFile(str(filename),2)
        
	    decrypted_file_name = 'decrypted_' + filename
	    index_of_slash = decrypted_file_name.rfind('/')
        
	    decr_name = decrypted_file_name[0:10] + decrypted_file_name[index_of_slash+1 :len(decrypted_file_name)]

	    fd = open(decr_name,'w+')
	
	    while 1:
		rec_m = self.recieveMessage(-1)
	 
		if rec_m != "END":
		    fd.write(rec_m)
		else:
		    fd.close()
		    print 'Decrypted file received, it is in your current directory with name ', decr_name,  '\n'
		    return -1     	

	    return -1

    def DES_encr_decr(self, key_size):
	return 1

    def recieveMessage(self, fd = -1):

	try:
            receivedMessage = self.sock.recv(self.MSGLEN)
	   # print ' Received message ', receivedMessage

	except SSL.ZeroReturnError:
	    print 'Server disconnected '
	    exit()
	
	return receivedMessage 

    def shutDownAndClose(self):
        self.sock.shutdown()
	self.sock.close()

    def byteToHex(self, byteStr):
	return ''.join( [ "%01X" % ord( x ) for x in byteStr ] ).strip()


def reg_signin():
    return raw_input ('Enter 0 for registration, 1 for sign in\n>>> ')

def getchar():
   
   #Returns a single character from standard input
    import tty, termios, sys
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    
    try:
	tty.setraw(sys.stdin.fileno())
	ch = sys.stdin.read(1)
    finally:
	termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
	return ch
				          
def check_username(username):
    if username == '':
	print 'Empty username!\n'
	return 1
    if len(username) > 19:
	print 'Long username!\n'
	return 2
    return 0

def check_password(password):
    if password == '':
	print 'Empty password!\n'
	return 1
    if len(password) > 19:
	print 'Long password!\n'
	return 2
    return 0

def registration(clientSock):
    user_name = raw_input('Choose a username.\n>>> ')
    
    if check_username(user_name) != 0:
	return 1
   
    clientSock.sendMessage(user_name)
    free_or_busy = clientSock.recieveMessage()
	
    if int(free_or_busy) == 1: # username is busy
	print 'Chosen username is busy!\n'
	return 1

    if int(free_or_busy) == 0: # username was free    
	while 1:
	    password = getpass.getpass('Choose a password.\n>>> ')
	    if check_password(password) != 0:
		continue
	    break
	
	clientSock.sendMessage(password)
	password_answer = clientSock.recieveMessage()
	return 0

def sign_up(clientSock):
    user_name = raw_input('Enter your username.\n>>> ')
    clientSock.sendMessage(user_name)
    
    password = getpass.getpass('Enter your password.\n>>> ')
    clientSock.sendMessage(password)
    answer = clientSock.recieveMessage()
    
    if answer == 'Right!':
	print 'You successfully signed up.\n'
	return 0
    
    if answer == 'Wrong!':
	print 'Wrong username or password!\n'
	return 1

def demand_services(clientSock):
    clientSock.sendMessage("CSP1.0://Get Services")
    
    print('Press any button to see services.')
    getchar()

    while 1:
	services = clientSock.recieveMessage()
	if services == 'END':
	    break
	else:
	    print services

def call_corresponding_service(serviceId, options, clientSock):
     
     if serviceId < 0 or serviceId > 19:
	print 'Wrong order'
	return -2 #exit
     
     if serviceId == 2 or serviceId == 8 or serviceId == 9 or serviceId == 13 or serviceId == 14:
	print ' Your specified order now is not available, it will be available soon\n'
	return -2 #exit

     if serviceId > 0  and serviceId <= 12:
	return options.get(serviceId)(str(serviceId),0)  #continue
     if serviceId > 12  and serviceId <= 19:
	return options.get(serviceId)(str(serviceId),1)  #continue
 
    
#if __name__ == "__main__":
#   clientSock = clientSocket()
#    clientSock.connect("127.0.0.1", 8888)

