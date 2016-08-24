#!/usr/bin/python

import socket
import os
import getpass
import time 

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
	    print "Wrong file.\n"
	    return -2

	print 'File is being sent ...\n'
        for piece in self.readInChunks(f, chunkSize):
	    self.sendMessage(piece)
	
	print 'File sent.\n'

    def getFile(self):        
        inputFile = raw_input("Enter the path of the file: ")
        return inputFile
    
    def get_sha1_string(self, num, aux = 0):
	return 1

    def get_sha1_file(self, num, aux = 0):
        
	while 1:
	    f = self.getFile()
	    try:
		fileSize = os.path.getsize(f)
		
		if not os.path.isfile(f):
		    print 'Specified file is not a regular file!'
		    continue
	    except:
		print "Specified file doesn't exist.\n"
		continue
	    break
        
	seq = (num, str(fileSize))
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

	public_RSA = 'public_RSA' + '.txt'
	
	fd = open(public_RSA,'w+')
	
	while 1:
	    RSA_pub_key = self.recieveMessage(-1)
		
	    if RSA_pub_key != "END":
		fd.write(RSA_pub_key)
	    else:
		fd.close()
		break   	
	
	RSA_private_key_ID = self.recieveMessage(-1)
	    
	os.rename(public_RSA, public_RSA + str(RSA_private_key_ID))

	print '\nRSA public key file is in your current directory with name ',  public_RSA +str(RSA_private_key_ID), '\n'
	print 'RSA private key ID: ', RSA_private_key_ID, '\n'

	return 1
   
    def check_RSA_encrypted_file(self, filename):
	f = open(filename)
	
	if os.path.getsize(filename) != 426 or f.readline() != '-----BEGIN RSA PUBLIC KEY-----\n':
	    return -1
	return 0
    	
    def RSA_encryption(self, num, aux = 0):
	seq = (num, '-1')
	params = ':'.join(seq)
	
	self.sendMessage(params)
	
	while 1:
	    message = raw_input('Enter the message to encrypt(no more than 200 symbols)\n>>> ')
	    if message == '' or len(message) >= 200:
		continue
	    else:
		self.sendMessage(message)   
		break

	pub_key = raw_input('Enter the public RSA key pathname.\n>>> ')
	
	while 1:
	    try:
		f = open(pub_key)
	    except:
		print "Specified file doesn't exist.\n"
		self.sendMessage('1') #Specified file doesn't exist
		return 
	    if self.check_RSA_encrypted_file(pub_key) == -1:
		self.sendMessage('1') 
		print 'Wrong file.\n'
		return
	    break

	self.sendMessage('0')
	
	self.sendFile(pub_key)	
	self.sendMessage('##END##')

	RSA_encrypted = self.recieveMessage(-1)	
	RSA_private_ID = self.recieveMessage(-1)
	
	RSA_encrypted_file = 'RSA_encrypted.txt' + RSA_private_ID
	
	fd = open(RSA_encrypted_file,'w+')
	fd.write(RSA_encrypted) 
        	
	print 'RSA encryption done. Encrypted file is in your current directory with name ',RSA_encrypted_file
	
	if RSA_private_ID != '0':
	    
	    print 'You should decrypt with RSA private key ID', RSA_private_ID
	
	return 1
    
    def RSA_decryption(self, num, aux = 0):
	
	seq = (num, '-1')
	params = ':'.join(seq)
	
	self.sendMessage(params)
	
	while 1:
	    RSA_private_ID = raw_input('Enter RSA private key ID: ')
	    if len(RSA_private_ID) > 9:
		continue
	    else:
		self.sendMessage(RSA_private_ID)
		break

	answer = self.recieveMessage()
	
	if int(answer) == -1:
	    print 'Wrong RSA private key ID'
	    return 1
    
	encrypted = raw_input('Enter the public RSA encrypted pathname.\n>>> ')
	
	try:
	    f = open(encrypted)
	except:
	    print "Specified file doesn't exist.\n"
	    self.sendMessage('1') #Specified file doesn't exist
	    return 
	
	self.sendMessage('0')
	self.sendFile(encrypted)	
	self.sendMessage('##END##')
        
	ok = self.recieveMessage()
	
	if int(ok) == -1:
	    print ' RSA decryption failed, it may ba caused by specifing wrong RSA private key ID.\n'
	    return 
	
	decrypted = self.recieveMessage()
	print 'decrypted: ', decrypted
    
    def EC_key_transmission(self, num, aux = 0):
	
	seq = (num, '-1')
	params = ':'.join(seq)
	
	self.sendMessage(params)
	
	if int(self.recieveMessage()) == -1:
	    print 'Error occured while EC processing, try order again' 
	    return

	EC_pub = self.recieveMessage()
	
	print 'Elliptic curve public point: ', EC_pub
	return

    def EC_get_shared_secret(self, num, aux = 0):
	
	seq = (num, '-1')
	params = ':'.join(seq)
	
	self.sendMessage(params)

	EC_pub_key = raw_input("Provide your EC public key: ")
	self.sendMessage(EC_pub_key)

	if int(self.recieveMessage()) == -1:
	    print 'Wrong EC public key!'
	    return 

	EC_peer_pub_key = raw_input("Provide your peer's EC public key: ")
	self.sendMessage(EC_peer_pub_key)
    	
	if int(self.recieveMessage()) == -1:
	    print "\nShared secret couldn't be set, it may be caused by providing wrong peer's public point!"
	    return 
	
	shared_secret = self.recieveMessage()
	
	print '\n\nNow you can use mutual shared secret as a symmetric secret key for further encryption/decryption.\nShared secret: ', self.byteToHex(shared_secret), '\n\n'
    
    def symmetric_key(self, num, aux = 0):
	
	CorrespondingKey = { '3' : '7', '4' : '21', '5' : '16', '6' : '24', '7' : '32' }
	size = CorrespondingKey.get(num)

	seq = (num, size)
	params = ':'.join(seq)
	
	self.sendMessage(params)
	result = self.recieveMessage()
	print 'Key ID: ', result
	return result
    
    def AES_encryption(self, AES_file, filename):
	chunkSize = 15
	self.sendMessage('0') 

	encrypted_file_name = 'encrypted_' + filename + '.txt'
	index_of_slash = encrypted_file_name.rfind('/')
        
	encr_name = encrypted_file_name[0:10] + encrypted_file_name[index_of_slash+1 : len(encrypted_file_name)]

	fd = open(encr_name,'w+')
	
	while 1:
	    piece = AES_file.read(chunkSize)
	
	    if not piece:
		self.sendMessage('##END##')
	    else:
		self.sendMessage(piece)
		
	    rec_m = self.recieveMessage()
	    if rec_m != "END":
		fd.write(rec_m)
	    else:
		fd.close()
		return encr_name

    def AES_decryption(self, AES_file, filename):
	chunkSize = 16 
	self.sendMessage("1")
	    
	decrypted_file_name = 'decrypted_' + filename
	index_of_slash = decrypted_file_name.rfind('/')
        
	decr_name = decrypted_file_name[0:10] + decrypted_file_name[index_of_slash+1 :len(decrypted_file_name)]

	fd = open(decr_name,'w+')
	
	while 1:
	    piece = AES_file.read(chunkSize)
	
	    if not piece:
		self.sendMessage('##END##')
	    else:
		self.sendMessage(piece)
		
	    rec_m = self.recieveMessage()
	    
	    if rec_m != "END":
		fd.write(rec_m)
	    else:
		fd.close()
		return decr_name 

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

	filename = raw_input("Input filename to encrypt/decrypt\n... ")
	    
	try:
	    AES_file = open(filename)
	except:
	    print 'Wrongfile!'
	    self.sendMessage('-1')
	    return
	
	self.sendMessage('0')
	
	if aux == 0: ## AES encryption
	    encr_name = self.AES_encryption(AES_file, filename) 
	    print 'Encrypted file received, it is in your current directory with name ', encr_name,  '\n'
	    return 0     	

	if aux == 1: ## AES decryption
	    decr_name = self.AES_decryption(AES_file, filename)
	    print 'Decrypted file received, it is in your current directory with name ',
	    decr_name,  '\n'
	    return 0     	


    def DES_encr_decr(self, key_size, aux = 0):
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

def get_service():
     
     while 1:
		try:
		    serviceId = input("Choose service: ")
		except NameError:
		    print ' Wrong order!\n'
		    continue	
		except SyntaxError:
		    print ' Wrong order!\n'
		    continue
	    	return serviceId	

def call_corresponding_service(serviceId, options, clientSock):
     
     while 1:  
	
	if serviceId < 0 or serviceId > 22:
	    print ' Wrong order!\n'
	    	
	if serviceId == 2 or serviceId == 8 or serviceId == 9 or serviceId == 13 or serviceId == 14:
	    print ' Your specified order now is not available, it will be available soon\n'    	

	if serviceId > 0 and serviceId <= 12 and serviceId != 2 and serviceId != 8 and serviceId != 9:
	    return options.get(serviceId)(str(serviceId),0)  #continue
	
	if serviceId > 14  and serviceId <= 22:
	    return options.get(serviceId)(str(serviceId),1)  #continue
    	
	serviceId = get_service()

