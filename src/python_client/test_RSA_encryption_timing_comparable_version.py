import pytest
#from  client_main import reg_signin
import client
import hashlib
import os
import socket
import getpass
import sys
import time
from OpenSSL import SSL, crypto

SUCCESS = 777
FAILURE = -777

def setup_function(function):
    print ("Testing function: %s" % function.__name__)

def connection(clientSock, host = '127.0.0.1', port = 8888):

    clientSock.connect(host, port)
    rec = clientSock.recieveMessage()
 
def registration(clientSock, user_name, password):
   
    clientSock.sendMessage('0')
  
    clientSock.sendMessage(user_name)
    
    if int(clientSock.recieveMessage()) == 1:
	return FAILURE
   
    clientSock.sendMessage(password)
   
    clientSock.recieveMessage()#timeout = 1)
    
    return SUCCESS


def demand_services(clientSock):
      
      clientSock.sendMessage("CSP1.0://Get Services")

      while 1:
	  services = clientSock.recieveMessage()
	  if services == 'END':
	      break
	  else:
	      continue

def send_file(clientSock, file_name):
    
    try:
	f = open(file_name)
    except:
        print "Wrong file.\n"
        exit()
     
    for piece in clientSock.readInChunks(f, 15):
	    clientSock.sendMessage(piece)



def RSA_key(clientSock):
 
    seq = ('18', '2048')
    params = ':'.join(seq)
    
    clientSock.sendMessage(params)
    
    public_RSA = 'public_RSA' + '.txt'
	
    fd = open(public_RSA,'w+')
	
    while 1: 
	RSA_pub_key = clientSock.recieveMessage(-1)
		
	if RSA_pub_key != "END":
	    fd.write(RSA_pub_key)
	else:
	    fd.close()
	    break   	
	
    RSA_private_key_ID = clientSock.recieveMessage(-1)
	    
    print 'RSA public key file is in your current directory with name ',  public_RSA
    
    return RSA_private_key_ID

def RSA_encryption(clientSock):
    
    seq = ('19', '-1')
    params = ':'.join(seq)
	
    clientSock.sendMessage(params)
    send_file(clientSock, '/home/davidt/workspace/CSP/src/python_client/RSA_test_file')
  
    clientSock.sendMessage('0')
	
    send_file(clientSock, '/home/davidt/workspace/CSP/src/python_client/public_RSA.txt')	
    
    clientSock.sendMessage('##END##')

    RSA_encrypted  = clientSock.recieveMessage(-1)	
    RSA_private_ID = clientSock.recieveMessage(-1)
	 
def test_RSA_encryption():
    
    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)
   
    registration(clientSock, 'David', 'david')
    
    demand_services(clientSock)
    
    RSA_key(clientSock)
    
    demand_services(clientSock)
    
    t0 = time.time()
    
    for i in range(1,90):
	RSA_encryption(clientSock)
	demand_services(clientSock)

    print time.time() - t0
    assert 0

