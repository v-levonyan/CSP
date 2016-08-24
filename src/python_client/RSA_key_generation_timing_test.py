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

def test_RSA_key():
    
    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)
   
    registration(clientSock, 'DavidRSA', 'david')
    
    demand_services(clientSock)
    
    t0 = time.time()
    
    for i in range (0, 500):
	RSA_key(clientSock)
 	demand_services(clientSock)

        
    print 'time: ', time.time() - t0
    
    assert 1	


