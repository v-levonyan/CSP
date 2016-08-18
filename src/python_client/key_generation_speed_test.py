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

#      while 1:
          
#	  services = clientSock.recieveMessage()
  
#	  if services == 'END':
#              break
#          else:
#	      continue



def symmetric_key(clientSock, num):
 
         CorrespondingKey = { '3' : '7', '4' : '21', '5' : '16', '6' : '24', '7' : '32' }
         size = CorrespondingKey.get(num)
 
         seq = (num, size)
         params = ':'.join(seq)
 
         clientSock.sendMessage(params)
         return  clientSock.recieveMessage()
	
def get_key_ID(clientSock):
       	
    return symmetric_key(clientSock,'7')
     	

def test_AES_encryption():
    
    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)
   
    registration(clientSock, 'David', 'david')
    
    demand_services(clientSock)
    
    t0 = time.time()
    
    for i in range (0, 100):
#    while time.time() - t0 < 1.0:
	get_key_ID(clientSock)
 	demand_services(clientSock)

        
    print 'time: ', time.time() - t0
    
    assert 0	


