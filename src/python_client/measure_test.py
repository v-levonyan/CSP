import pytest
#from  client_main import reg_signin
import client
import hashlib
import os
import socket
import getpass
import sys
from OpenSSL import SSL, crypto

SUCCESS = 777
FAILURE = -777

def setup_function(function):
    print ("Testing function: %s" % function.__name__)

def connection(clientSock, host = '127.0.0.1', port = 8888):

    clientSock.connect(host, port)
    rec = clientSock.recieveMessage()
    print 'rec ', rec, ' rec'
    clientSock.sendMessage('0')


def registration(clientSock, user_name, password):
   
    clientSock.sendMessage('0')
    if client.check_username(user_name) != 0:
	clientSock.shutDownAndClose()
	return FAILURE 
   
    clientSock.sendMessage(user_name)
    
    if int(clientSock.recieveMessage()) == 1:
	return FAILURE

    #return free_or_busy

    if client.check_password(password) != 0:
	clientSock.shutDownAndClose()
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

def test_key_generation():

    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)
       
#    assert registration(clientSock, user_name = 'David', password = 'david') == SUCCESS
    
    registration(clientSock, user_name = 'David', password = 'david') 
    
    for i in range(0,100):
	
	clientSock.symmetric_key('7')
	
	assert 1
	demand_services(clientSock)
	

#    assert 0


