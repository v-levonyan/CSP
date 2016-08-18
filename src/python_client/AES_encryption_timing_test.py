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



def symmetric_key(clientSock, num):
 
         CorrespondingKey = { '3' : '7', '4' : '21', '5' : '16', '6' : '24', '7' : '32' }
         size = CorrespondingKey.get(num)
 
         seq = (num, size)
         params = ':'.join(seq)
 
         clientSock.sendMessage(params)
         return  clientSock.recieveMessage()
	
def get_key_ID(clientSock):
       	
    return symmetric_key(clientSock,'7')
     	

def send_file(clientSock, file_name):
    
    try:
	f = open(file_name)
    except:
        print "Wrong file.\n"
        exit()
     
    for piece in clientSock.readInChunks(f, 15):
	    clientSock.sendMessage(piece)


def AES_encryption(clientSock, key_ID, filename):
    
    clientSock.sendMessage('AESencr_decr:256')
    clientSock.sendMessage(key_ID)
    clientSock.recieveMessage()
    clientSock.sendMessage('0')
    clientSock.sendMessage('0')
    
    fileSize = os.path.getsize(filename)
    clientSock.sendMessage(str(fileSize))
    
    send_file(clientSock, filename)

    encrypted_file_name = 'encrypted_' + filename  + '.txt'
    index_of_slash = encrypted_file_name.rfind('/')

    encr_name = encrypted_file_name[0:10] + encrypted_file_name[index_of_slash+1 : len(encrypted_file_name)]

    fd = open(encr_name,'w+')

    while 1:
	rec_m = clientSock.recieveMessage(-1)
	if rec_m != "END":
	    fd.write(rec_m)
	else:
	    fd.close()
	    print 'Encrypted file received, it is in your current directory with name ', encr_name,  '\n' 
	    break 
    
    return -1     

def test_AES_encryption():
    
    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)
   
    registration(clientSock, 'David', 'david')
    
    demand_services(clientSock)
    
    key_ID = get_key_ID(clientSock)
    
    print key_ID
    
    demand_services(clientSock)

    for i in range(1,100):
	res = AES_encryption( clientSock, key_ID, '/home/davidt/workspace/CSP/src/python_client/AES_test_file')   
	demand_services(clientSock)

	assert  res == -1

