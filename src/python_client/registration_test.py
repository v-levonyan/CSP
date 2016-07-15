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

def connection(clientSock, host = '127.0.0.1', port = 8888):

    clientSock.connect(host, port)
    rec = clientSock.recieveMessage()
    print 'rec ', rec, ' rec'
    clientSock.sendMessage('0')


def registration(clientSock, user_name = '', password = ''):
    
    if client.check_username(user_name) != 0:
	return SUCCESS 
   
    clientSock.sendMessage(user_name)
    free_or_busy = clientSock.recieveMessage()

    return free_or_busy

    if client.check_password(password) != 0:
	return SUCCESS
    
    clientSock.sendMessage(password)
   
    return clientSock.recieveMessage()#timeout = 1)


def test_empty_login_password():

    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)
   # registration(clientSock)

    assert registration(clientSock) == SUCCESS
 

