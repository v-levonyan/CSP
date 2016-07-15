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

def connection(clientSock, host = '127.0.0.1', port = 8888):

    clientSock.connect(host, port)
    rec = clientSock.recieveMessage()
    print 'rec ', rec, ' rec'
    clientSock.sendMessage('0')


def registration(clientSock, user_name = '', password = ''):
    
    if client.check_username(user_name) != 0:
	clientSock.shutDownAndClose()
	return SUCCESS 
   
    clientSock.sendMessage(user_name)
    free_or_busy = clientSock.recieveMessage()

    #return free_or_busy

    if client.check_password(password) != 0:
	clientSock.shutDownAndClose()
	return SUCCESS
    
    clientSock.sendMessage(password)
   
    clientSock.shutDownAndClose()
    return clientSock.recieveMessage()#timeout = 1)


def test_empty_login_password():

    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)
    assert registration(clientSock) == SUCCESS


def test_long_login_password():

    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)
    assert registration(clientSock, user_name = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa', password =
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb') == SUCCESS

def test_empty_login_normal_password():

    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)
    assert registration(clientSock, user_name = '',  password = 'david') == SUCCESS

def test_normal_login_empty_password():

    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)
    assert registration(clientSock, user_name = 'david', password = '') == SUCCESS

def test_empty_login_long_password():

    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)
    assert registration(clientSock, user_name = '', password ='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') == SUCCESS

def test_normal_login_long_password():

    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)
    assert registration(clientSock, user_name = 'david', password ='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') == SUCCESS



def registrate_by_normal_login_password(clientSock, user_name = '', password = ''):
    
    if client.check_username(user_name) != 0:
	clientSock.shutDownAndClose()
	return FAILURE 
   
    clientSock.sendMessage(user_name)
    free_or_busy = clientSock.recieveMessage()

    return free_or_busy

    if client.check_password(password) != 0:
	clientSock.shutDownAndClose()
	return FAILURE
    
    clientSock.sendMessage(password)
   
    clientSock.shutDownAndClose()
    return clientSock.recieveMessage()#timeout = 1)

def test_normal_login_normal_password():

    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)
    assert registrate_by_normal_login_password(clientSock, user_name = 'david', password ='david123') != FAILURE


