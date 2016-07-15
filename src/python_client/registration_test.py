import pytest
#from  client_main import reg_signin
import client
import hashlib
import os
import socket
import getpass
import sys
from OpenSSL import SSL, crypto

def by_empty_password():
    
    ctx = client.context()
    clientSock = client.clientSocket(ctx)

    clientSock.connect('127.0.0.1', 8888)
    rec = clientSock.recieveMessage()

    clientSock.sendMessage('David')
    clientSock.sendMessage('')
    r = clientSock.recieveMessage()#timeout = 1)
    clientSock.shutDownAndClose()
    return r

def by_empty_login():
    ctx = client.context()

    clientSock = client.clientSocket(ctx)

    clientSock.connect('127.0.0.1', 8888)
    rec = clientSock.recieveMessage()

    clientSock.sendMessage('')
    clientSock.sendMessage('dsaf')
    
    clientSock.shutDownAndClose()
    return clientSock.recieveMessage()#timeout = 1)

def test_empty_password():
    result = by_empty_password()
    assert int(result) != 0
    assert int(result) != 1

def test_empty_login():

    result = by_empty_login()
    assert int(result) != 0
    assert int(result) != 1

