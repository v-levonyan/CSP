import pytest
#from  client_main import reg_signin
import client
import hashlib
import os
import socket
import getpass
import sys
from OpenSSL import SSL, crypto

# Initialize context
ctx = client.context()

clientSock = client.clientSocket(ctx)

clientSock.connect('127.0.0.1', 8888)
rec = clientSock.recieveMessage()

print rec 

def registrate_user_by_empty_password():
    clientSock.sendMessage('David')
    clientSock.sendMessage(' ')
    r = clientSock.recieveMessage()
    return r


def test_empty_password():
    result = registrate_user_by_empty_password()
    assert int(result) != 0
    assert int(result) != 1
