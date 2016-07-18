import pytest
#from  client_main import reg_signin
import client
import hashlib
import os
import socket
import getpass
import sys
#from client_main import options
from OpenSSL import SSL, crypto

FAILURE = -777

def setup_function(function):
    
    print ("Testing function: %s" % function.__name__)


def connection(clientSock, host = '127.0.0.1', port = 8888):

    clientSock.connect(host, port)
    rec = clientSock.recieveMessage()
    print 'rec ', rec, ' rec'
    clientSock.sendMessage('0')

def registrate_by_normal_login_password(clientSock, user_name, password):
    
    if client.check_username(user_name) != 0:
	clientSock.shutDownAndClose()
	return FAILURE 
   
    clientSock.sendMessage(user_name)
    free_or_busy = clientSock.recieveMessage()
    
    if free_or_busy == 1:
	return free_or_busy

    if client.check_password(password) != 0:
	clientSock.shutDownAndClose()
	return FAILURE
    
    clientSock.sendMessage(password)
   
   # clientSock.shutDownAndClose()
    return clientSock.recieveMessage()#timeout = 1)

def run_program():

    ctx = client.context() 
    clientSock = client.clientSocket(ctx)
    
    connection(clientSock)

    if registrate_by_normal_login_password(clientSock, user_name = 'david', password ='david') == '1':
	print 'User already exists.\n'
	exit()

    return clientSock

clientSock = run_program()
#run_program()

options = {
        1 : clientSock.get_sha1_file,  2 : clientSock.get_sha1_string, 3 :
	clientSock.symmetric_key,      4 : clientSock.symmetric_key,  5  :
	clientSock.symmetric_key,      6 : clientSock.symmetric_key,  7  :
	clientSock.symmetric_key,      8 : clientSock.DES_encr_decr, 9  : clientSock.DES_encr_decr,
	10 : clientSock.AES_encr_decr, 11 : clientSock.AES_encr_decr, 12 :
	clientSock.AES_encr_decr, 13 : clientSock.DES_encr_decr, 14 : clientSock.DES_encr_decr, 15 :
	clientSock.AES_encr_decr, 16 : clientSock.AES_encr_decr, 17 : clientSock.AES_encr_decr}
	
def demand_services(clientSock):
    clientSock.sendMessage("CSP1.0://Get Services")
    services = clientSock.recieveMessage()

demand_services(clientSock)

def test_wrong_service_1():
    assert client.call_corresponding_service(2, options, clientSock) == -2

def test_wrong_service_2():
    assert client.call_corresponding_service('sdfad', options, clientSock) == -2

def test_wrong_service_3():
    assert client.call_corresponding_service(200, options, clientSock) == -2

def test_correct_service():
    assert len(client.call_corresponding_service(7, options, clientSock)) == 64
