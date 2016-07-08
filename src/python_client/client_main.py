#!/usr/bin/python

import client
import argparse
import hashlib
import os
import socket
from OpenSSL import SSL, crypto

parser = argparse.ArgumentParser()
parser.add_argument("--host", help="specify the host to connect with", default="127.0.0.1")
parser.add_argument("--port", help="specify the port of the host", type=int, default=8888)

args = parser.parse_args()

# Initialize context
ctx = client.context()

clientSock = client.clientSocket(ctx)

clientSock.connect(args.host, args.port)

print "Secure connection established"

options = {
        1 : clientSock.get_sha1_file,  2 : clientSock.get_sha1_string, 3 :
	clientSock.symmetric_key,      4 : clientSock.symmetric_key,  5  :
	clientSock.symmetric_key,      6 : clientSock.symmetric_key,  7  :
	clientSock.symmetric_key,      8 : clientSock.DES_encr_decr, 9  : clientSock.DES_encr_decr,
	10 : clientSock.AES_encr_decr, 11 : clientSock.AES_encr_decr, 12 :
	clientSock.AES_encr_decr, 13 : clientSock.DES_encr_decr, 14 : clientSock.DES_encr_decr, 15 :
	clientSock.AES_encr_decr, 16 : clientSock.AES_encr_decr, 17 : clientSock.AES_encr_decr}
	
rec_message = clientSock.recieveMessage()

reg_or_log = -1	

if rec_message == "Authorize!":
    
    while 1:
	reg_or_log = raw_input ('Enter 0 for registration, 1 for sign in\n>>> ')
	
	if reg_or_log == "0" or reg_or_log == "1":
	    break

if reg_or_log == '0': # registration
    clientSock.sendMessage('0')
    
    while 1:
	user_name = raw_input('Choose a username.\n>>> ')
	clientSock.sendMessage(user_name)
    
	free_or_busy = clientSock.recieveMessage()
	
	if int(free_or_busy) == 1: # username is busy
	    print 'Chosen username is busy!\n'
	    continue
	if int(free_or_busy) == 0: # username was free
	    password = raw_input('Choose a password.\n>>> ')
	    clientSock.sendMessage(password)
	    break


if reg_or_log == '1': # log in
    clientSock.sendMessage('1')

while 1:
    clientSock.sendMessage("CSP1.0://Get Services")
    services = clientSock.recieveMessage()
    print services
    serviceId = input("Choose service: ")

    if serviceId < 0 or serviceId > 17:
	print 'Wrong order'
	exit(1)
    if serviceId == 2 or serviceId == 8 or serviceId == 9 or serviceId == 13 or serviceId == 14:
	print ' Your specified order now is not available, it will be available soon\n'
	exit()

    if serviceId > 0  and serviceId <= 12:
	result = options.get(serviceId)(str(serviceId),0)
	if result == -1:
	    continue

    if serviceId > 12 and serviceId <= 17:
	result = options.get(serviceId)(str(serviceId),1)
	if result == -1:
	    continue
    
    pretty = clientSock.byteToHex(result)
    
    if serviceId == 1 or serviceId == 2:
	print '\nSHA 1: ', pretty
	print '\n'

    if serviceId >=3 and serviceId <= 7:
	print 'Symmetric key generated, ID: ', result
	print '\n'
    else:
	continue
