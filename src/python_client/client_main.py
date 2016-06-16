#!/usr/bin/python

from client import clientSocket
import argparse
import hashlib
import os
import socket
from OpenSSL import SSL, crypto

parser = argparse.ArgumentParser()
parser.add_argument("--host", help="specify the host to connect with", default="127.0.0.1")
parser.add_argument("--port", help="specify the port of the host", type=int, default=8888)

args = parser.parse_args()

def verify_cb(conn, cert, errnum, depth, ok):
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    print('Got certificate\n: Certificates owner name' + commonname + '\n')
    return ok

dir = os.curdir

# Initialize context
ctx = SSL.Context(SSL.SSLv23_METHOD)
ctx.set_options(SSL.OP_NO_SSLv2)
ctx.set_options(SSL.OP_NO_SSLv3)
ctx.set_verify(SSL.VERIFY_PEER, verify_cb) # Demand a certificate
ctx.use_privatekey_file(os.path.join(dir, 'mycert.pem'))
ctx.use_certificate_file(os.path.join(dir,'mycert.pem'))
ctx.load_verify_locations(os.path.join(dir, 'CA.pem'))

clientSock = clientSocket(ctx)

clientSock.connect(args.host, args.port)

print "Secure connection established"

options = {
        1 : clientSock.getSHA1File
        }

clientSock.sendMessage("CSP1.0://Get Services")

services = clientSock.recieveMessage()
print services
serviceId = input("Choose service: ")

if serviceId == 2:
    print ' Your specified order now is not available, it will available soon'
    exit(1)
if serviceId != 1:
    print 'wrong order'
    exit(1)
result = options.get(serviceId)()
pretty = clientSock.byteToHex(result) 
print 'SHA 1 : ', pretty


