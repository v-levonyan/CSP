#!/usr/bin/python

from client import clientSocket
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--host", help="specify the host to connect with", default="127.0.0.1")
parser.add_argument("--port", help="specify the port of the host", type=int, default=8888)

args = parser.parse_args()

clientSock = clientSocket()
clientSock.connect(args.host, args.port)

options = {
        1 : clientSock.getSHA1File
        }

clientSock.sendMessage("CSP1.0://Get Services")

while 1:
    print "loop"
    services = clientSock.recieveMessage()
    print services
    serviceId = input("Choose service: ")
    result = options.get(serviceId)()
    print result
    
