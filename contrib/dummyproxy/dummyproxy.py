#!/usr/bin/env python
# coding: utf-8
#
# Simple TCP Proxy implemented using Twisted Library
#
# The proxy is intended to be used in conjuntion
# with Tor2web configured with a dummyproxy circuit.
# 
# Typical scenario involves a setup like this:
#
#      t2w -> dummyproxy -> dummyproxy -> dummyproxy -> HTTP/HTTPS application server
#
# Author: Giovanni Pellerano <evilaliv3@globaleaks.org>
#

import sys

from twisted.internet import protocol, reactor

class ClientProtocol(protocol.Protocol):
    def connectionMade(self):
        self.factory.server.client = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''
 
    # Server => Proxy
    def dataReceived(self, data):
        self.factory.server.write(data)
 
    # Proxy => Server
    def write(self, data):
        if data:
            self.transport.write(data)

    def connectionLost(self, why):
        self.factory.server.transport.loseConnection()


class ServerProtocol(protocol.Protocol):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.buffer = None
        self.client = None

    def connectionMade(self):
        factory = protocol.ClientFactory()
        factory.protocol = ClientProtocol
        factory.server = self

        reactor.connectTCP(self.ip, self.port, factory)

    # Client => Proxy
    def dataReceived(self, data):
        if self.client:
            self.client.write(data)
        else:
            self.buffer = data

    # Proxy => Client
    def write(self, data):
        self.transport.write(data)

    def connectionLost(self, why):
        self.transport.loseConnection()

class ServerFactory(protocol.Factory):
    protocol = ServerProtocol

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def buildProtocol(self, addr):
        p = self.protocol(self.ip, self.port)
        p.factory = self
        return p

if __name__ == "__main__":

    if len(sys.argv) != 5:
        sys.stderr.write("Usage: " + sys.argv[0] + "<src-port> <dst-host> <dst-port>\n\n" \
                         "\texample: ./dummyproxy.py 127.0.0.1 80 127.0.0.1 8080\n" \
                         "\t         ./dummyproxy.py 0.0.0.0 88 google.com 80\n\n")
        sys.exit(1)

    src_ip = str(sys.argv[1])
    src_port = int(sys.argv[2])

    dst_ip = str(sys.argv[3])
    dst_port = int(sys.argv[4])

    factory = ServerFactory(dst_ip, dst_port)

    reactor.listenTCP(src_port, factory, interface=src_ip)

    reactor.run()
