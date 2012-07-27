"""
    Tor2web
    Copyright (C) 2012 Hermes No Profit Association - GlobaLeaks Project

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: [GLOBALEAKS_MODULE_DESCRIPTION]

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

from twisted.internet import defer
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet.endpoints import _WrappingFactory

import socket
import struct
from zope.interface import implements

SOCKS_errors = {\
    0x00: "request granted",
    0x01: "general failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused by destination host",
    0x06: "TTL expired",
    0x07: "command not supported / protocol error",
    0x08: "address type not supported",
    0x23: "hidden service not found",
    0x24: "hidden service not reachable"
}

class SOCKSError(Exception):
    def __init__(self, code, error):
        self.code = code
        self.error = error
    def __str__(self):
        return repr(self.error) + " (" + repr(self.code) + ")"

class SOCKSv5ClientProtocol(Protocol):
    postHandshakeEndpoint = None
    postHandshakeFactory = None
    handshakeDone = None
    buf = ''
    state = 0

    def socks_state_0(self, data):
        # in SOCKSv5 protocol is always the client that send the first message
        self.transport.loseConnection()

    def socks_state_1(self, data):
        if data != "\x05\x00":
            self.transport.loseConnection()

            return

        host = self.postHandshakeEndpoint._host
        port = self.postHandshakeEndpoint._port
            
        # Anonymous access allowed - let's issue connect
        self.transport.write(struct.pack("!BBBBB", 5, 1, 0, 3, len(host)) + host + struct.pack("!H", port))
        
        self.state = 2

    def socks_state_2(self, data):
        if data[:2] != "\x05\x00":
            self.transport.loseConnection()

            errcode = ord(data[1])
            
            if errcode in SOCKS_errors:
                self.handshakeDone.errback(SOCKSError(hex(errcode), SOCKS_errors[errcode]))
            else:
                self.handshakeDone.errback(SOCKSError(hex(errcode), "unrecognized Error"))
                
            return

        self.transport.protocol = self.postHandshakeFactory.buildProtocol(self.transport.getHost())
        self.transport.protocol.transport = self.transport
        self.transport.protocol.connectionMade()

    def thisMustNeverHappen(self, data):
        self.transport.loseConnection()

    def connectionMade(self):
        # We implement only Anonymous access
        self.transport.write(struct.pack("!BB", 5, len("\x00")) + "\x00")
        
        self.state = 1
        
    def dataReceived(self, data):
        getattr(self, 'socks_state_%s' % (self.state), self.thisMustNeverHappen)(data)

class SOCKSv5ClientFactory(ClientFactory):
    protocol = SOCKSv5ClientProtocol

    def buildProtocol(self, addr):
        r = ClientFactory.buildProtocol(self, addr)
        r.postHandshakeEndpoint = self.postHandshakeEndpoint
        r.postHandshakeFactory = self.postHandshakeFactory
        r.handshakeDone = self.handshakeDone
        return r
        
    def clientConnectionFailed(self, connector, reason):
        self.handshakeDone.errback("connection to sock server failed")

class SOCKSWrapper(object):
    implements(IStreamClientEndpoint)
    factory = SOCKSv5ClientFactory

    def __init__(self, reactor, host, port, endpoint):
        self._reactor = reactor
        self._host = host
        self._port = port
        self._endpoint = endpoint

    def connect(self, protocolFactory):
        """
        Return a deferred firing when the SOCKS connection is established.
        """

        def _canceller(deferred):
            connector.stopConnecting()
            deferred.errback(
                error.ConnectingCancelledError(connector.getDestination()))

        try:
            # Connect with an intermediate SOCKS factory/protocol,
            # which then hands control to the provided protocolFactory
            # once a SOCKS connection has been established.

            f = self.factory()
            f.postHandshakeEndpoint = self._endpoint
            f.postHandshakeFactory = protocolFactory
            f.handshakeDone = defer.Deferred()

            connector = self._reactor.connectTCP(self._host, self._port, f)
            return f.handshakeDone
        except:
            return defer.fail()
