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

import socket
import struct

from zope.interface import implements
from twisted.internet import defer, interfaces
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.internet.endpoints import TCP4ClientEndpoint, SSL4ClientEndpoint, _WrappingProtocol, _WrappingFactory
from twisted.protocols import policies

class SOCKSError(Exception):
    def __init__(self, value):
        Exception.__init__(self)
        self.code = value

class SOCKSv5ClientProtocol(_WrappingProtocol):
    state = 0

    def __init__(self, connectedDeferred, wrappedProtocol, host, port):
        _WrappingProtocol.__init__(self, connectedDeferred, wrappedProtocol)
        self._host = host
        self._port = port
        self.ready = False
        self.buf = []

    def socks_state_0(self, data):
        # error state
        self._connectedDeferred.errback(SOCKSError(0x00))
        return

    def socks_state_1(self, data):
        if data != "\x05\x00":
            self._connectedDeferred.errback(SOCKSError(0x00))
            return

        # Anonymous access allowed - let's issue connect
        self.transport.write(struct.pack("!BBBBB", 5, 1, 0, 3,
                                         len(self._host)) + 
                                         self._host +
                                         struct.pack("!H", self._port))

    def socks_state_2(self, data):
        if data[:2] != "\x05\x00":
            # Anonymous access denied

            errcode = ord(data[1])
            self._connectedDeferred.errback(SOCKSError(errcode))
                
            return

        self.ready = True

        self._wrappedProtocol.transport = self.transport
        self._wrappedProtocol.connectionMade()
        
        self._connectedDeferred.callback(self._wrappedProtocol)

    def connectionMade(self):
        # We implement only Anonymous access
        self.transport.write(struct.pack("!BB", 5, len("\x00")) + "\x00")
        
        self.state = self.state + 1

    def dataReceived(self, data):
        if self.state != 3:
            getattr(self, 'socks_state_%s' % (self.state),
                    self.socks_state_0)(data)
            self.state = self.state + 1
        else:
            self._wrappedProtocol.dataReceived(data)

class SOCKSv5ClientFactory(_WrappingFactory):
    protocol = SOCKSv5ClientProtocol
    
    def __init__(self, wrappedFactory, host, port):
        _WrappingFactory.__init__(self, wrappedFactory)
        self._host, self._port = host, port

    def buildProtocol(self, addr):
        """
        Proxy C{buildProtocol} to our C{self._wrappedFactory} or errback
        the C{self._onConnection} L{Deferred}.

        @return: An instance of L{_WrappingProtocol} or C{None}
        """''
        try:
            proto = self._wrappedFactory.buildProtocol(addr)
        except:
            self._onConnection.errback()
        else:
            return self.protocol(self._onConnection, proto,
                                 self._host, self._port)

class SOCKS5ClientEndpoint(object):
    """
    TCP client endpoint with an IPv4 configuration.
    """
    implements(interfaces.IStreamClientEndpoint)

    def __init__(self, reactor, sockhost, sockport,
                 host, port, timeout=30, bindAddress=None):
        """
        @param reactor: An L{IReactorTCP} provider

        @param host: A hostname, used when connecting
        @type host: str

        @param port: The port number, used when connecting
        @type port: int

        @param timeout: The number of seconds to wait before assuming the
            connection has failed.
        @type timeout: int

        @param bindAddress: A (host, port) tuple of local address to bind to,
            or None.
        @type bindAddress: tuple
        """
        self._reactor = reactor
        self._sockhost = sockhost
        self._sockport = sockport
        self._host = host
        self._port = port
        self._timeout = timeout
        self._bindAddress = bindAddress

    def connect(self, protocolFactory):
        """
        Implement L{IStreamClientEndpoint.connect} to connect via TCP.
        """
        try:
            wf = SOCKSv5ClientFactory(protocolFactory, self._host, self._port)
            self._reactor.connectTCP(
                self._sockhost, self._sockport, wf,
                timeout=self._timeout, bindAddress=self._bindAddress)
            return wf._onConnection
        except:
            return defer.fail()
