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
from twisted.python.failure import Failure

class SOCKSError(Exception):
    def __init__(self, value):
        Exception.__init__(self)
        self.code = value

class SOCKSv5ClientProtocol(_WrappingProtocol):
    state = 0

    def __init__(self, connectedDeferred, wrappedProtocol, host, port, optimistic = False):
        _WrappingProtocol.__init__(self, connectedDeferred, wrappedProtocol)
        self._host = host
        self._port = port
        self._optimistic = optimistic
        self._buf = ''
        
    def error(self, error):
        if not self._optimistic:
            self._connectedDeferred.errback(error)
        else:
            errorcode = 600 + error.value.code
            self._wrappedProtocol.dataReceived("HTTP/1.1 "+str(errorcode)+" ANTANI\r\n\r\n")
            self.transport.loseConnection()

    def socks_state_0(self):
        # error state
        self.error(SOCKSError(0x00))
        return

    def socks_state_1(self):
        if len(self._buf) < 2:
            return

        if self._buf[:2] != "\x05\x00":
            # Anonymous access denied
            self.error(Failure(SOCKSError(0x00)))
            return

        if not self._optimistic:
            self.transport.write(struct.pack("!BBBBB", 5, 1, 0, 3, len(self._host)) + self._host + struct.pack("!H", self._port))

        self._buf = self._buf[2:]
        
        self.state = self.state + 1

    def socks_state_2(self):
        if len(self._buf) < 10:
            return

        if self._buf[:2] != "\x05\x00":
            self.error(Failure(SOCKSError(ord(self._buf[1]))))
            return
    
        self._buf = self._buf[10:]

        if not self._optimistic:
            self._wrappedProtocol.makeConnection(self.transport)
            self._connectedDeferred.callback(self._wrappedProtocol)

        self.state = self.state + 1

    def connectionMade(self):
        # We implement only Anonymous access
        self.transport.write(struct.pack("!BB", 5, len("\x00")) + "\x00")
        
        if self._optimistic:
            self.transport.write(struct.pack("!BBBBB", 5, 1, 0, 3, len(self._host)) + self._host + struct.pack("!H", self._port))
            self._wrappedProtocol.makeConnection(self.transport)
            self._connectedDeferred.callback(self._wrappedProtocol)
        
        self.state = self.state + 1

    def dataReceived(self, data):
        if self.state != 3:
            self._buf = self._buf.join(data)
            getattr(self, 'socks_state_%s' % (self.state), self.socks_state_0)()
        else:
            self._wrappedProtocol.dataReceived(data)

class SOCKSv5ClientFactory(_WrappingFactory):
    protocol = SOCKSv5ClientProtocol
    
    def __init__(self, wrappedFactory, host, port, optimistic):
        _WrappingFactory.__init__(self, wrappedFactory)
        self._host = host
        self._port = port
        self._optimistic = optimistic

    def buildProtocol(self, addr):
        try:
            proto = self._wrappedFactory.buildProtocol(addr)
        except:
            self._onConnection.errback()
        else:
            return self.protocol(self._onConnection, proto,
                                 self._host, self._port, self._optimistic)

class SOCKS5ClientEndpoint(object):
    """
    SOCKS5 TCP client endpoint with an IPv4 configuration.
    """
    implements(interfaces.IStreamClientEndpoint)

    def __init__(self, reactor, sockhost, sockport,
                 host, port, optimistic, timeout=30, bindAddress=None):
        self._reactor = reactor
        self._sockhost = sockhost
        self._sockport = sockport
        self._host = host
        self._port = port
        self._optimistic = optimistic
        self._timeout = timeout
        self._bindAddress = bindAddress

    def connect(self, protocolFactory):
        try:
            wf = SOCKSv5ClientFactory(protocolFactory, self._host, self._port, self._optimistic)
            self._reactor.connectTCP(
                self._sockhost, self._sockport, wf,
                timeout=self._timeout, bindAddress=self._bindAddress)
            return wf._onConnection
        except:
            return defer.fail()
