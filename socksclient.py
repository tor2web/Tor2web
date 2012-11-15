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
from twisted.internet import defer
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.protocols import policies

SOCKS_errors = {\
    0x23: "error_socks_hs_not_found.xml",
    0x24: "error_socks_hs_not_reachable.xml"
}

class SOCKSError(Exception):
    def __init__(self, value, data):
        Exception.__init__(self)
        self.code = value
        self.template = data

class SOCKSv5ClientProtocol(policies.ProtocolWrapper):
    state = 0

    def __init__(self, factory, wrappedProtocol):
        policies.ProtocolWrapper.__init__(self, factory, wrappedProtocol)
        self.ready = False
        self.buf = []

    def socks_state_0(self, data):
        # error state
        self.factory.clientConnectionFailed(self, SOCKSError(0x00, "error_socks.xml"))
        return

    def socks_state_1(self, data):
        if data != "\x05\x00":
            self.factory.clientConnectionFailed(self, SOCKSError(0x00, "error_socks.xml"))
            return
            
        # Anonymous access allowed - let's issue connect
        self.transport.write(struct.pack("!BBBBB", 5, 1, 0, 3,
                                         len(self.factory.host)) + 
                                         self.factory.host +
                                         struct.pack("!H", self.factory.port))

    def socks_state_2(self, data):
        if data[:2] != "\x05\x00":
            # Anonymous access denied

            errcode = ord(data[1])
            
            if errcode in SOCKS_errors:
                self.factory.clientConnectionFailed(self, SOCKSError(hex(errcode), SOCKS_errors[errcode]))
            else:
                self.factory.clientConnectionFailed(self, SOCKSError(hex(errcode), "error_socks.xml"))
                
            return

        self.ready = True
        policies.ProtocolWrapper.connectionMade(self)
        
        if self.buf != []:
            self.transport.write(''.join(self.buf))
            self.buf = []

    def connectionMade(self):
        # We implement only Anonymous access
        self.transport.write(struct.pack("!BB", 5, len("\x00")) + "\x00")
        
        self.state = self.state + 1

    def connectionLost(self, reason):
        if self.ready:
            policies.ProtocolWrapper.connectionLost(self, reason)

    def write(self, data):
        if self.ready:
            self.transport.write(data)
        else:
            self.buf.append(data)

    def dataReceived(self, data):
        if self.state != 3:
            getattr(self, 'socks_state_%s' % (self.state), self.socks_state_0)(data)
            self.state = self.state + 1
        else:
            policies.ProtocolWrapper.dataReceived(self, data)

class SOCKSv5ClientFactory(policies.WrappingFactory):
    protocol = SOCKSv5ClientProtocol
    
    def __init__(self, deferred, wrappedFactory, host, port):
        policies.WrappingFactory.__init__(self, wrappedFactory)
        self.deferred = deferred
        self.host, self.port = host, port
        
    def clientConnectionFailed(self, connector, reason):
        if self.deferred is not None:
            d, self.deferred = self.deferred, None
            d.errback(reason)
