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

import os
import re
import socket

try:
    from twisted.protocols import tls

except ImportError:
    raise Exception("tor2web: ssl hack for listenSSLonExistingFD not implemented (tls only)")


def listenTCPonExistingFD(reactor, fd, factory):
    return reactor.adoptStreamPort(fd, socket.AF_INET, factory)

def listenSSLonExistingFD(reactor, fd, factory, contextFactory):

    tlsFactory = tls.TLSMemoryBIOFactory(contextFactory, False, factory)
    port = reactor.listenTCPonExistingFD(reactor, fd, tlsFactory)
    port._type = 'TLS'
    return port

def re_sub(pattern, replacement, string):
    def _r(m):
        # Now this is ugly.
        # Python has a "feature" where unmatched groups return None
        # then re_sub chokes on this.
        # see http://bugs.python.org/issue1519638
        
        # this works around and hooks into the internal of the re module...
 
        # the match object is replaced with a wrapper that
        # returns "" instead of None for unmatched groups
 
        class _m():
            def __init__(self, m):
                self.m=m
                self.string=m.string
            def group(self, n):
                return m.group(n) or ""
 
        return re._expand(pattern, _m(m), replacement)
    
    return re.sub(pattern, _r, string)
    
def t2w_file_path(prefix, path):
    """
    Returns the path of a tor2web file.
    It could be:
       - a default file, loaded from /usr/share/tor2web + path
       - an overridden file present in config.datadir + path
    """
    if os.path.exists(os.path.join(prefix, path)):
        return os.path.join(prefix, path)
    else:
        return os.path.join("/usr/share/tor2web", path)

def verify_onion(address):
    """
    Check to see if the address is a .onion.
    returns the onion address as a string if True else returns False
    """
    try:
        onion, tld = address.split(".")
        if tld == 'onion' and len(onion) == 16 and onion.isalnum():
            return True
    except Exception:
        pass

    return False
