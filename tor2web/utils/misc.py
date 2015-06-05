"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: [GLOBALEAKS_MODULE_DESCRIPTION]

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

import re
import socket

from twisted.protocols import tls

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

def verify_onion(address):
    """
    Check to see if the address is a .onion.
    returns the onion address as a string if True else returns False
    """
    try:
        pieces = address.split(".")

        # all pieces must exist and be alnums
        for piece in pieces:
           if piece == '':
              return False

            if not piece.isalnum():
               return False

         # get the final two pieces
         onion, tld = pieces[-2:]

         if len(onion) == 16 and tld.lower() == 'onion':
            return True

    except Exception:
        pass

    return False
