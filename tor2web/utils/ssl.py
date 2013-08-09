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

from OpenSSL import SSL

from twisted.internet.ssl import ContextFactory

class T2WSSLContextFactory(ContextFactory):
    """
    """
    _context = None

    _context_reuse_count = 0
    _max_context_reuse = 50

    def __init__(self, privateKeyFileName, certificateChainFileName, dhFileName, cipherList):
        """
        @param privateKeyFileName: Name of a file containing a private key
        @param certificateChainFileName: Name of a file containing a certificate chain
        @param dhFileName: Name of a file containing diffie hellman parameters
        @param cipherList: The SSL cipher list selection to use
        """
        self.privateKeyFileName = privateKeyFileName
        self.certificateChainFileName = certificateChainFileName
        self.sslmethod = SSL.SSLv23_METHOD
        self.dhFileName = dhFileName
        self.cipherList = cipherList

        # Create a context object right now.  This is to force validation of
        # the given parameters so that errors are detected earlier rather
        # than later.
        self._context = self.getContext()

    def getContext(self):
        """
        Return an SSL context.
        """
        if self._context is None or self._context_reuse_count >= self._max_context_reuse:

           ctx = SSL.Context(self.sslmethod)
           # Disallow SSLv2! It's insecure!
           ctx.set_options(SSL.OP_NO_SSLv2)
           # https://twistedmatrix.com/trac/ticket/5487
           # SSL_OP_NO_COMPRESSION = 0x00020000L
           ctx.set_options(0x00020000)
           # SSL_MODE_RELEASE_BUFFERS = 0x00000010L
           ctx.set_options(0x00000010L)

           if self.certificateChainFileName is not None:
               ctx.use_certificate_chain_file(self.certificateChainFileName)

           ctx.use_privatekey_file(self.privateKeyFileName)
           ctx.set_cipher_list(self.cipherList)
           ctx.load_tmp_dh(self.dhFileName)

           # we renew here the context; old reference is lose and the
           # object will be automagically deleted when the last
           # connection that uses it will die.

           self._context = ctx
           self._context_reuse_count = 0

        self._context_reuse_count += 1

        return self._context
