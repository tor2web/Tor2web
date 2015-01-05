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

import re
import socket

# for URL-rewriting
from bs4 import BeautifulSoup


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
        onion, tld = address.split(".")
        if tld == 'onion' and len(onion) == 16 and onion.isalnum():
            return True
    except Exception:
        pass

    return False


def rewrite_urls_in_html( html_doc, basehost, proto ):
    '''returns a html_doc with all of the .onion URLs replaced with tor2web URLs'''

    soup = BeautifulSoup(html_doc)


    for link in soup.find_all('a'):
        # spec says 'href' should always be there, but we check just in-case.
        if link.has_attr('href'):
            link['href'] = rewrite_url( link['href'], basehost, proto )

    return str(soup)

oniondomain_pattern = re.compile(r'^([a-z0-9]{16})\.onion$', re.IGNORECASE)

def rewrite_url( href, basehost, proto ):
    '''convert any .onion href to a tor2web url'''

    global oniondomain_pattern

    # 1. If there's not http:// or https://, skip it.
    if not href.lower().startswith('http://') and not href.lower().startswith('https://'):
        return href

    # remove any weird whitespace from the beginning and end (have seen this before)
    href = href.strip()

    # we know it's either http or https.  Find the :// and remove everything before it.
    two_parts = href.split( '://', 1 )
    assert len(two_parts) == 2, "had an error.  This error should be impossible"
    domain_and_path = two_parts[1] # domain_and_path is everything after the first '://'

    # domain is everything before the first '/', and path is everything after it
    two_parts = domain_and_path.split('/', 1)
    domain, path = two_parts[0], two_parts[1] if len(two_parts) == 2 else ''


    # the final '/' here in replacement is REQUIRED.  It ensures we do the right thing
    # even if a clearweb subdomain is called 'onion'

    replacement = r'\1' + '.' + basehost
    new_domain = re.sub( oniondomain_pattern, replacement, domain, count=1)

    z = [proto, new_domain]
    if path:
        z.extend(['/',path])

    return ''.join(z)
