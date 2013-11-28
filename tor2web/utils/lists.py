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
import gzip
import json
from StringIO import StringIO
import os
import glob

from OpenSSL import SSL
from twisted.internet import reactor, ssl
from twisted.internet.task import LoopingCall
from twisted.internet.defer import Deferred
from twisted.web.client import HTTPPageGetter, HTTPClientFactory, _URI
from OpenSSL.SSL import VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT
from OpenSSL.crypto import load_certificate, FILETYPE_PEM


certificateAuthorityMap = {}

for certFileName in glob.glob("/etc/ssl/certs/*.pem"):
    # There might be some dead symlinks in there, so let's make sure it's real.
    if os.path.exists(certFileName):
        data = open(certFileName).read()
        x509 = load_certificate(FILETYPE_PEM, data)
        digest = x509.digest('sha1')
        # Now, de-duplicate in case the same cert has multiple names.
        certificateAuthorityMap[digest] = x509

class HTTPSVerifyingContextFactory(ssl.ClientContextFactory):
    def __init__(self, hostname):
        self.hostname = hostname

    def getContext(self):
        ctx = self._contextFactory(self.method)

        # Disallow SSLv2! It's insecure!
        ctx.set_options(SSL.OP_NO_SSLv2)

        ctx.set_options(SSL.OP_SINGLE_DH_USE)

        # http://en.wikipedia.org/wiki/CRIME_(security_exploit)
        # https://twistedmatrix.com/trac/ticket/5487
        # SSL_OP_NO_COMPRESSION = 0x00020000L
        ctx.set_options(0x00020000)

        store = ctx.get_cert_store()
        for value in certificateAuthorityMap.values():
            store.add_cert(value)
        ctx.set_verify(VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT, self.verifyHostname)
        return ctx
    
    def verifyHostname(self, connection, x509, errno, depth, preverifyOK):
        if  depth == 0 and preverifyOK:
            cn = x509.get_subject().commonName

            if cn.startswith(b"*.") and self.hostname.split(b".")[1:] == cn.split(b".")[1:]:
                return True

            elif self.hostname == cn:
                return True

            return False

        return preverifyOK

def getPageCached(url, contextFactory=None, *args, **kwargs):
    """download a web page as a string, keep a cache of already downloaded pages

    Download a page. Return a deferred, which will callback with a
    page (as a string) or errback with a description of the error.

    See HTTPClientCacheFactory to see what extra args can be passed.
    """
    uri = _URI.fromBytes(url)
    scheme = uri.scheme
    host = uri.host
    port = uri.port
 
    factory = HTTPClientCacheFactory(url, *args, **kwargs)

    if scheme == 'https':
        if contextFactory is None:
            contextFactory = HTTPSVerifyingContextFactory(host)
        reactor.connectSSL(host, port, factory, contextFactory)
    else:
        reactor.connectTCP(host, port, factory)

    return factory.deferred

class HTTPCacheDownloader(HTTPPageGetter):
    def connectionMade(self, isCached=False):
        self.content_is_gzip = False

        if self.factory.url in self.factory.cache and 'response' in self.factory.cache[self.factory.url]:
            self.cache = self.factory.cache[self.factory.url]
        else:
            self.cache = None

        self.cachetemp = {}

        method = getattr(self.factory, 'method', 'GET')
        self.sendCommand(method, self.factory.path)
        if self.factory.scheme == 'http' and self.factory.port != 80:
            host = '%s:%s' % (self.factory.host, self.factory.port)
        elif self.factory.scheme == 'https' and self.factory.port != 443:
            host = '%s:%s' % (self.factory.host, self.factory.port)
        else:
            host = self.factory.host

        self.sendHeader('host', self.factory.headers.get('host', host))
        self.sendHeader('user-agent', self.factory.agent)
        self.sendHeader('accept-encoding', 'gzip')

        if self.cache and 'etag' in self.cache:
            self.sendHeader('etag', self.cache['etag'])

        if self.cache and 'if-modified-since' in self.cache:
            self.sendHeader('if-modified-since', self.cache['if-modified-since'])

        data = getattr(self.factory, 'postdata', None)
        if data is not None:
            self.sendHeader('content-length', str(len(data)))

        cookieData = []
        for (key, value) in self.factory.headers.items():
            if key.lower() not in self._specialHeaders:
                # we calculated it on our own
                self.sendHeader(key, value)
            if key.lower() == 'cookie':
                cookieData.append(value)
        for cookie, cookval in self.factory.cookies.items():
            cookieData.append('%s=%s' % (cookie, cookval))
        if cookieData:
            self.sendHeader('cookie', '; '.join(cookieData))

        self.endHeaders()
        self.headers = {}

        if data is not None:
            self.transport.write(data)

    def handleHeader(self, key, value):
        key = key.lower()

        if key == 'date' or key == 'last-modified':
            self.cachetemp[key] = value

        if key == 'etag':
            self.cachetemp[key] = value

        if key == 'content-encoding' and value == 'gzip':
            self.content_is_gzip = True
            
        HTTPPageGetter.handleHeader(self, key, value)

    def handleResponse(self, response):
        if self.content_is_gzip:
            c_f = StringIO(response)
            response = gzip.GzipFile(fileobj=c_f).read()

        self.cachetemp['response'] = response
        self.factory.cache[self.factory.url] = self.cachetemp
        HTTPPageGetter.handleResponse(self, response)

    def handleStatus(self, version, status, message):
        HTTPPageGetter.handleStatus(self, version, status, message)
        
    def handleStatus_304(self):
        # content not modified
        pass

class HTTPClientCacheFactory(HTTPClientFactory):
    protocol = HTTPCacheDownloader
    cache = {}

    def __init__(self, url, method='GET', postdata=None, headers=None,
                 agent="Tor2Web (https://github.com/globaleaks/tor2web-3.0)",
                 timeout=0, cookies=None,
                 followRedirect=1):

        headers = {}

        if url in self.cache:
            if 'etag' in self.cache[url]:
                headers['etag'] = self.cache[url]['etag']
            elif 'last-modified' in self.cache[url]:
                headers['if-modified-since'] = self.cache[url]['last-modified']
            elif 'date' in self.cache[url]:
                headers['if-modified-since'] = self.cache[url]['date']

        HTTPClientFactory.__init__(self, url=url, method=method,
                postdata=postdata, headers=headers, agent=agent,
                timeout=timeout, cookies=cookies, followRedirect=followRedirect)
        self.deferred = Deferred()


class List(set):
    def __init__(self, filename, url='', refreshPeriod=0):
        set.__init__(self)
        self.filename = filename
        self.url = url
       
        self.load()

        if url != '' and refreshPeriod != 0:
            self.lc = LoopingCall(self.update)
            self.lc.start(refreshPeriod)

    def load(self):
        """
        Load the list from the specified file.
        """
        self.clear()
        
        #simple touch to create non existent files
        try:
            open(self.filename, 'a').close()

            with open(self.filename, 'r') as fh:
                for l in fh.readlines():
                    self.add(re.split("#", l)[0].rstrip("[ , \n,\t]"))
        except:
            pass

    def dump(self):
        """
        Dump the list to the specified file.
        """
        try:
            with open(self.filename, 'w') as fh:
                for l in self:
                    fh.write(l + "\n")
        except:
            pass
    
    def handleData(self, data):
        for elem in data.split('\n'):
            if elem != '':
                self.add(elem)

    def processData(self, data):
        try:
            if len(data) != 0:
                self.handleData(data)
                self.dump()
        except Exception:
            pass

    def update(self):
        pageFetchedDeferred = getPageCached(self.url)
        pageFetchedDeferred.addCallback(self.processData)
        return pageFetchedDeferred

class TorExitNodeList(List):
    def handleData(self, data):
        self.clear()
        data = json.loads(data)
        for relay in data['relays']:
            for ip in relay['a']:
                if ip != '':
                    self.add(ip)
