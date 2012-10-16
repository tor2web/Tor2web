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

from twisted.internet import reactor, ssl
from twisted.internet.task import LoopingCall
from twisted.internet.defer import Deferred
from twisted.web.client import HTTPPageGetter, HTTPClientFactory, _parse

import re
import gzip
import json

from StringIO import StringIO

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
                 agent="Tor2Web (https://github.com/globaleaks/tor2web-3.0)", timeout=0, cookies=None,
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

def getPageCached(url, contextFactory=None, *args, **kwargs):
    """download a web page as a string, keep a cache of already downloaded pages

    Download a page. Return a deferred, which will callback with a
    page (as a string) or errback with a description of the error.

    See HTTPClientCacheFactory to see what extra args can be passed.
    """       
    scheme, host, port, path = _parse(url)
    factory = HTTPClientCacheFactory(url, *args, **kwargs)
    if scheme == 'https':
        if contextFactory is None:
            contextFactory = ssl.ClientContextFactory()
        reactor.connectSSL(host, port, factory, contextFactory)
    else:
        reactor.connectTCP(host, port, factory)

    return factory.deferred
    
class fileList(set):
    def __init__(self, filename):
        set.__init__(self)
        self.filename = filename
       
        self.load()
       
    def load(self):
        """
        Load the list from the specified file.
        """
        self.clear()
        
        #simple touch to create non existent files
        open(self.filename, 'a').close()

        fh = open(self.filename, 'r')
        for l in fh.readlines():
            self.add(re.split("#", l)[0].rstrip("[ , \n,\t]"))
        fh.close()

    def dump(self):
        """
        Dump the list to the specified file.
        """
        fh = open(self.filename, 'w')
        for l in self:
           fh.write(l + "\n")
        fh.close()
    
class updateFileList(fileList):
    def __init__(self, filename, url, refreshPeriod):
        fileList.__init__(self, filename)
        self.url = url
        if refreshPeriod != 0:
            self.lc = LoopingCall(self.update)
            self.lc.start(refreshPeriod)

    def processData(self, data, d):
        if(len(data) != 0):
            try:
                self.handleData(data)
            except:
                d.callback(False)
          
            self.dump()

        d.callback(True)

    def handleError(self, error, d):
        d.errback()

    def update(self):
        update_finished = Deferred()
        pageFetchedDeferred = getPageCached(self.url)
        pageFetchedDeferred.addCallback(self.processData, update_finished)
        pageFetchedDeferred.addErrback(self.handleError, update_finished)
        return update_finished

class torExitNodeList(updateFileList):
    def handleData(self, data):
        self.clear()
        data = json.loads(data)
        for relay in data['relays']:
            for ip in relay['a']:
                if(ip != ''):
                    self.add(ip)

class hashedBlockList(updateFileList):
    def handleData(self, data):
        for blockelem in data.split('\n'):
            if(blockelem != ''):
                self.add(blockelem)
