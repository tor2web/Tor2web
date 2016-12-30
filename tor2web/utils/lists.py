"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: Lists utils

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

import re
import gzip
import json
from collections import OrderedDict
from StringIO import StringIO

from twisted.internet import reactor, ssl
from twisted.internet.task import LoopingCall
from twisted.internet.defer import Deferred
from twisted.web.client import HTTPPageGetter, HTTPClientFactory

try:
    from twisted.web.client import URI
except ImportError:
    from twisted.web.client import _URI as URI

from tor2web.utils.ssl import HTTPSVerifyingContextFactory


class LimitedSizeDict(OrderedDict):
    def __init__(self, *args, **kwds):
        self.size_limit = kwds.pop("size_limit", None)
        OrderedDict.__init__(self, *args, **kwds)
        self._check_size_limit()

    def __setitem__(self, key, value):
        if key in self:
            del self[key]
        OrderedDict.__setitem__(self, key, value)
        self._check_size_limit()

    def _check_size_limit(self):
        if self.size_limit is not None:
            while len(self) > self.size_limit:
                self.popitem(last=False)


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

    def __init__(self, url, method='GET', postdata=None, headers={},
                 agent="Tor2Web (https://github.com/globaleaks/tor2web-3.0)",
                 timeout=0, cookies=None,
                 followRedirect=1):

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
    def __init__(self, filename, url='', mode='MERGE', refreshPeriod=0):
        set.__init__(self)
        self.filename = filename
        self.url = url
        self.mode = mode

        self.load()

        if url != '' and refreshPeriod != 0:
            self.lc = LoopingCall(self.update)
            self.lc.start(refreshPeriod)

    def load(self):
        """
        Load the list from the specified file.
        """
        self.clear()

        # simple touch to create non existent files
        try:
            open(self.filename, 'a').close()
        except Exception:
            pass

        try:
            with open(self.filename, 'r') as fh:
                for l in fh.readlines():
                    self.add(re.split("#", l)[0].rstrip("[ , \n,\t]"))
        except Exception:
            pass

    def dump(self):
        """
        Dump the list to the specified file.
        """
        try:
            with open(self.filename, 'w') as fh:
                for l in self:
                    fh.write(l + "\n")
        except Exception:
            pass

    def handleData(self, data):
        if self.mode == 'REPLACE':
            self.clear()

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
        if self.mode == 'REPLACE':
            self.clear()

        for ip in re.findall( r'ExitAddress ([^ ]*) ', data):
            self.add(ip)
