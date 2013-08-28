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
   :synopsis: Implementation of the Tor2web Worker

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

import os
import prctl
import re
import sys
import mimetypes
import random
import socket
import signal
import operator
import zlib
import hashlib
from StringIO import StringIO
from random import choice
from functools import partial
from urlparse import urlparse, urlunparse

from cgi import parse_header

from zope.interface import implements

from twisted.spread import pb
from twisted.internet import reactor, protocol, defer
from twisted.internet.abstract import isIPAddress, isIPv6Address
from twisted.internet.endpoints import TCP4ClientEndpoint, SSL4ClientEndpoint
from twisted.protocols.policies import WrappingFactory
from twisted.application import service, internet
from twisted.web import http, client, resource, _newclient
from twisted.web.http import StringTransport, _IdentityTransferDecoder, _ChunkedTransferDecoder, _MalformedChunkedDataError, parse_qs
from twisted.web.http_headers import Headers
from twisted.web.server import NOT_DONE_YET
from twisted.web.template import flattenString, XMLString
from twisted.web.iweb import IBodyProducer
from twisted.python import log, logfile
from twisted.python.compat import networkString, intToBytes
from twisted.python.filepath import FilePath
from twisted.internet.task import LoopingCall

from tor2web.utils.daemon import T2WDaemon
from tor2web.utils.config import VERSION
from tor2web.utils.lists import List, TorExitNodeList
from tor2web.utils.mail import sendmail, MailException
from tor2web.utils.misc import listenTCPonExistingFD, listenSSLonExistingFD, re_sub, t2w_file_path, verify_onion
from tor2web.utils.socks import SOCKS5ClientEndpoint, SOCKSError
from tor2web.utils.ssl import T2WSSLContextFactory
from tor2web.utils.storage import Storage
from tor2web.utils.templating import PageTemplate
from tor2web.utils.stats import T2WStats

SOCKS_errors = {\
    0x00: "error_sock_generic.tpl",
    0x23: "error_sock_hs_not_found.tpl",
    0x24: "error_sock_hs_not_reachable.tpl"
}

class Tor2webObj():
    def __init__(self):
        # The destination hidden service identifier
        self.onion = None

        # The path portion of the URI
        self.path = None

        # The full address (hostname + uri) that must be requested
        self.address = None

        # The headers to be sent
        self.headers = None

        # The requested uri
        self.uri = None

        # A boolean that keeps track of client gzip support
        self.client_supports_gzip = False

        # A boolean that keeps track of server gzip support
        self.server_response_is_gzip = False

        # A boolean that keeps track of document content type
        self.html = False


class BodyReceiver(protocol.Protocol):
    def __init__(self, finished):
        self._finished = finished
        self._data = []

    def dataReceived(self, bytes):
        self._data.append(bytes)

    def write(self, bytes):
        self._data.append(bytes)

    def connectionLost(self, reason):
        self._finished.callback(''.join(self._data))


class BodyStreamer(protocol.Protocol):
    def __init__(self, streamfunction, finished):
        self._finished = finished
        self._streamfunction = streamfunction

    def dataReceived(self, data):
        self._streamfunction(data)

    def connectionLost(self, reason):
        self._finished.callback('')


class BodyProducer(object):
    implements(IBodyProducer)
    
    def __init__(self):
        self.length = _newclient.UNKNOWN_LENGTH
        self.finished = defer.Deferred()
        self.consumer = None
        self.can_stream = False
        self.can_stream_d = defer.Deferred()

    def startProducing(self, consumer):
        self.consumer = consumer
        self.can_stream = True
        self.can_stream_d.callback(True)
        return self.finished

    @defer.inlineCallbacks
    def dataReceived(self, data):
        if not self.can_stream:
            yield self.can_stream_d
        self.consumer.write(data)

    def allDataReceived(self):
        self.finished.callback(None)

    def resumeProducing(self):
        pass

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass


class HTTPConnectionPool(client.HTTPConnectionPool):
    _factory = client._HTTP11ClientFactory

    def startedConnecting(self, connector):
        pass

    _factory.startedConnecting = startedConnecting

    def __init__(self, reactor, persistent=True, maxPersistentPerHost=2, cachedConnectionTimeout=240, retryAutomatically=True):
        client.HTTPConnectionPool.__init__(self, reactor, persistent)
        self.maxPersistentPerHost = maxPersistentPerHost
        self.cachedConnectionTimeout = cachedConnectionTimeout
        self.retryAutomatically = retryAutomatically


class Agent(client.Agent):
    def __init__(self, reactor,
                 contextFactory=client.WebClientContextFactory(),
                 connectTimeout=None, bindAddress=None,
                 pool=None, sockhost=None, sockport=None):
        if pool is None:
            pool = HTTPConnectionPool(reactor, False)
        self._reactor = reactor
        self._pool = pool
        self._contextFactory = contextFactory
        self._connectTimeout = connectTimeout
        self._bindAddress = bindAddress
        self._sockhost = sockhost
        self._sockport = sockport

    def _getEndpoint(self, scheme, host, port):
        kwargs = {}
        if self._connectTimeout is not None:
            kwargs['timeout'] = self._connectTimeout
        kwargs['bindAddress'] = self._bindAddress
        if scheme == 'http':
            return TCP4ClientEndpoint(self._reactor, host, port, **kwargs)
        elif scheme == 'shttp':
            return SOCKS5ClientEndpoint(self._reactor, self._sockhost,
                                        self._sockport, host, port, config['socksoptimisticdata'], **kwargs)
        elif scheme == 'https':
            return SSL4ClientEndpoint(self._reactor, host, port,
                                      self._wrapContextFactory(host, port),
                                      **kwargs)
        else:
            raise SchemeNotSupported("Unsupported scheme: %r" % (scheme,))


class T2WRequest(http.Request):
    """
    Used by Tor2webProxy to implement a simple web proxy.
    """
    def __init__(self, channel, queued, reactor=reactor):
        """
        Method overridden to change some part of proxy.Request and of the base http.Request
        """
        self.reactor = reactor
        self.notifications = []
        self.channel = channel
        self.queued = queued
        self.requestHeaders = Headers()
        self.received_cookies = {}
        self.responseHeaders = Headers()
        self.cookies = [] # outgoing cookies
        self.bodyProducer = BodyProducer()
        self.proxy_d = None
        self.proxy_response = None

        self.stream = ''

        self.header_injected = False
        # If we should disable the banner,
        # say that we have already injected it.
        if config['disable_banner']:
            self.header_injected = True

        if queued:
            self.transport = StringTransport()
        else:
            self.transport = self.channel.transport

        self.obj = Tor2webObj()
        self.var = Storage()
        self.var['version'] = VERSION
        self.var['basehost'] = config['basehost']
        self.var['errorcode'] = None

        self.html = False

        self.decoderGzip = None
        self.encoderGzip = None

        self.pool = pool

    def _cleanup(self):
        """
        Method overridden to avoid self.content actions.
        """
        if self.producer:
            log.err(RuntimeError("Producer was not unregistered for %s" % self.uri))
            self.unregisterProducer()
        self.channel.requestDone(self)
        del self.channel
        for d in self.notifications:
            d.callback(None)
        self.notifications = []

    def getRequestHostname(self):
        """
            Function overload to fix ipv6 bug:
                http://twistedmatrix.com/trac/ticket/6014
        """
        host = self.getHeader(b'host')
        if host:
            if host[0]=='[':
                return host.split(']',1)[0] + "]"
            return networkString(host.split(':', 1)[0])
        return networkString(self.getHost().host)

    def forwardData(self, data, end=False):
        if not self.startedWriting:
            if self.obj.client_supports_gzip:
                self.setHeader(b'content-encoding', b'gzip')

            if data != '' and end:
                self.setHeader(b'content-length', intToBytes(len(data)))

        if data != '':
            try:
                self.write(data)
            except:
                pass

    def requestReceived(self, command, path, version):
        """
        Method overridden to reduce the function actions
        """
        self.method, self.uri = command, path
        self.clientproto = version

        # cache the client and server information, we'll need this later to be
        # serialized and sent with the request so CGIs will work remotely
        self.client = self.channel.transport.getPeer()
        self.host = self.channel.transport.getHost()

        self.process()

    def add_banner(self, banner, data):
        """
        Inject tor2web banner inside the returned page
        """
        return str(data.group(1)) + str(banner)

    @defer.inlineCallbacks
    def handleFixPart(self, data):
        if self.obj.server_response_is_gzip:
            data = self.unzip(data)

        data = self.stream + data

        if len(data) >= 1000:
            if not self.header_injected and data.find("<body") != -1:
                banner = yield flattenString(self, templates['banner.tpl'])
                data = re.sub(rexp['body'], partial(self.add_banner, banner), data)
                self.header_injected = True

            data = re_sub(rexp['t2w'], r'https://\2.' + config['basehost'], data)

            self.forwardData(self.handleCleartextForwardPart(data[:-500]))
            self.stream = data[-500:]
        else:
            self.stream = data

    @defer.inlineCallbacks
    def handleFixEnd(self, data):
        if self.obj.server_response_is_gzip:
            data = self.unzip(data, True)

        data = self.stream + data

        if not self.header_injected and data.find("<body") != -1:
            banner = yield flattenString(self, templates['banner.tpl'])
            data = re.sub(rexp['body'], partial(self.add_banner, banner), data)
            self.header_injected = True
                
        data = re_sub(rexp['t2w'], r'https://\2.' + config['basehost'], data)

        data = self.handleCleartextForwardPart(data, True)
        self.forwardData(data, True)

        self.stream = ''

        try:
            self.finish()
        except:
            pass

    def handleGzippedForwardPart(self, data, end=False):
        if not self.obj.client_supports_gzip:
            data = self.unzip(data, end)

        return data

    def handleCleartextForwardPart(self, data, end=False):
        if self.obj.client_supports_gzip:
           data = self.zip(data, end)
        
        return data

    def handleForwardPart(self, data):
        if self.obj.server_response_is_gzip:
            data = self.handleGzippedForwardPart(data)
        else:
            data = self.handleCleartextForwardPart(data)

        self.forwardData(data)

    def handleForwardEnd(self, data):
        if self.obj.server_response_is_gzip:
            data = self.handleGzippedForwardPart(data, True)
        else:
            data = self.handleCleartextForwardPart(data, True)

        self.forwardData(data, True)
        try:
            self.finish()
        except:
            pass

    def contentFinish(self, data):
        if self.obj.client_supports_gzip:
            self.setHeader(b'content-encoding', b'gzip')
            data = self.zip(data, True)

        self.setHeader(b'content-length', intToBytes(len(data)))

        try:
            self.write(data)
            self.finish()
        except:
            pass

    def sendError(self, error=500, errortemplate='error_generic.tpl'):
        self.setResponseCode(error)
        self.var['errorcode'] = error
        return flattenString(self, templates[errortemplate]).addCallback(self.contentFinish)

    def handleError(self, failure):
        if type(failure.value) is SOCKSError:
            self.setResponseCode(404)
            self.var['errorcode'] = failure.value.code
            if failure.value.code in SOCKS_errors:
                return flattenString(self, templates[SOCKS_errors[failure.value.code]]).addCallback(self.contentFinish)
            else:
                return flattenString(self, templates[SOCKS_errors[0x00]]).addCallback(self.contentFinish)
        else:
            self.sendError()

    def unzip(self, data, end=False):
        data1 = data2 = ''

        try:
            if self.decoderGzip == None:
                self.decoderGzip = zlib.decompressobj(16 + zlib.MAX_WBITS)

            if data != '':
                data1 = self.decoderGzip.decompress(data)

            if end:
                data2 = self.decoderGzip.flush()

        except:
            pass

        return data1 + data2

    def zip(self, data, end=False):
        data1 = data2 = ''

        try:
            if self.encoderGzip == None:
                self.encoderGzip = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)

            if data != '':
                data1 = self.encoderGzip.compress(data)

            if end:
                data2 = self.encoderGzip.flush()
        except:
            pass

        return data1 + data2

    def process_request(self, req):
        """
        This function:
            - "resolves" the address;
            - alters and sets the proper headers.
        """
        t2w_log(req)

        self.obj.host_tor = "http://" + self.obj.onion
        self.obj.host_tor2web = "https://" + self.obj.onion.replace(".onion", "") + "." + config['basehost']
        self.obj.address = "http://" + self.obj.onion + self.obj.uri

        self.obj.headers = req.headers

        t2w_log("Headers before fix:")
        t2w_log(self.obj.headers)

        self.obj.headers.removeHeader(b'if-modified-since')
        self.obj.headers.removeHeader(b'if-none-match')
        self.obj.headers.setRawHeaders(b'host', [self.obj.onion])
        self.obj.headers.setRawHeaders(b'connection', [b'keep-alive'])
        self.obj.headers.setRawHeaders(b'Accept-encoding', [b'gzip, chunked'])
        self.obj.headers.setRawHeaders(b'x-tor2web', [b'encrypted'])

        for key, values in self.obj.headers.getAllRawHeaders():
            fixed_values = []
            for value in values:
                value = re_sub(rexp['w2t'], r'http://\2.onion', value)
                fixed_values.append(value)

            self.obj.headers.setRawHeaders(key, fixed_values)

        t2w_log("Headers after fix:")
        t2w_log(self.obj.headers)

        return True

    @defer.inlineCallbacks
    def process(self):
        content = ""

        request = Storage()
        request.headers = self.requestHeaders
        request.host = self.getRequestHostname()
        request.uri = self.uri

        content_length = self.getHeader(b'content-length')
        transfer_encoding = self.getHeader(b'transfer-encoding')

        staticpath = request.uri
        staticpath = re.sub('\/$', '/index.html', staticpath)
        staticpath = re.sub('^(/antanistaticmap/)?', '', staticpath)
        staticpath = re.sub('^/', '', staticpath)

        resource_is_local = isIPAddress(request.host) or \
                            isIPv6Address(request.host) or \
                            (config['overriderobotstxt'] and request.uri == '/robots.txt') or \
                            request.uri.startswith('/antanistaticmap/')

        if content_length is not None:
            self.bodyProducer.length = int(content_length)
            producer = self.bodyProducer
            request.headers.removeHeader(b'content-length')
        elif transfer_encoding is not None:
            producer = self.bodyProducer
            request.headers.removeHeader(b'transfer-encoding')
        else:
            producer = None

        if config['mirror'] is not None:
            if config['basehost'] in config['mirror']:
                config['mirror'].remove(config['basehost'])
            self.var['mirror'] = choice(config['mirror'])

        # we serve contents only over https
        if not self.isSecure() and (config['transport'] != 'HTTP'):
            self.redirect("https://" + request.host + request.uri)
            self.finish()
            return

        # 0: Request admission control stage
        # we try to deny some ua/crawlers regardless the request is (valid or not) / (local or not)
        # we deny EVERY request to known user agents reconized with pattern matching
        if config['blockcrawl'] and request.headers.getRawHeaders(b'user-agent') != None:
            for ua in blocked_ua_list:
                if re.match(ua, request.headers.getRawHeaders(b'user-agent')[0].lower()):
                    self.sendError(403, "error_blocked_ua.tpl")
                    defer.returnValue(NOT_DONE_YET)

        # 1: Client capability assessment stage
        if request.headers.getRawHeaders(b'accept-encoding') != None:
            if re.search('gzip', request.headers.getRawHeaders(b'accept-encoding')[0]):
                self.obj.client_supports_gzip = True

        # 2: Content delivery stage
        # we need to verify if the requested resource is local (/antanistaticmap/*) or remote
        # because some checks must be done only for remote requests;
        # in fact local content is always served (css, js, and png in fact are used in errors)
        if resource_is_local:
            # the requested resource is local, we deliver it directly
            try:
                if staticpath == "dev/null":
                    content = "A" * random.randint(20, 1024)
                    defer.returnValue(self.contentFinish(content))
                    return
                
                elif staticpath == "stats/yesterday":
                    content = yield rpc("get_yesterday_stats")
                    defer.returnValue(self.contentFinish(content))
                    return

                elif staticpath == "notification":
 
                    #################################################################
                    # Here we need to parse POST data in x-www-form-urlencoded format
                    #################################################################
                    content_receiver = BodyReceiver(defer.Deferred())
                    self.bodyProducer.startProducing(content_receiver)
                    yield self.bodyProducer.finished
                    content = ''.join(content_receiver._data)

                    args = {}

                    ctype = self.requestHeaders.getRawHeaders(b'content-type')
                    if ctype is not None:
                        ctype = ctype[0]

                    if self.method == b"POST" and ctype:
                        mfd = b'multipart/form-data'
                        key, pdict = parse_header(ctype)
                        if key == b'application/x-www-form-urlencoded':
                            args.update(parse_qs(content, 1))
                    #################################################################
                    
                    if 'by' in args and 'url' in args and 'comment' in args:
                        tmp = []
                        tmp.append("From: Tor2web Node %s.%s <%s>\n" % (config['nodename'], config['basehost'], config['smtpmail']))
                        tmp.append("To: %s\n" % (config['smtpmailto_notifications']))
                        tmp.append("Subject: Tor2web Node (IPv4 %s, IPv6 %s): notification for %s\n" % (config['listen_ipv4'], config['listen_ipv6'], args['url'][0]))
                        tmp.append("Content-Type: text/plain; charset=ISO-8859-1\n")
                        tmp.append("Content-Transfer-Encoding: 8bit\n\n")
                        tmp.append("BY: %s\n" % (args['by'][0]))
                        tmp.append("URL: %s\n" % (args['url'][0]))
                        tmp.append("COMMENT: %s\n" % (args['comment'][0]))
                        message = StringIO(''.join(tmp))

                        try:
                            sendmail(config['smtpuser'], config['smtppass'], config['smtpmail'], config['smtpmailto_notifications'], message, config['smtpdomain'], config['smtpport'])
                        except:
                            pass

                        defer.returnValue(self.contentFinish(''))

                else:
                    if type(antanistaticmap[staticpath]) == str:
                        filename, ext = os.path.splitext(staticpath)
                        self.setHeader(b'content-type', mimetypes.types_map[ext])
                        content = antanistaticmap[staticpath]
                        defer.returnValue(self.contentFinish(content))

                    elif type(antanistaticmap[staticpath]) == PageTemplate:
                        defer.returnValue(flattenString(self, antanistaticmap[staticpath]).addCallback(self.contentFinish))

            except:
                pass
            
            self.sendError(404)
            defer.returnValue(NOT_DONE_YET)

        else:
            self.obj.uri = request.uri

            if not request.host:
                self.sendError(406, 'error_invalid_hostname.tpl')
                defer.returnValue(NOT_DONE_YET)

            if config['mode'] == "TRANSLATION":
                self.obj.onion = config['onion']
            else:
                self.obj.onion = request.host.split(".")[0] + ".onion"
                t2w_log("detected <onion_url>.tor2web Hostname: %s" % self.obj.onion)
                if not verify_onion(self.obj.onion):
                    self.sendError(406, 'error_invalid_hostname.tpl')
                    defer.returnValue(NOT_DONE_YET)

                if config['mode'] == "ACCESSLIST":
                    if not hashlib.md5(self.obj.onion) in access_list:
                        self.sendError(403, 'error_hs_completely_blocked.tpl')
                        defer.returnValue(NOT_DONE_YET)

                elif config['mode'] == "BLACKLIST":
                    if hashlib.md5(self.obj.onion).hexdigest() in access_list:
                        self.sendError(403, 'error_hs_completely_blocked.tpl')
                        defer.returnValue(NOT_DONE_YET)

                    if hashlib.md5(self.obj.onion + self.obj.uri).hexdigest() in access_list:
                        self.sendError(403, 'error_hs_specific_page_blocked.tpl')
                        defer.returnValue(NOT_DONE_YET)

            # we need to verify if the user is using tor;
            # on this condition it's better to redirect on the .onion
            if self.getClientIP() in tor_exits_list:
                self.redirect("http://" + self.obj.onion + request.uri)

                try:
                    self.finish()
                except:
                    pass

                return

            # Avoid image hotlinking
            if request.uri.lower().endswith(('gif','jpg','png')):
                if request.headers.getRawHeaders(b'referer') != None and not config['basehost'] in request.headers.getRawHeaders(b'referer')[0].lower():
                    self.sendError(403)
                    defer.returnValue(NOT_DONE_YET)

            # the requested resource is remote, we act as proxy

            self.process_request(request)

            parsed = urlparse(self.obj.address)

            self.var['address'] = self.obj.address
            self.var['onion'] = self.obj.onion.replace(".onion", "")
            self.var['path'] = parsed[2]
            if parsed[3] is not None and parsed[3] != '':
                self.var['path'] += '?' + parsed[3]

            agent = Agent(reactor, sockhost=config['sockshost'], sockport=config['socksport'], pool=self.pool)
            self.proxy_d = agent.request(self.method,
                                         's' + self.obj.address,
                                         self.obj.headers, bodyProducer=producer)

            self.proxy_d.addCallback(self.cbResponse)
            self.proxy_d.addErrback(self.handleError)

            defer.returnValue(NOT_DONE_YET)

    def cbResponse(self, response):
        self.proxy_response = response
        if int(response.code) >= 600 and int(response.code) <= 699:
            self.setResponseCode(500)
            self.var['errorcode'] = int(response.code) - 600
            if self.var['errorcode'] in SOCKS_errors:
                return flattenString(self, templates[SOCKS_errors[self.var['errorcode']]]).addCallback(self.contentFinish)
            else:
                return flattenString(self, templates[SOCKS_errors[0x00]]).addCallback(self.contentFinish)

        self.setResponseCode(response.code)

        self.processResponseHeaders(response.headers)

        if(response.length is not 0):
            finished = defer.Deferred()
            if self.obj.html:
                response.deliverBody(BodyStreamer(self.handleFixPart, finished))
                finished.addCallback(self.handleFixEnd)
            else:
                response.deliverBody(BodyStreamer(self.handleForwardPart, finished))
                finished.addCallback(self.handleForwardEnd)

            return finished
        else:
            self.contentFinish('')
            return defer.succeed

    def handleHeader(self, key, values):
        keyLower = key.lower()
        
        # some headers does not allow multiple occurrences
        # in case of multiple occurrences we evaluate only the first
        valueLower = values[0].lower()

        if keyLower == 'transfer-encoding' and valueLower == 'chunked':
            return

        elif keyLower == 'content-encoding' and valueLower == 'gzip':
            self.obj.server_response_is_gzip = True
            return

        elif keyLower == 'content-type' and re.search('text/html', valueLower):
            self.obj.html = True

        elif keyLower == 'content-length':
            self.receivedContentLen = valueLower
            return

        elif keyLower == 'cache-control':
            return

        if keyLower in ('location'):
            fixed_values = []
            for value in values:
                value = re_sub(rexp['t2w'], r'https://\2.' + config['basehost'], value)
                fixed_values.append(value)
            values = fixed_values
        
        self.responseHeaders.setRawHeaders(key, values)

    def handleEndHeaders(self):
        self.setHeader(b'cache-control', b'no-cache')
        self.setHeader(b'strict-transport-security', b'max-age=31536000')

    def processResponseHeaders(self, headers):
        # currently we track only responding hidden services
        # we don't need to block on the rpc now so no yield is needed
        rpc("update_stats", str(self.obj.onion.replace(".onion", "")))

        for key, values in headers.getAllRawHeaders():
            self.handleHeader(key, values)

        self.handleEndHeaders()

    def connectionLost(self, reason):
        try:
            if self.proxy_d:
                self.proxy_d.cancel()
        except:
            pass

        try:
            if self.proxy_response:
                self.proxy_response._transport.stopProducing()
        except:
            pass

        try:
            http.Request.connectionLost(self, reason)
        except:
            pass

    def finish(self):
        try:
            http.Request.finish(self)
        except:
            pass

class T2WProxy(http.HTTPChannel):
    requestFactory = T2WRequest

    def headerReceived(self, line):
        """
        Overridden to reduce the function actions and
        in particular to avoid self._transferDecoder actions and
        implement a streaming proxy
        """
        header, data = line.split(b':', 1)
        header = header.lower()
        data = data.strip()
        req = self.requests[-1]
        if header == b'content-length':
            try:
                self.length = int(data)
            except ValueError:
                self.transport.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                self.length = None
                self.transport.loseConnection()
                return
            self._transferDecoder = _IdentityTransferDecoder(
                self.length, req.bodyProducer.dataReceived, self._finishRequestBody)
        elif header == b'transfer-encoding' and data.lower() == b'chunked':
            self.length = None
            self._transferDecoder = _ChunkedTransferDecoder(
                req.bodyProducer.dataReceived, self._finishRequestBody)
        reqHeaders = req.requestHeaders
        values = reqHeaders.getRawHeaders(header)
        if values is not None:
            values.append(data)
        else:
            reqHeaders.setRawHeaders(header, [data])

    def allHeadersReceived(self):
        """
        Overridden to reduce the function actions
        """
        req = self.requests[-1]
        self.persistent = self.checkPersistence(req, self._version)

        req.requestReceived(self._command, self._path, self._version)

    def allContentReceived(self):
        if len(self.requests):
            req = self.requests[-1]
            req.bodyProducer.allDataReceived()
        
        # reset ALL state variables, so we don't interfere with next request
        self.length = 0
        self._receivedHeaderCount = 0
        self._HTTPChannel__first_line = 1
        self._transferDecoder = None
        del self._command, self._path, self._version

        # Disable the idle timeout, in case this request takes a long
        # time to finish generating output.
        if self.timeOut:
            self._savedTimeOut = self.setTimeout(None)

class T2WProxyFactory(http.HTTPFactory):
    protocol = T2WProxy

    def _openLogFile(self, path):
        return log.NullFile()

    def log(self, request):
        """
        Log a request's result to the logfile, by default in combined log format.
        """
        if config['logreqs']:
            line = "127.0.0.1 (%s) - - %s \"%s\" %s %s \"%s\" \"%s\"\n" % (
                self._escape(request.getHeader(b'host')),
                self._logDateTime,
                '%s %s %s' % (self._escape(request.method),
                              self._escape(request.uri),
                              self._escape(request.clientproto)),
                request.code,
                request.sentLength or "-",
                self._escape(request.getHeader(b'referer') or "-"),
                self._escape(request.getHeader(b'user-agent') or "-"))

            rpc("log_access", str(line))

class T2WLimitedRequestsFactory(WrappingFactory):
    def __init__(self, wrappedFactory, allowedRequests):
        WrappingFactory.__init__(self, wrappedFactory)
        self.requests_countdown = allowedRequests

    def registerProtocol(self, p):
        """
        Called by protocol to register itself.
        """
        WrappingFactory.registerProtocol(self, p)

        if self.requests_countdown > 0:
            self.requests_countdown -= 1

        if self.requests_countdown == 0:
            # bai bai mai friend
            #
            # known bug: currently when the limit is reached all
            #            the active requests are trashed.
            #            this simple solution is used to achive
            #            stronger stability.
            try:
                reactor.stop()
            except:
                pass

@defer.inlineCallbacks
def rpc(f, *args, **kwargs):
    d = rpc_factory.getRootObject()
    d.addCallback(lambda object: object.callRemote(f,  *args, **kwargs))
    ret = yield d
    defer.returnValue(ret)
    
def t2w_log(msg):
    rpc("log_debug", str(msg))
    print msg

@defer.inlineCallbacks
def start():
    global config
    global antanistaticmap
    global templates
    global pool
    global rexp
    global fds_https
    global fds_http
    global ports

    config = yield rpc("get_config")

    lc = LoopingCall(updateTask)
    lc.start(600)

    rexp = {
        'body': re.compile(r'(<body.*?\s*>)', re.I),
        'w2t': re.compile(r'(http.?:)?//([a-z0-9]{16}).' + config['basehost'] + '(?!:\d+)', re.I),
        't2w': re.compile(r'(http.?:)?//([a-z0-9]{16}).(?!' + config['basehost'] + ')onion(?!:\d+)', re.I)
    }

    ###############################################################################
    # Templates loading
    ###############################################################################
    antanistaticmap = {}

    files = FilePath('/usr/share/tor2web/static/').globChildren("*")
    for file in files:
        file = FilePath(t2w_file_path(config['datadir'], os.path.join('static', file.basename())))
        antanistaticmap[file.basename()] = file.getContent()

    # we add additional files eventually written in datadir/static
    # and not already loaded by previos lines.
    if os.path.exists(os.path.join(config['datadir'], "static/")):
        for file in files:
            if file.basename() not in antanistaticmap:
                antanistaticmap[file.basename()] = file.getContent()

    ###############################################################################

    ###############################################################################
    # Templates loading
    ###############################################################################
    templates = {}

    files = FilePath('/usr/share/tor2web/templates/').globChildren("*.tpl")
    for file in files:
        file = FilePath(t2w_file_path(config['datadir'], os.path.join('templates', file.basename())))
        templates[file.basename()] = PageTemplate(XMLString(file.getContent()))
    ###############################################################################

    pool = HTTPConnectionPool(reactor, True,
                              config['sockmaxpersistentperhost'],
                              config['sockcachedconnectiontimeout'],
                              config['sockretryautomatically'])

    factory = T2WProxyFactory()

    # we do not want all workers to die in the same moment
    requests_countdown = config['requests_per_process'] / random.randint(1, 3)

    factory = T2WLimitedRequestsFactory(factory, requests_countdown)

    context_factory = T2WSSLContextFactory(os.path.join(config['datadir'], "certs/tor2web-key.pem"),
                                                       os.path.join(config['datadir'], "certs/tor2web-intermediate.pem"),
                                                       os.path.join(config['datadir'], "certs/tor2web-dh.pem"),
                                                       config['cipher_list'])

    if config['debugmode'] and config['debugtostdout']:
        log.startLogging(sys.stdout)
    else:
        log.startLogging(log.NullFile)

    fds_https = filter(None, args[0].split(","))
    fds_https = [int(i) for i in fds_https]

    fds_http = filter(None, args[1].split(","))
    fds_http = [int(i) for i in fds_http]

    reactor.listenTCPonExistingFD = listenTCPonExistingFD
    reactor.listenSSLonExistingFD = listenSSLonExistingFD

    for fd in fds_https:
        ports.append(reactor.listenSSLonExistingFD(reactor,
                                                   fd=fd,
                                                   factory=factory,
                                                   contextFactory=context_factory))

    for fd in fds_http:
        ports.append(reactor.listenTCPonExistingFD(reactor,
                                                   fd=fd,
                                                   factory=factory))

    sys.excepthook = MailException

def updateTask():
    def set_access_list(l):
        global access_list
        access_list = l

    def set_blocked_ua_list(l):
        global blocked_ua_list
        blocked_ua_list = l

    def set_tor_exits_list(l):
        global tor_exits_list
        tor_exits_list = l

    d = rpc("get_access_list")
    d.addCallback(set_access_list)

    d = rpc("get_blocked_ua_list")
    d.addCallback(set_blocked_ua_list)

    d = rpc("get_tor_exits_list")
    d.addCallback(set_tor_exits_list)

def SigQUIT(SIG, FRM):
    reactor.stop()

args = sys.argv[1:]
if len(sys.argv[1:]) != 2:
    exit(1)

access_list = []
blocked_ua_list = []
tor_exits_list = []
ports = []

rpc_factory = pb.PBClientFactory()
reactor.connectUNIX(os.path.join("/var/run/tor2web/rpc.socket"),  rpc_factory)

signal.signal(signal.SIGUSR1, SigQUIT)
signal.signal(signal.SIGTERM, SigQUIT)
signal.signal(signal.SIGINT, SigQUIT)

prctl.set_pdeathsig(signal.SIGINT)
prctl.set_proctitle("tor2web-worker")

start()

reactor.run()

exit(0)
