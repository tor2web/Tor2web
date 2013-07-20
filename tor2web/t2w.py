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
import sys
import mimetypes
import zlib
import hashlib
from StringIO import StringIO
from random import choice
from functools import partial
from urlparse import urlparse

from cgi import parse_header

from zope.interface import implements

from twisted.internet import reactor, protocol, defer
from twisted.internet.abstract import isIPAddress, isIPv6Address
from twisted.internet.endpoints import TCP4ClientEndpoint, SSL4ClientEndpoint
from twisted.application import service, internet
from twisted.web import http, client, resource, _newclient
from twisted.web.http import StringTransport, _IdentityTransferDecoder, _ChunkedTransferDecoder, _MalformedChunkedDataError, parse_qs
from twisted.web.http_headers import Headers
from twisted.web.server import NOT_DONE_YET
from twisted.web.template import flattenString, XMLString
from twisted.web.iweb import IBodyProducer
from twisted.python import log, logfile, failure
from twisted.python.compat import networkString, intToBytes
from twisted.python.filepath import FilePath

from tor2web.utils.config import VERSION, config
from tor2web.utils.lists import List, torExitNodeList
from tor2web.utils.mail import sendmail, MailException
from tor2web.utils.socks import SOCKS5ClientEndpoint, SOCKSError
from tor2web.utils.ssl import T2WSSLContextFactory
from tor2web.utils.storage import Storage
from tor2web.utils.templating import PageTemplate

SOCKS_errors = {\
    0x00: "error_sock_generic.tpl",
    0x23: "error_sock_hs_not_found.tpl",
    0x24: "error_sock_hs_not_reachable.tpl"
}

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
        log.msg('onion: %s tld: %s' % (onion, tld))
        if tld == 'onion' and len(onion) == 16 and onion.isalnum():
            return True
    except:
        pass

    return False
    
def verify_resource_is_local(host, uri, path):
    return isIPAddress(host) or isIPv6Address(host) or uri.startswith(path)

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

        self.error = {}

        self.client_supports_gzip = False

        self.server_response_is_gzip = False

        self.contentNeedFix = False

class Tor2web(object):
    def __init__(self, config):
        """
        Process tor2web requests, fix links, inject banner and
        all that happens between a client request and the fetching
        of the content from the Tor Hidden Service.

        :config a config object
        """
        self.config = config

        self.accesslist = []
        if config.mode == "TRANSLATION":
            pass

        elif config.mode == "WHITELIST":
            self.accesslist = List(os.path.join(config.datadir, 'lists', 'whitelist.txt'))
        
        elif config.mode == "BLACKLIST":
            self.accesslist = List(os.path.join(config.datadir, 'lists', 'blocklist_hashed.txt'))

            # clear local cleartext list
            # (load -> hash -> clear feature; for security reasons)
            self.blocklist_cleartext = List(os.path.join(config.datadir, 'lists', 'blocklist_cleartext.txt'))
            for i in self.blocklist_cleartext:
                self.accesslist.add(hashlib.md5(i).hexdigest())

            self.accesslist.dump()

            self.blocklist_cleartext.clear()
            self.blocklist_cleartext.dump()

        self.blocked_ua = []
        if config.blockcrawl:
            tmp = List(os.path.join(config.datadir, 'lists', 'blocked_ua.txt'))
            for ua in tmp:
                self.blocked_ua.append(ua.lower())

        # Load Exit Nodes list with the refresh rate configured  in config file
        self.TorExitNodes = torExitNodeList(os.path.join(config.datadir, 'lists', 'exitnodelist.txt'),
                                            "https://onionoo.torproject.org/summary?type=relay",
                                            config.exit_node_list_refresh)

    def process_request(self, obj, req):
        """
        This function:
            - "resolves" the address;
            - alters and sets the proper headers.
        """
        log.msg(req)

        obj.host_tor = "http://" + obj.onion
        obj.host_tor2web = "https://" + obj.onion.replace(".onion", "") + "." + config.basehost
        obj.address = "http://" + obj.onion + obj.uri

        obj.headers = req.headers

        log.msg("Headers before fix:")
        log.msg(obj.headers)

        obj.headers.removeHeader(b'if-modified-since')
        obj.headers.removeHeader(b'if-none-match')
        obj.headers.setRawHeaders(b'host', [obj.onion])
        obj.headers.setRawHeaders(b'connection', [b'keep-alive'])
        obj.headers.setRawHeaders(b'accept-encoding', [b'gzip, chunked'])
        obj.headers.setRawHeaders(b'x-tor2web', [b'encrypted'])

        for key, values in obj.headers.getAllRawHeaders():
            fixed_values = []
            for value in values:
                value = re_sub(rexp['w2t'], r'http://\2.onion', value)
                fixed_values.append(value)

            obj.headers.setRawHeaders(key, fixed_values)

        log.msg("Headers after fix:")
        log.msg(obj.headers)

        return True

    def add_banner(self, obj, banner, data):
        """
        Inject tor2web banner inside the returned page
        """
        return str(data.group(1)) + str(banner)

    def process_html(self, obj, banner, data):
        """
        Process the result from the Hidden Services HTML
        """
        log.msg("processing HTML type content")
        
        data = re_sub(rexp['t2w'], r'https://\2.' + config.basehost, data)

        data = re.sub(rexp['body'], partial(self.add_banner, obj, banner), data)

        return data

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
                                        self._sockport, host, port, config.socksoptimisticdata, **kwargs)
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
    staticmap = "/antanistaticmap/"

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

        if queued:
            self.transport = StringTransport()
        else:
            self.transport = self.channel.transport

        self.obj = Tor2webObj()
        self.var = Storage()
        self.var['version'] = VERSION
        self.var['basehost'] = config.basehost
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
            self.write(data)

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

        self.forwardData(data, False)

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
        self.write(data)
        try:
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

    @defer.inlineCallbacks
    def process(self):
        content = ""

        request = Storage()
        request.headers = self.requestHeaders
        request.host = self.getRequestHostname()
        request.uri = self.uri

        content_length = self.getHeader(b'content-length')
        transfer_encoding = self.getHeader(b'transfer-encoding')

        if content_length is not None:
            self.bodyProducer.length = int(content_length)
            producer = self.bodyProducer
            request.headers.removeHeader(b'content-length')
        elif transfer_encoding is not None:
            producer = self.bodyProducer
            request.headers.removeHeader(b'transfer-encoding')
        else:
            producer = None

        if config.mirror is not None:
            self.var['mirror'] = choice(config.mirror)

        # we serve contents only over https
        if not self.isSecure():
            self.redirect("https://" + request.host + request.uri)
            self.finish()
            return

        # 0: Request admission control stage
        # firstly we try to instruct spiders that honour robots.txt that we don't want to get indexed
        if request.uri == "/robots.txt" and config.blockcrawl:
            self.write("User-Agent: *\nDisallow: /\n")
            self.finish()
            return

        # secondly we try to deny some ua/crawlers regardless the request is (valid or not) / (local or not)
        # we deny EVERY request to known user agents reconized with pattern matching
        if request.headers.getRawHeaders(b'user-agent') != None:
            for ua in t2w.blocked_ua:
                check = request.headers.getRawHeaders(b'user-agent')[0].lower()
                if re.match(ua, check):
                    self.sendError(403, "error_blocked_ua.tpl")
                    defer.returnValue(NOT_DONE_YET)

        # we need to verify if the requested resource is local (/antanistaticmap/*) or remote
        # because some checks must be done only for remote requests;
        # in fact local content is always served (css, js, and png in fact are used in errors)

        if not verify_resource_is_local(request.host, request.uri, self.staticmap):
            if not request.host:
                self.sendError(406, 'error_invalid_hostname.tpl')
                defer.returnValue(NOT_DONE_YET)

            if config.mode == "TRANSLATION":
                self.obj.onion = config.onion
            else:
                self.obj.onion = request.host.split(".")[0] + ".onion"
                log.msg("detected <onion_url>.tor2web Hostname: %s" % self.obj.onion)
                if not verify_onion(self.obj.onion):
                    self.sendError(406, 'error_invalid_hostname.tpl')
                    defer.returnValue(NOT_DONE_YET)

                if config.mode == "ACCESSLIST":
                    if self.obj.onion not in self.accesslist:
                        self.sendError(403, 'error_hs_completely_blocked.tpl')
                        defer.returnValue(NOT_DONE_YET)

                elif config.mode == "BLOCKLIST":
                    if hashlib.md5(self.obj.onion).hexdigest() in self.accesslist:
                        self.sendError(403, 'error_hs_completely_blocked.tpl')
                        defer.returnValue(NOT_DONE_YET)

                    if hashlib.md5(self.obj.onion + self.obj.uri).hexdigest() in accesslist:
                        self.sendError(403, 'error_hs_specific_page_blocked.tpl')
                        defer.returnValue(NOT_DONE_YET)
            
            self.obj.uri = request.uri

            # we need to verify if the user is using tor;
            # on this condition it's better to redirect on the .onion
            if self.getClientIP() in t2w.TorExitNodes:
                self.redirect("http://" + self.obj.onion + request.uri)
                self.finish()
                return

            # Avoid image hotlinking
            if request.uri.lower().endswith(('gif','jpg','png')):
                if request.headers.getRawHeaders(b'referer') != None and not config.basehost in request.headers.getRawHeaders(b'referer')[0].lower():
                    self.sendError(403)
                    defer.returnValue(NOT_DONE_YET)

        # 1: Client capability assesment stage
        if request.headers.getRawHeaders(b'accept-encoding') != None:
            if re.search('gzip', request.headers.getRawHeaders(b'accept-encoding')[0]):
                self.obj.client_supports_gzip = True

        # 2: Content delivery stage
        if verify_resource_is_local(request.host, request.uri, self.staticmap):
            # the requested resource is local, we deliver it directly
            try:
                staticpath = request.uri
                staticpath = re.sub('\/$', '/index.html', staticpath)
                staticpath = re.sub('^('+self.staticmap+')?', '', staticpath)
                staticpath = re.sub('^/', '', staticpath)
                if staticpath in antanistaticmap:
                    if type(antanistaticmap[staticpath]) == str:
                        filename, ext = os.path.splitext(staticpath)
                        self.setHeader(b'content-type', mimetypes.types_map[ext])
                        content = antanistaticmap[staticpath]
                    elif type(antanistaticmap[staticpath]) == PageTemplate:
                        defer.returnValue(flattenString(self, antanistaticmap[staticpath]).addCallback(self.contentFinish))
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
                        tmp.append("From: Tor2web Node %s.%s <%s>\n" % (config.nodename, config.basehost, config.smtpmail))
                        tmp.append("To: %s\n" % (config.smtpmailto_notifications))
                        tmp.append("Subject: Tor2web Node (IPv4 %s, IPv6 %s): notification for %s\n" % (config.listen_ipv4, config.listen_ipv6, args['url'][0]))
                        tmp.append("Content-Type: text/plain; charset=ISO-8859-1\n")
                        tmp.append("Content-Transfer-Encoding: 8bit\n\n")
                        tmp.append("BY: %s\n" % (args['by'][0]))
                        tmp.append("URL: %s\n" % (args['url'][0]))
                        tmp.append("COMMENT: %s\n" % (args['comment'][0]))
                        message = StringIO(''.join(tmp))
                        try:
                            sendmail(config.smtpuser, config.smtppass, config.smtpmail, config.smtpmailto_notifications, message, config.smtpdomain, config.smtpport)
                        except:
                            pass
                    else:
                        self.sendError(404)
                        defer.returnValue(NOT_DONE_YET)

            except:
                self.sendError(404)
                defer.returnValue(NOT_DONE_YET)

            defer.returnValue(self.contentFinish(content))

        else:
            # the requested resource is remote, we act as proxy

            t2w.process_request(self.obj, request)

            parsed = urlparse(self.obj.address)

            self.var['address'] = self.obj.address
            self.var['onion'] = parsed[1]
            self.var['path'] = parsed[2] + '?' + parsed[3]

            agent = Agent(reactor, sockhost=config.sockshost, sockport=config.socksport, pool=self.pool)
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
            if self.obj.contentNeedFix:
                response.deliverBody(BodyReceiver(finished))
                finished.addCallback(self.processResponseBody)

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
            self.obj.contentNeedFix = True
            self.html = True

        elif keyLower == 'content-length':
            self.receivedContentLen = valueLower
            return

        elif keyLower == 'cache-control':
            return

        fixed_values = []
        for value in values:
            value = re_sub(rexp['t2w'], r'https://\2.' + config.basehost, value)
            fixed_values.append(value)

        self.responseHeaders.setRawHeaders(key, fixed_values)

    def handleEndHeaders(self):
        self.setHeader(b'cache-control', b'no-cache')
        self.setHeader(b'strict-transport-security', b'max-age=31536000')

    def processResponseHeaders(self, headers):
        for key, values in headers.getAllRawHeaders():
            self.handleHeader(key, values)

        self.handleEndHeaders()

    def handleHTMLData(self, header, data):
        data = t2w.process_html(self.obj, header, data)

        self.contentFinish(data)

    def processResponseBody(self, data):
        if self.obj.server_response_is_gzip:
            data = self.unzip(data, True)

        if data and self.obj.contentNeedFix:
            if self.html:
                d = flattenString(self, templates['banner.tpl'])
                d.addCallback(self.handleHTMLData, data)
                return

        self.contentFinish(data)

    def connectionLost(self, reason):
        try:
            if self.proxy_d:
                self.proxy_d.cancel()
        except:
            pass
        try:
            if self.proxy_response:
                self.proxy_response._transport.stopProducing()
                self.proxy_response._transport.abortConnection()
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
        self._HTTPChannel__first_line = 1
        self._transferDecoder = None
        del self._command, self._path, self._version

        # Disable the idle timeout, in case this request takes a long
        # time to finish generating output.
        if self.timeOut:
            self._savedTimeOut = self.setTimeout(None)

    def rawDataReceived(self, data):
        self.resetTimeout()

        try:
            self._transferDecoder.dataReceived(data)
        except _MalformedChunkedDataError:
            self.transport.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            self.transport.loseConnection()

class T2WProxyFactory(http.HTTPFactory):
    protocol = T2WProxy

    def _openLogFile(self, path):
        return logfile.DailyLogFile.fromFullPath(path)

    def log(self, request):
        """
        Log a request's result to the logfile, by default in combined log format.
        """
        if config.logreqs and hasattr(self, "logFile"):
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
            self.logFile.write(line)

def startTor2webHTTP(t2w, f, ip):
    return internet.TCPServer(int(t2w.config.listen_port_http), f, interface=ip)

def startTor2webHTTPS(t2w, f, ip):
    return internet.SSLServer(int(t2w.config.listen_port_https), f,
                              T2WSSLContextFactory(os.path.join(config.datadir, "certs/tor2web-key.pem"),
                                                   os.path.join(config.datadir, "certs/tor2web-intermediate.pem"),
                                                   os.path.join(config.datadir, "certs/tor2web-dh.pem"),
                                                   t2w.config.cipher_list),
                              interface=ip)

###############################################################################
# Basic Safety Checks
###############################################################################
config.load()

if not os.path.exists(config.datadir):
    print "Tor2web Startup Failure: unexistent directory (%s)" % config.datadir
    exit(1)

if config.mode not in [ 'TRANSLATION', 'WHITELIST', 'BLACKLIST' ]:
    print "Tor2web Startup Failure: config.mode must be one of: TRANSLATION / WHITELIST / BLACKLIST"
    exit(1)

if config.mode == "TRANSLATION":
    if not verify_onion(config.onion):
        print "Tor2web Startup Failure: TRANSLATION config.mode require config.onion configuration"
        exit(1)        
    
for d in [ 'certs',  'lists', 'logs',  'static', 'templates']:
    path = os.path.join(config.datadir, d)
    if not os.path.exists(path):
        print "Tor2web Startup Failure: unexistent directory (%s)" % path
        exit(1)
files =[]
files.append('certs/tor2web-key.pem')
files.append('certs/tor2web-intermediate.pem')
files.append('certs/tor2web-dh.pem')
for f in files:
    path = os.path.join(config.datadir, f)
    try:
        if (not os.path.exists(path) or
            not os.path.isfile(path) or
            not os.access(path, os.R_OK)):
            print "Tor2web Startup Failure: unexistent file (%s)" % path
            exit(1)
    except:
        print "Tor2web Startup Failure: error while accessing file (%s)" % path
        exit(1)

###############################################################################

sys.excepthook = MailException

t2w = Tor2web(config)

rexp = {
    'body': re.compile(r'(<body.*?\s*>)', re.I),
    'w2t': re.compile(r'(https:)?//([a-z0-9]{16}).' + config.basehost + '(:443)?', re.I),
    't2w': re.compile(r'(http:)?//([a-z0-9]{16}).onion(:80)?', re.I)
}

application = service.Application("Tor2web")
service.IProcess(application).processName = "tor2web"

class T2WLogObserver(log.FileLogObserver):
    """Custom Logging observer"""
    def emit(self, eventDict):
        """Custom emit for FileLogObserver"""
        log.FileLogObserver.emit(self, eventDict)

        if 'failure' in eventDict:
            vf = eventDict['failure']
            e_t, e_v, e_tb = vf.type, vf.value, vf.getTracebackObject()
            sys.excepthook(e_t, e_v, e_tb)

if config.debugmode:
    if config.debugtostdout is not True:
        application.setComponent(log.ILogObserver,
                                 T2WLogObserver(logfile.DailyLogFile.fromFullPath(os.path.join(config.datadir, 'logs', 'debug.log'))).emit)
    else:
        application.setComponent(log.ILogObserver, T2WLogObserver(sys.stdout).emit)
else:
    application.setComponent(log.ILogObserver, T2WLogObserver(log.NullFile).emit)

antanistaticmap = {}
files = FilePath(os.path.join(config.datadir,"static/")).globChildren("*")
for file in files:
    antanistaticmap[file.basename()] = file.getContent()

templates = {}
files = FilePath(os.path.join(config.datadir, 'templates/')).globChildren("*.tpl")
for file in files:
    templates[file.basename()] = PageTemplate(XMLString(file.getContent()))

antanistaticmap['tos.html'] = templates['tos.tpl']

pool = HTTPConnectionPool(reactor, True,
                          config.sockmaxpersistentperhost,
                          config.sockcachedconnectiontimeout,
                          config.sockretryautomatically)

factory = T2WProxyFactory(os.path.join(config.datadir, 'logs', 'access.log'))

if config.listen_ipv6 == "::" or config.listen_ipv4 == config.listen_ipv6:
    # fix for incorrect configurations
    ipv4 = None
else:
    ipv4 = config.listen_ipv4
ipv6 = config.listen_ipv6

for ip in [ipv4, ipv6]:
    if ip == None:
        continue

    service_https = startTor2webHTTPS(t2w, factory, ip)
    service_https.setServiceParent(application)

    service_http = startTor2webHTTP(t2w, factory, ip)
    service_http.setServiceParent(application)
