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

from zope.interface import implements

from twisted.internet import reactor, protocol, defer
from twisted.internet.abstract import isIPAddress, isIPv6Address
from twisted.internet.error import ConnectionRefusedError
from twisted.internet.endpoints import TCP4ClientEndpoint, SSL4ClientEndpoint
from twisted.application import service, internet
from twisted.web import proxy, http, client, resource, http_headers, _newclient
from twisted.web._newclient import Request, RequestNotSent, RequestGenerationFailed, TransportProxyProducer, STATUS
from twisted.web.http import StringTransport
from twisted.web.http_headers import _DictHeaders
from twisted.web.server import NOT_DONE_YET
from twisted.web.template import flattenString, XMLString
from twisted.web.iweb import IBodyProducer
from twisted.python.filepath import FilePath
from twisted.python import log, logfile, failure

from utils.config import VERSION, config
from utils.lists import List, torExitNodeList
from utils.mail import sendmail, MailException
from utils.socks import SOCKS5ClientEndpoint, SOCKSError
from utils.ssl import T2WSSLContextFactory
from utils.storage import Storage
from utils.templating import PageTemplate

rexp = {
    'href': re.compile(r'<[a-z]*\s*.*?\s*href\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*.*?>', re.I),
    'src': re.compile(r'<[a-z]*\s*.*?\s*src\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*.*?>', re.I),
    'action': re.compile(r'<[a-z]*\s*.*?\s*action\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*.*?>', re.I),
    'body': re.compile(r'(<body.*?\s*>)', re.I)
}

SOCKS_errors = {\
    0x00: "error_sock_generic.tpl",
    0x23: "error_sock_hs_not_found.tpl",
    0x24: "error_sock_hs_not_reachable.tpl"
}

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

    # The destination hidden service identifier
    onion = None

    # The path portion of the URI
    path = None

    # The full address (hostname + uri) that must be requested
    address = None

    # The headers to be sent
    headers = None

    # The requested uri
    uri = None

    error = {}

    client_supports_gzip = False

    server_response_is_gzip = False

    contentNeedFix = False

class Tor2web(object):
    def __init__(self, config):
        """
        Process tor2web requests, fix links, inject banner and
        all that happens between a client request and the fetching
        of the content from the Tor Hidden Service.

        :config a config object
        """
        self.config = config

        self.basehost = config.basehost

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

        obj.host_tor = "http://" + obj.onion + ".onion"
        obj.host_tor2web = "https://" + obj.onion + "." + self.config.basehost + ":" + str(self.config.listen_port_https)
        obj.address = "http://" + obj.onion + obj.uri

        obj.headers = req.headers

        log.msg("Headers before fix:")
        log.msg(obj.headers)

        obj.headers.removeHeader('If-Modified-Since')
        obj.headers.removeHeader('If-None-Match')
        obj.headers.setRawHeaders('Host', [obj.onion])
        obj.headers.setRawHeaders('X-tor2web', ['encrypted'])
        obj.headers.setRawHeaders('Connection', ['keep-alive'])
        obj.headers.setRawHeaders('Accept-Encoding', ['gzip, chunked'])

        for key, values in obj.headers.getAllRawHeaders():
            fixed_values = []
            for value in values:
                fixed_values.append(value.replace(obj.host_tor2web, obj.host_tor))

            obj.headers.setRawHeaders(key, fixed_values)

        log.msg("Headers after fix:")
        log.msg(obj.headers)

        return True

    def leaving_link(self, obj, target):
        """
        Returns a link pointing to a resource outside of Tor2web.
        """
        link = target.netloc + target.path
        if target.query:
            link += "?" + target.query

        return "https://leaving." + self.basehost + "/" + link

    def fix_link(self, obj, data):
        """
        Operates some links corrections.
        """
        parsed = urlparse(data)
        exiting = True

        scheme = parsed.scheme

        if scheme == 'http':
            scheme = 'https'

        if scheme == 'data':
            link = data
            return link;

        if scheme == '':
            link = data
        else:
            if parsed.netloc == '':
                netloc = obj.onion
            else:
                netloc = parsed.netloc

            if netloc == obj.onion:
                exiting = False
            elif netloc.endswith(".onion"):
                netloc = netloc.replace(".onion", "")
                exiting = False

            link = scheme + "://"

            if exiting:
                # Actually not implemented: need some study.
                # link = self.leaving_link(obj, parsed)
                link = data
            else:
                link += netloc + "." + self.basehost + parsed.path

            if parsed.query:
                link += "?" + parsed.query

        return link

    def fix_links(self, obj, data):
        """
        Fix links in the result from HS

        example:
            when visiting <onion_url>.tor2web.org
            /something -> /something
            <onion_url>/something -> <onion_url>.tor2web.org/something
        """
        link = self.fix_link(obj, data.group(1))

        return data.group(0).replace(data.group(1), link)

    def add_banner(self, obj, banner, data):
        """
        Inject tor2web banner inside the returned page
        """
        return str(data.group(1)) + str(banner)

    def process_links(self, obj, data):
        """
        Process all the possible HTML tag attributes that may contain links.
        """
        log.msg("processing URL attributes")

        items = ['src', 'href', 'action']
        for item in items:
            data = re.sub(rexp[item], partial(self.fix_links, obj), data)

        log.msg("finished processing links...")

        return data

    def process_html(self, obj, banner, data):
        """
        Process the result from the Hidden Services HTML
        """
        log.msg("processing HTML type content")

        data = self.process_links(obj, data)

        data = re.sub(rexp['body'], partial(self.add_banner, obj, banner), data)

        return data

class BodyReceiver(protocol.Protocol):
    def __init__(self, finished):
        self._finished = finished
        self._data = []

    def dataReceived(self, bytes):
        self._data.append(bytes)

    def connectionLost(self, reason):
        self._finished.callback(''.join(self._data))

class BodyStreamer(protocol.Protocol):
    def __init__(self, streamfunction, finished):
        self._finished = finished
        self._streamfunction = streamfunction

    def dataReceived(self, bytes):
        self._streamfunction(bytes)

    def connectionLost(self, reason):
        self._finished.callback('')

class BodyProducer(object):
    implements(IBodyProducer)

    def __init__(self, content, content_length):
        self.content = content
        self.length = int(content_length)
        self.finished = defer.Deferred()
        self.consumed = 0

    def startProducing(self, consumer):
        while True:
            tmp = self.content.read(4096)
            if len(tmp) == 0:
                break
            consumer.write(tmp)
        self.finished.callback(None)
        return self.finished

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass

class Headers(http_headers.Headers):
    def setRawHeaders(self, name, values):
        if name.lower() not in self._rawHeaders:
            self._rawHeaders[name.lower()] = dict()
        self._rawHeaders[name.lower()]['name'] = name
        self._rawHeaders[name.lower()]['values'] = values

    def getRawHeaders(self, name, default=None):
        if name.lower() in self._rawHeaders:
            return self._rawHeaders[name.lower()]['values']
        return default

    def getAllRawHeaders(self):
        for k, v in self._rawHeaders.iteritems():
            yield v['name'], v['values']

class HTTPClientParser(_newclient.HTTPClientParser):
    def connectionMade(self):
        # We need to override Headers() class with our one.
        self.headers = Headers()
        self.connHeaders = Headers()
        self.state = STATUS
        self._partialHeader = None

    def headerReceived(self, name, value):
        if self.isConnectionControlHeader(name.lower()):
            headers = self.connHeaders
        else:
            headers = self.headers
        headers.addRawHeader(name, value)

class HTTP11ClientProtocol(_newclient.HTTP11ClientProtocol):
    def request(self, request):
        if self._state != 'QUIESCENT':
            return defer.fail(RequestNotSent())

        self._state = 'TRANSMITTING'
        _requestDeferred = defer.maybeDeferred(request.writeTo, self.transport)
        self._finishedRequest = defer.Deferred()

        self._currentRequest = request

        self._transportProxy = TransportProxyProducer(self.transport)
        self._parser = HTTPClientParser(request, self._finishResponse)
        self._parser.makeConnection(self._transportProxy)
        self._responseDeferred = self._parser._responseDeferred

        def cbRequestWrotten(ignored):
            if self._state == 'TRANSMITTING':
                self._state = 'WAITING'
                self._responseDeferred.chainDeferred(self._finishedRequest)

        def ebRequestWriting(err):
            if self._state == 'TRANSMITTING':
                self._state = 'GENERATION_FAILED'
                self.transport.loseConnection()
                self._finishedRequest.errback(
                    failure.Failure(RequestGenerationFailed([err])))
            else:
                log.err(err, 'Error writing request, but not in valid state '
                             'to finalize request: %s' % self._state)

        _requestDeferred.addCallbacks(cbRequestWrotten, ebRequestWriting)

        return self._finishedRequest

class _HTTP11ClientFactory(protocol.ClientFactory):
    def __init__(self, quiescentCallback):
        self._quiescentCallback = quiescentCallback

    def buildProtocol(self, addr):
        return HTTP11ClientProtocol(self._quiescentCallback)

class HTTPConnectionPool(client.HTTPConnectionPool):
    _factory = _HTTP11ClientFactory

    def __init__(self, reactor, persistent=True, maxPersistentPerHost=2, cachedConnectionTimeout=240, retryAutomatically=True):
        client.HTTPConnectionPool.__init__(self, reactor, persistent)

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

    def _requestWithEndpoint(self, key, endpoint, method, parsedURI,
                             headers, bodyProducer, requestPath):
        if headers is None:
            headers = Headers()
        if not headers.hasHeader('host'):
            headers = headers.copy()
            headers.addRawHeader(
                'host', self._computeHostValue(parsedURI.scheme, parsedURI.host,
                                               parsedURI.port))

        d = self._pool.getConnection(key, endpoint)
        def cbConnected(proto):
            return proto.request(
                Request(method, requestPath, headers, bodyProducer,
                        persistent=self._pool.persistent))
        d.addCallback(cbConnected)
        return d

class T2WRequest(proxy.ProxyRequest):
    """
    Used by Tor2webProxy to implement a simple web proxy.
    """
    staticmap = "/antanistaticmap/"

    def __init__(self, channel, queued, reactor=reactor):
        # We need to override together some part of proxy.Request and of the base http.Request
        self.reactor = reactor
        self.notifications = []
        self.channel = channel
        self.queued = queued
        self.requestHeaders = Headers()
        self.received_cookies = {}
        self.responseHeaders = Headers()
        self.cookies = [] # outgoing cookies

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

        self.pool = HTTPConnectionPool(reactor, True,
                                       config.sockmaxpersistentperhost,
                                       config.sockcachedconnectiontimeout,
                                       config.sockretryautomatically)

    def __setattr__(self, name, value):
        """
        Support assignment of C{dict} instances to C{received_headers} for
        backwards-compatibility.
        """
        if name == 'received_headers':
            # A property would be nice, but Request is classic.
            self.requestHeaders = headers = Headers()
            for k, v in value.iteritems():
                headers.setRawHeaders(k, [v])
        elif name == 'requestHeaders':
            self.__dict__[name] = value
            self.__dict__['received_headers'] = _DictHeaders(value)
        elif name == 'headers':
            self.responseHeaders = headers = Headers()
            for k, v in value.iteritems():
                headers.setRawHeaders(k, [v])
        elif name == 'responseHeaders':
            self.__dict__[name] = value
            self.__dict__['headers'] = _DictHeaders(value)
        else:
            self.__dict__[name] = value

    def getRequestHostname(self):
        """
            Function overload to fix ipv6 bug:
                http://twistedmatrix.com/trac/ticket/6014
        """
        host = self.getHeader('host')
        if host:
            if host[0]=='[':
                return host.split(']',1)[0] + "]"
            return host.split(':', 1)[0]
        return self.getHost().host

    def forwardData(self, data, end=False):
        if not self.startedWriting:
            if self.obj.client_supports_gzip:
                self.setHeader('content-encoding', 'gzip')

            if data != '' and end:
                self.setHeader('content-length', len(data))

        if data != '':
            self.write(data)

    def handleGzippedForwardPart(self, data, end=False):
        if not self.obj.client_supports_gzip:
            data = self.unzip(data, end)

        self.forwardData(data, end)

    def handleCleartextForwardPart(self, data, end=False):
        if self.obj.client_supports_gzip:
           data = self.zip(data, end)

        self.forwardData(data, end)

    def handleForwardPart(self, data):
        if self.obj.server_response_is_gzip:
            self.handleGzippedForwardPart(data)
        else:
            self.handleCleartextForwardPart(data)

    def handleForwardEnd(self, data):
        if self.obj.server_response_is_gzip:
            self.handleGzippedForwardPart(data, True)
        else:
            self.handleCleartextForwardPart(data, True)
        self.finish()

    def contentFinish(self, content):
        if self.obj.client_supports_gzip:
            self.setHeader('content-encoding', 'gzip')
            content = self.zip(content, True)

        self.setHeader('content-length', len(content))
        self.write(content)
        self.finish()

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

            return data1 + data2

        except:
            self.finish()

    def zip(self, data, end=False):
        data1 = data2 = ''

        try:
            if self.encoderGzip == None:
                self.encoderGzip = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)

            if data != '':
                data1 = self.encoderGzip.compress(data)

            if end:
                data2 = self.encoderGzip.flush()

            return data1 + data2

        except:
            self.finish()

    def process(self):
        content = ""

        request = Storage()
        request.headers = self.requestHeaders
        request.host = self.getRequestHostname()
        request.uri = self.uri

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
            self.write("User-Agent: *\n")
            self.write("Disallow: /\n")
            self.finish()
            return

        # secondly we try to deny some ua/crawlers regardless the request is (valid or not) / (local or not)
        # we deny EVERY request to known user agents reconized with pattern matching
        if request.headers.getRawHeaders('user-agent') != None:
            for ua in t2w.blocked_ua:
                check = request.headers.getRawHeaders('user-agent')[0].lower()
                if re.match(ua, check):
                    return self.sendError(403, "error_blocked_ua.tpl")

        # we need to verify if the requested resource is local (/antanistaticmap/*) or remote
        # because some checks must be done only for remote requests;
        # in fact local content is always served (css, js, and png in fact are used in errors)

        if not verify_resource_is_local(request.host, request.uri, self.staticpath):
            if not request.host:
                return self.sendError(406, 'error_invalid_hostname.tpl')

            if config.mode == "TRANSLATION":
                self.obj.onion = config.onion
            else:
                self.obj.onion = request.host.split(".")[0] + ".onion"
                log.msg("detected <onion_url>.tor2web Hostname: %s" % self.obj.onion)
                if not verify_onion(self.obj.onion):
                    return self.sendError(406, 'error_invalid_hostname.tpl')

                if config.mode == "ACCESSLIST":
                    if self.obj.onion not in self.accesslist:
                        return self.sendError(403, 'error_hs_completely_blocked.tpl')

                elif config.mode == "BLOCKLIST":
                    if hashlib.md5(self.obj.onion).hexdigest() in self.accesslist:
                        return self.sendError(403, 'error_hs_completely_blocked.tpl')

                    if hashlib.md5(self.obj.onion + self.obj.uri).hexdigest() in accesslist:
                        return self.sendError(403, 'error_hs_specific_page_blocked.tpl')
            
            self.obj.uri = request.uri

            # we need to verify if the user is using tor;
            # on this condition it's better to redirect on the .onion
            if self.getClientIP() in t2w.TorExitNodes:
                self.redirect("http://" + self.obj.onion + request.uri)
                self.finish()
                return

            # pattern matching checks to for early request refusal.
            #
            # future pattern matching checks for denied content and conditions must be put in the stage
            #
            if request.uri.lower().endswith(('gif','jpg','png')):
                # Avoid image hotlinking
                if request.headers.getRawHeaders('referer') == None or not config.basehost in request.headers.getRawHeaders('referer')[0].lower():
                    return self.sendError(403)

        self.setHeader('strict-transport-security', 'max-age=31536000')

        # 1: Client capability assesment stage
        if request.headers.getRawHeaders('accept-encoding') != None:
            if re.search('gzip', request.headers.getRawHeaders('accept-encoding')[0]):
                self.obj.client_supports_gzip = True

        # 2: Content delivery stage
        if verify_resource_is_local(request.host, request.uri, self.staticpath):
            # the requested resource is local, we deliver it directly
            try:
                staticpath = request.uri
                staticpath = re.sub('\/$', '/index.html', staticpath)
                staticpath = re.sub('^('+self.staticmap+')?', '', staticpath)
                staticpath = re.sub('^/', '', staticpath)
                if staticpath in antanistaticmap:
                    if type(antanistaticmap[staticpath]) == str:
                        filename, ext = os.path.splitext(staticpath)
                        self.setHeader('content-type', mimetypes.types_map[ext])
                        content = antanistaticmap[staticpath]
                    elif type(antanistaticmap[staticpath]) == PageTemplate:
                        return flattenString(self, antanistaticmap[staticpath]).addCallback(self.contentFinish)
                elif staticpath == "notification":
                    if 'by' in self.args and 'url' in self.args and 'comment' in self.args:
                        tmp = []
                        tmp.append("From: Tor2web Node %s.%s <%s>\n" % (config.nodename, config.basehost, config.smtpmail))
                        tmp.append("To: %s\n" % (config.smtpmailto_notifications))
                        tmp.append("Subject: Tor2web Node (IPv4 %s, IPv6 %s): notification for %s\n" % (config.listen_ipv4, config.listen_ipv6, self.args['url'][0]))
                        tmp.append("Content-Type: text/plain; charset=ISO-8859-1\n")
                        tmp.append("Content-Transfer-Encoding: 8bit\n\n")
                        tmp.append("BY: %s\n" % (self.args['by'][0]))
                        tmp.append("URL: %s\n" % (self.args['url'][0]))
                        tmp.append("COMMENT: %s\n" % (self.args['comment'][0]))
                        message = StringIO(''.join(tmp))
                        sendmail(config.smtpuser, config.smtppass, config.smtpmail, config.smtpmailto_notifications, message, config.smtpdomain, config.smtpport)
                    else:
                        return self.sendError(404)

            except:
                return self.sendError(404)

            return self.contentFinish(content)

        else:
            # the requested resource is remote, we act as proxy

            t2w.process_request(self.obj, request)

            try:
                parsed = urlparse(self.obj.address)
                protocol = parsed[0]
                host = parsed[1]
                if ':' in host:
                    host, port = host.split(":")
                    port = int(port)
                else:
                    port = self.ports[protocol]

            except:
                return self.sendError(400, "error_invalid_hostname.tpl")

            dest = client._parse(self.obj.address) # scheme, host, port, path

            self.var['onion'] = self.obj.onion
            self.var['path'] = dest[3]

            content_length = self.getHeader('content-length')
            if content_length is not None and content_length >= 0:
                bodyProducer = BodyProducer(self.content,
                                            content_length)

                request.headers.removeHeader('content-length')
            else:
                bodyProducer = None

            agent = Agent(reactor, sockhost=config.sockshost, sockport=config.socksport, pool=self.pool)
            d = agent.request(self.method, 'shttp://'+dest[1]+dest[3],
                    self.obj.headers, bodyProducer=bodyProducer)

            d.addCallback(self.cbResponse)
            d.addErrback(self.handleError)

            return NOT_DONE_YET

    def cbResponse(self, response):
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

        if keyLower == 'location':
            value = t2w.fix_link(self.obj, valueLower)

        elif keyLower == 'connection':
            return

        elif keyLower == 'transfer-encoding' and valueLower == 'chunked':
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
            fixed_values.append(value.replace(self.obj.host_tor, self.obj.host_tor2web))

        self.responseHeaders.setRawHeaders(key, fixed_values)

    def handleEndHeaders(self):
        self.setHeader('cache-control', 'no-cache')

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

class T2WProxy(http.HTTPChannel):
    requestFactory = T2WRequest

class T2WProxyFactory(http.HTTPFactory):
    protocol = T2WProxy

    def _openLogFile(self, path):
        """
        Override in subclasses, e.g. to use twisted.python.logfile.
        """
        return logfile.DailyLogFile.fromFullPath(path)

    def log(self, request):
        """
        Log a request's result to the logfile, by default in combined log format.
        """
        if config.logreqs and hasattr(self, "logFile"):
            line = "127.0.0.1 (%s) - - %s \"%s\" %s %s \"%s\" \"%s\"\n" % (
                self._escape(request.getHeader('host')),
                self._logDateTime,
                '%s %s %s' % (self._escape(request.method),
                              self._escape(request.uri),
                              self._escape(request.clientproto)),
                request.code,
                request.sentLength or "-",
                self._escape(request.getHeader('referer') or "-"),
                self._escape(request.getHeader('user-agent') or "-"))
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

application = service.Application("Tor2web")
service.IProcess(application).processName = "tor2web"
if config.debugmode:
    if config.debugtostdout is not True:
        application.setComponent(log.ILogObserver,
                                 log.FileLogObserver(logfile.DailyLogFile.fromFullPath(os.path.join(config.datadir, 'logs', 'debug.log'))).emit)
else:
    application.setComponent(log.ILogObserver, log.FileLogObserver(log.NullFile).emit)

antanistaticmap = {}
files = FilePath(os.path.join(config.datadir,"static/")).globChildren("*")
for file in files:
    antanistaticmap[file.basename()] = file.getContent()

templates = {}
files = FilePath(os.path.join(config.datadir, 'templates/')).globChildren("*.tpl")
for file in files:
    templates[file.basename()] = PageTemplate(XMLString(file.getContent()))

antanistaticmap['tos.html'] = templates['tos.tpl']

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
