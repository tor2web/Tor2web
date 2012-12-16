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
import sys
import traceback
import copy
import re
import urlparse
import mimetypes
import gzip
import json
import zlib
from StringIO import StringIO
from OpenSSL import SSL

from twisted.mail.smtp import ESMTPSenderFactory
from twisted.internet import ssl, reactor
from twisted.internet.error import ConnectionRefusedError
from twisted.internet.ssl import ClientContextFactory, DefaultOpenSSLContextFactory
from twisted.internet.defer import Deferred, succeed, fail, maybeDeferred
from twisted.application import service, internet
from twisted.web import proxy, http, client, resource, http_headers, _newclient
from twisted.web._newclient import Request, RequestNotSent, RequestGenerationFailed, TransportProxyProducer, STATUS
from twisted.web.template import flattenString, XMLString
from twisted.web.server import NOT_DONE_YET
from twisted.python.filepath import FilePath
from twisted.python import log
from twisted.python.logfile import DailyLogFile
from twisted.python.failure import Failure
from twisted.internet import protocol, defer
from twisted.internet.endpoints import TCP4ClientEndpoint, SSL4ClientEndpoint, _WrappingProtocol, _WrappingFactory

from config import config
from tor2web import Tor2web, Tor2webObj
from storage import Storage
from templating import PageTemplate
from socksclient import SOCKS5ClientEndpoint, SOCKSError
from twisted.web.http_headers import _DictHeaders

SOCKS_errors = {\
    0x00: "error_sock_generic.tpl",
    0x23: "error_sock_hs_not_found.tpl",
    0x24: "error_sock_hs_not_reachable.tpl"
}

def MailException(etype, value, tb):
    """
    Formats traceback and exception data and emails the error

    @param etype: Exception class type
    @param value: Exception string value
    @param tb: Traceback string data
    """
    excType = re.sub("(<(type|class ')|'exceptions.|'>|__main__.)", "", str(etype)).strip()
    message = ""
    message += "From: Tor2web Node %s.%s <%s>\n" % (config.nodename, config.basehost, config.smtpmail)
    message += "To: %s\n" % (config.smtpmailto_exceptions)
    message += "Subject: Tor2web Node Exception (IPV4: %s, IPv6: %s)\n" % (config.listen_ipv4, config.listen_ipv6)
    message += "Content-Type: text/plain; charset=ISO-8859-1\n"
    message += "Content-Transfer-Encoding: 8bit\n\n"
    message += "%s %s" % (excType, etype.__doc__)
    for line in traceback.extract_tb(tb):
        message += "\tFile: \"%s\"\n\t\t%s %s: %s\n" %(line[0], line[2], line[1], line[3])
    while 1:
        if not tb.tb_next: break
        tb = tb.tb_next
    stack = []
    f = tb.tb_frame
    while f:
        stack.append(f)
        f = f.f_back
    stack.reverse()
    message += "\nLocals by frame, innermost last:"
    for frame in stack:
        message += "\nFrame %s in %s at line %s" % (frame.f_code.co_name, frame.f_code.co_filename, frame.f_lineno)
        for key, val in frame.f_locals.items():
            message += "\n\t%20s = " % key
            try:
                message += str(val)
            except:
                message += "<ERROR WHILE PRINTING VALUE>"

    message = StringIO(message)
    sendmail(config.smtpuser, config.smtppass, config.smtpmail, config.smtpmailto_exceptions, message, config.smtpdomain, config.smtpport)


def sendmail(authenticationUsername, authenticationSecret, fromAddress, toAddress, messageFile, smtpHost, smtpPort=25):
    """
    Sends an email using SSLv3 over SMTP

    @param authenticationUsername: account username
    @param authenticationSecret: account password
    @param fromAddress: the from address field of the email
    @param toAddress: the to address field of the email
    @param messageFile: the message content
    @param smtpHost: the smtp host
    @param smtpPort: the smtp port
    """
    contextFactory = ClientContextFactory()
    contextFactory.method = SSL.SSLv3_METHOD

    resultDeferred = Deferred()

    senderFactory = ESMTPSenderFactory(
        authenticationUsername,
        authenticationSecret,
        fromAddress,
        toAddress,
        messageFile,
        resultDeferred,
        contextFactory=contextFactory)

    reactor.connectTCP(smtpHost, smtpPort, senderFactory)

    return resultDeferred


class T2WSSLContextFactory(DefaultOpenSSLContextFactory):
    """
    """
    _context = None

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
        self.cacheContext()

    def cacheContext(self):
        if self._context is None:
            ctx = SSL.Context(self.sslmethod)
            # Disallow SSLv2! It's insecure!
            ctx.set_options(SSL.OP_NO_SSLv2)
            ctx.use_certificate_chain_file(self.certificateChainFileName)
            ctx.use_privatekey_file(self.privateKeyFileName)
            ctx.set_cipher_list(self.cipherList)
            ctx.load_tmp_dh(self.dhFileName)
            self._context = ctx

class BodyReceiver(protocol.Protocol):
    def __init__(self, finished):
        self._finished = finished
        self._data = ""

    def dataReceived(self, bytes):
        self._data += bytes

    def connectionLost(self, reason):
        self._finished.callback(self._data)

class BodyStreamer(protocol.Protocol):
    def __init__(self, streamfunction, finished):
        self._finished = finished
        self._streamfunction = streamfunction

    def dataReceived(self, bytes):
        self._streamfunction(bytes)

    def connectionLost(self, reason):
        self._finished.callback('')

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
            return fail(RequestNotSent())

        self._state = 'TRANSMITTING'
        _requestDeferred = maybeDeferred(request.writeTo, self.transport)
        self._finishedRequest = Deferred()

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
                    Failure(RequestGenerationFailed([err])))
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
    staticmap = "/" + config.staticmap + "/"

    def __init__(self, channel, queued, reactor=reactor):
        self.reactor = reactor
        self.obj = Tor2webObj()
        self.var = Storage()
        self.var['basehost'] = config.basehost
        self.var['errorcode'] = None

        self.notifications = []
        self.channel = channel
        self.queued = queued
        self.requestHeaders = Headers()
        self.received_cookies = {}
        self.responseHeaders = Headers()
        self.cookies = [] # outgoing cookies

        self.html = False
        self.decoderChunked = None        
        self.decoderGzip = None
        self.encoderGzip = None        

        if queued:
            self.transport = StringTransport()
        else:
            self.transport = self.channel.transport

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
                self.stringio = StringIO()
                self.encoderGzip = gzip.GzipFile(fileobj=self.stringio, mode='w')
                self.nextseek = 0

            if data != '':
                self.encoderGzip.write(data)
                self.stringio.seek(self.nextseek)
                data1 = self.stringio.read()
                self.nextseek = self.nextseek + len(data1)

            if end:
                self.encoderGzip.close()
                self.stringio.seek(self.nextseek)
                data2 = self.stringio.read()
                self.stringio.close()
                
            return data1 + data2

        except:
            self.finish()

    def process(self):
        try:
            content = ""

            request = Storage()
            request.headers = self.requestHeaders
            request.host = self.getRequestHostname()
            request.uri = self.uri

            if config.mirror is not None:
                from random import choice
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
                if request.headers.getRawHeaders('user-agent')[0] in t2w.blocked_ua:
                    return self.sendError(403, "error_blocked_ua.tpl")

            # we need to verify if the requested resource is local (/antanistaticmap/*) or remote
            # because some checks must be done only for remote requests;
            # in fact local content is always served (css, js, and png in fact are used in errors)
            
            t2w.verify_resource_is_local(self.obj, request.host, request.uri, self.staticmap)
            
            if not self.obj.resourceislocal:
                # we need to validate the request to avoid useless processing
                
                if not t2w.verify_hostname(self.obj, request.host, request.uri):
                    return self.sendError(self.obj.error['code'], self.obj.error['template'])

                # we need to verify if the user is using tor;
                # on this condition it's better to redirect on the .onion             
                if self.getClientIP() in t2w.TorExitNodes:
                    self.redirect("http://" + self.obj.hostname + request.uri)
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
            if self.obj.resourceislocal:
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
                            message = ""
                            message += "From: Tor2web Node %s.%s <%s>\n" % (config.nodename, config.basehost, config.smtpmail)
                            message += "To: %s\n" % (config.smtpmailto_notifications)
                            message += "Subject: Tor2web Node (IPv4 %s, IPv6 %s): notification for %s\n" % (config.listen_ipv4, config.listen_ipv6, self.args['url'][0])
                            message += "Content-Type: text/plain; charset=ISO-8859-1\n"
                            message += "Content-Transfer-Encoding: 8bit\n\n"
                            message += "BY: %s\n" % (self.args['by'][0])
                            message += "URL: %s\n" % (self.args['url'][0])
                            message += "COMMENT: %s\n" % (self.args['comment'][0])
                            message = StringIO(message)
                            sendmail(config.smtpuser, config.smtppass, config.smtpmail, config.smtpmailto_notifications, message, config.smtpdomain, config.smtpport)
                    else:
                        return self.sendError(404)

                except:
                    return self.sendError(404)

                return self.contentFinish(content)

            else:
                # the requested resource is remote, we act as proxy

                if not t2w.process_request(self.obj, request):
                    return self.sendError(self.obj.error['code'], self.obj.error['template'])

                try:
                    parsed = urlparse.urlparse(self.obj.address)
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

                agent = Agent(reactor, sockhost="127.0.0.1", sockport=9050, pool=pool)
                d = agent.request(self.method, 'shttp://'+dest[1]+dest[3], self.obj.headers, None)
                d.addCallback(self.cbResponse)
                d.addErrback(self.handleError)

                return NOT_DONE_YET

        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            MailException(exc_type, exc_value, exc_traceback)

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
            if self.obj.contentNeedFix:
                finished = defer.Deferred()
                response.deliverBody(BodyReceiver(finished))
                finished.addCallback(self.processResponseBody)
                return finished

            else:
                finished = defer.Deferred()
                response.deliverBody(BodyStreamer(self.handleForwardPart, finished))
                finished.addCallback(self.handleForwardEnd)
                return finished
        else:
            self.contentFinish('')
            return defer.succeed

    def handleHeader(self, key, value):
        keyLower = key.lower()
        valueLower = value.lower()
        
        if keyLower == 'location':
            value = t2w.fix_link(self.obj, value)

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
            self.receivedContentLen = value
            return

        elif keyLower == 'cache-control':
            return

        self.setHeader(key, value)

    def handleEndHeaders(self):
        self.setHeader('cache-control', 'no-cache')

    def processResponseHeaders(self, headers):
        for name, values in headers.getAllRawHeaders():
            self.handleHeader(name, values[0])
        
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
        return DailyLogFile.fromFullPath(path)

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
    return internet.SSLServer(int(t2w.config.listen_port_https), f, T2WSSLContextFactory(t2w.config.sslkeyfile, t2w.config.sslcertfile, t2w.config.ssldhfile, t2w.config.cipher_list), interface=ip)

sys.excepthook = MailException

t2w = Tor2web(config)

pool = HTTPConnectionPool(reactor, True,
                          config.sockmaxpersistentperhost,
                          config.sockcachedconnectiontimeout,
                          config.sockretryautomatically)

application = service.Application("Tor2web")
if config.debugmode:
    if config.debugtostdout is not True:
        application.setComponent(log.ILogObserver, log.FileLogObserver(DailyLogFile.fromFullPath(config.debuglogpath)).emit)
else:
    application.setComponent(log.ILogObserver, log.FileLogObserver(log.NullFile).emit)


antanistaticmap = {}
files = FilePath("static/").globChildren("*")
for file in files:
    antanistaticmap[file.basename()] = file.getContent()

templates = {}
files = FilePath("templates/").globChildren("*.tpl")
for file in files:
    templates[file.basename()] = PageTemplate(XMLString(file.getContent()))

antanistaticmap['tos.html'] = templates['tos.tpl']

factory = T2WProxyFactory(config.accesslogpath)

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
