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

from config import config
from tor2web import Tor2web, Tor2webObj
from storage import Storage
from templating import ErrorTemplate, PageTemplate

from twisted.mail.smtp import ESMTPSenderFactory
from twisted.internet import ssl, reactor, endpoints
from twisted.internet.ssl import ClientContextFactory, DefaultOpenSSLContextFactory
from twisted.internet.defer import Deferred
from twisted.application import service, internet
from twisted.web import proxy, http, client, resource
from twisted.web.template import flattenString
from twisted.web.server import NOT_DONE_YET
from twisted.python.filepath import FilePath
from twisted.python import log
from twisted.python.logfile import DailyLogFile

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

from socksclient import SOCKSv5ClientFactory, SOCKSWrapper
from OpenSSL import SSL

t2w = Tor2web(config)

application = service.Application("Tor2web")
if config.debugmode:
    application.setComponent(log.ILogObserver, log.FileLogObserver(DailyLogFile.fromFullPath(config.debuglogpath)).emit)
else:
    application.setComponent(log.ILogObserver, log.FileLogObserver(log.NullFile).emit)

def MailException(etype, value, tb):
    """Formats traceback and exception data and emails the error

    Arguments:
    etype -- Exception class type
    value -- Exception string value
    tb -- Traceback string data
    """

    excType = re.sub("(<(type|class ')|'exceptions.|'>|__main__.)", "", str(etype)).strip()
    message = ""
    message += "From: Tor2web Node %s <%s>\n" % (config.listen_ip, config.smtpmail)
    message += "To: %s\n" % (config.smtpmailto_exceptions)
    message += "Subject: Tor2web Node %s exception\n" % (config.listen_ip)
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

class T2WProxyClient(proxy.ProxyClient):
    """
    """
    def __init__(self, command, rest, version, headers, data, father, obj):
        self.father = father
        self.command = command
        self.rest = rest
        self.headers = headers
        self.data = data

        self.obj = obj
        self.bf = []
        contenttype = 'unknown'
        self.html = False
        self.location = False
        self.decoderChunked = None        
        self.decoderGzip = None
        self.encoderGzip = None
        
        self.startedWriting = False

    def handleHeader(self, key, value):

        keyLower = key.lower()
        valueLower = value.lower()

        if keyLower == 'location':
            self.location = t2w.fix_link(self.obj, valueLower)
            return

        elif keyLower == 'transfer-encoding' and valueLower == 'chunked':
            self.decoderChunked = http._ChunkedTransferDecoder(self.handleResponsePart, self.handleResponseEnd)
            return

        elif keyLower == 'content-encoding' and valueLower == 'gzip':
            self.obj.server_response_is_gzip = True
            return

        elif keyLower == 'content-type' and re.search('text/html', valueLower):
            self.obj.contentNeedFix = True
            self.html = True
            
        elif keyLower == 'content-length':
            return

        elif keyLower == 'cache-control':
            return

        elif keyLower == 'connection' and valueLower == 'keep-alive':
            self.obj.server_supports_keepalive = True
            return
        
        proxy.ProxyClient.handleHeader(self, key, value)

    def handleEndHeaders(self):
        proxy.ProxyClient.handleHeader(self, 'cache-control', 'no-cache')
        if self.location:
            proxy.ProxyClient.handleHeader(self, 'location', self.location)

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

    def handleResponsePart(self, data):
        if self.obj.server_response_is_gzip:
            if self.obj.contentNeedFix:
                data = self.unzip(data)
                self.bf.append(data)
            else:
                self.handleGzippedForwardPart(data)
        else:
            if self.obj.contentNeedFix:
                self.bf.append(data)
            else:
                self.handleCleartextForwardPart(data)
               
    def handleGzippedForwardPart(self, data, end=False):
        if not self.obj.client_supports_gzip:
            data = self.unzip(data, end)

        self.forwardData(data, end)

    def handleCleartextForwardPart(self, data, end=False):
        if self.obj.client_supports_gzip:
           data = self.zip(data, end)

        self.forwardData(data, end)
    
    def handleResponseEnd(self):

        # if self.decoderGzip != None:
        #   the response part is gzipped and two conditions may have set this:
        #   - the content response has to be modified
        #   - the client does not support gzip
        #   => we have to terminate the unzip process
        #      we have to check if the content has to be modified

        if self.decoderGzip is not None:
            data = self.unzip('', True)
                
            if data:
                self.bf.append(data)

        data = ''.join(self.bf)

        if data and self.obj.contentNeedFix:
            if self.html:
                data = t2w.process_html(self.obj, data)
        
        self.handleCleartextForwardPart(data, True)

    def rawDataReceived(self, data):
        if self.decoderChunked is not None:
            self.decoder.dataReceived(data)
        else:
            self.handleResponsePart(data)

    def forwardData(self, data, end=False):
        if not self.startedWriting:
            self.startedWriting = True

            if self.obj.client_supports_gzip:
                proxy.ProxyClient.handleHeader(self, 'content-encoding', 'gzip')

            if data != '' and end:
                proxy.ProxyClient.handleHeader(self, 'content-length', len(data))

        if data != '':
            self.father.write(data)
        
        if end:
            self.finish()

    def finish(self):
        if not self._finished:
            self._finished = True
            self.father.finish()
            self.transport.loseConnection()

    def connectionLost(self, reason):
        self.handleResponseEnd()
 
class T2WProxyClientFactory(proxy.ProxyClientFactory):
    protocol = T2WProxyClient
    
    def __init__(self, command, rest, version, headers, data, father, obj):
        self.obj = obj
        proxy.ProxyClientFactory.__init__(self, command, rest, version, headers, data, father)

    def buildProtocol(self, addr):
        return self.protocol(self.command, self.rest, self.version, self.headers, self.data, self.father, self.obj)

class T2WRequest(proxy.ProxyRequest):
    """
    Used by Tor2webProxy to implement a simple web proxy.
    """
    protocols = {'http': T2WProxyClientFactory}
    ports = {'http': 80}
    staticmap = "/" + config.staticmap + "/"

    def __init__(self, *args, **kw):
        proxy.ProxyRequest.__init__(self, *args, **kw)
        self.obj = Tor2webObj()

    def contentGzip(self, content):
        stringio = StringIO()
        ram_gzip_file = gzip.GzipFile(fileobj=stringio, mode='w')
        ram_gzip_file.write(content)
        ram_gzip_file.close()
        content = stringio.getvalue()
        stringio.close()
        return content
    
    def contentFinish(self, content):
        if self.obj.client_supports_gzip:
            self.setHeader('content-encoding', 'gzip')
            content = self.contentGzip(content)

        self.setHeader('content-length', len(content))
        self.write(content)
        self.finish()

    def error(self, error, errortemplate='error_generic.xml'):
        self.setResponseCode(error)
        return flattenString(None, ErrorTemplate(error, errortemplate)).addCallback(self.contentFinish)
        
    def sockserror(self, err):
        self.setResponseCode(501)
        return flattenString(None, ErrorTemplate(error, errortemplate)).addCallback(self.contentFinish)

    def process(self):
        try:
            content = ""
          
            request = Storage()
            request.headers = self.getAllHeaders().copy()
            request.host = request.headers.get('host')
            request.uri = self.uri
            request.resourceislocal = False
            
            # we serve contents only over https
            if not self.isSecure():
                self.redirect("https://" + self.getRequestHostname() + request.uri)
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
            if request.headers.get('user-agent') in t2w.blocked_ua:
                return self.error(403, "error_blocked_ua.xml")

            # we need to verify if the requested resource is local (/antanistaticmap/*) or remote
            # becouse some checks must be done only for remote requests;
            # in fact local content is always served (css, js, and png in fact are used in errors)
            
            if request.host == config.listen_ip:
                request.resourceislocal = True
            else:
                request.resourceislocal = request.uri.startswith(self.staticmap)

            if not request.resourceislocal:
                # we need to validate the request to avoid useless processing
                
                if not t2w.verify_hostname(self.obj, request.host, request.uri):
                    return self.error(self.obj.error['code'], self.obj.error['template'])

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
                    if request.headers.get('referer') == None or not config.basehost in request.headers.get('referer').lower():
                        return self.error(403)

            self.setHeader('strict-transport-security', 'max-age=31536000') 

            # 1: Client capability assesment stage
            if request.headers.get('accept-encoding') != None:
                if re.search('gzip', request.headers.get('accept-encoding')):
                    self.obj.client_supports_gzip = True

            if request.headers.get('connection') != None:
                if re.search('keep-alive', request.headers.get('connection')):
                    self.obj.client_supports_keepalive = True

            # 2: Content delivery stage
            if request.resourceislocal:
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
                            return flattenString(None, antanistaticmap[staticpath]).addCallback(self.contentFinish)
                    elif staticpath.startswith("notification"):
                        if 'by' in self.args and 'url' in self.args and 'comment' in self.args:
                            message = ""
                            message += "From: Tor2web Node %s <%s>\n" % (config.listen_ip, config.smtpmail)
                            message += "To: %s\n" % (config.smtpmailto_notifications)
                            message += "Subject: Tor2web Node %s: notification for %s\n" % (config.listen_ip, self.args['url'][0])
                            message += "Content-Type: text/plain; charset=ISO-8859-1\n"
                            message += "Content-Transfer-Encoding: 8bit\n\n"
                            message += "BY: %s\n" % (self.args['by'][0])
                            message += "URL: %s\n" % (self.args['url'][0])
                            message += "COMMENT: %s\n" % (self.args['comment'][0])
                            message = StringIO(message)
                            sendmail(config.smtpuser, config.smtppass, config.smtpmail, config.smtpmailto_notifications, message, config.smtpdomain, config.smtpport)
                    else:
                        return self.error(404)

                except:
                    return self.error(404)

                return self.contentFinish(content)

            else:
                # the requested resource is remote, we act as proxy

                if not t2w.process_request(self.obj, request):
                    return self.error(self.obj.error['code'], self.obj.error['template'])

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
                    return self.error(400, "error_invalid_hostname.xml")

                self.rest = urlparse.urlunparse(('', '') + parsed[2:])
                if not self.rest:
                    self.rest = "/"

                socksendpoint = endpoints.TCP4ClientEndpoint(reactor, config.sockshost, config.socksport)
                
                dest = client._parse(self.obj.address) # scheme, host, port, path
                finalendpoint = endpoints.TCP4ClientEndpoint(reactor, dest[1], dest[2])

                wrapper = SOCKSWrapper(reactor, socksendpoint, finalendpoint)
                f = self.protocols[protocol](self.method, self.rest, self.clientproto, self.obj.headers, content, self, self.obj)

                d = wrapper.connect(f)
                d.addErrback(self.sockserror)

                return NOT_DONE_YET

        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            MailException(exc_type, exc_value, exc_traceback)

class T2WProxy(http.HTTPChannel):
    requestFactory = T2WRequest

class T2WProxyFactory(http.HTTPFactory):
    protocol = T2WProxy

    def __init__(self):
        """Initialize.
        """
        http.HTTPFactory.__init__(self, logPath=config.accesslogpath)
        self.sessions = {}
        self.resource = resource

    def _openLogFile(self, path):
        """
        Override in subclasses, e.g. to use twisted.python.logfile.
        """
        f = DailyLogFile.fromFullPath(path)
        return f

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

def startTor2webHTTP(t2w, f):
    return internet.TCPServer(int(t2w.config.listen_port_http), f, interface=config.listen_ip)

def startTor2webHTTPS(t2w, f):
    return internet.SSLServer(int(t2w.config.listen_port_https), f, T2WSSLContextFactory(t2w.config.sslkeyfile, t2w.config.sslcertfile, t2w.config.ssldhfile, t2w.config.cipher_list), interface=config.listen_ip)

sys.excepthook = MailException

antanistaticmap = {}
localpath = FilePath("static/")
files = localpath.globChildren("*")
for file in files:
    antanistaticmap[file.basename()] = file.open().read()

antanistaticmap['tos.html'] = PageTemplate('tos.xml')

factory = T2WProxyFactory()

service_https = startTor2webHTTPS(t2w, factory)
service_https.setServiceParent(application)

service_http = startTor2webHTTP(t2w, factory)
service_http.setServiceParent(application)
