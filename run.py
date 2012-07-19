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

from config import Config
from tor2web import Tor2web, Tor2webObj
from storage import Storage
from templating import ErrorTemplate

import mimetypes
import gzip
import sys
import urlparse
import re
import cgi
import traceback
import threading
import zlib

from StringIO import StringIO

from twisted.mail.smtp import ESMTPSenderFactory
from twisted.internet import ssl, reactor, endpoints
from twisted.internet.ssl import ClientContextFactory
from twisted.internet.defer import Deferred, DeferredQueue
from twisted.application import service, internet
from twisted.web import proxy, http, client, resource
from twisted.web.template import flattenString
from twisted.python.filepath import FilePath
from twisted.web.server import NOT_DONE_YET

from socksclient import SOCKSv5ClientFactory, SOCKSWrapper
from OpenSSL import SSL

config = Config("main")

t2w = Tor2web(config)

application = service.Application("Tor2web")

def MailException(etype, value, tb):
    """Formats traceback and exception data and emails the error

    Arguments:
    etype -- Exception class type
    value -- Exception string value
    tb -- Traceback string data
    """

    excType = re.sub('(<(type|class \')|\'exceptions.|\'>|__main__.)', '', str(etype)).strip()
    message = ""
    message += "TO: %s\n" % (config.smtpmailto)
    message += "SUBJECT: Tor2web exception\n\n"
    message += "%s %s" % (excType, etype.__doc__)

    for line in traceback.extract_tb(tb):
        message += '\tFile: "%s"\n\t\t%s %s: %s\n' % (line[0], line[2], line[1], line[3])
    while 1:
        if not tb.tb_next: break
        tb = tb.tb_next
    stack = []
    f = tb.tb_frame
    while f:
        stack.append(f)
        f = f.f_back
    stack.reverse()
    message += '\nLocals by frame, innermost last:'
    for frame in stack:
        message += '\nFrame %s in %s at line %s' % (frame.f_code.co_name, frame.f_code.co_filename, frame.f_lineno)
        for key, val in frame.f_locals.items():
            message += '\n\t%20s = ' % key
            try:
                message += str(val)
            except:
                message += '<ERROR WHILE PRINTING VALUE>'

    message = StringIO(message)
    sendmail(config.smtpuser, config.smtppass, config.smtpmailto, config.smtpmailto, message, config.smtpdomain, config.smtpport);

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

class T2WSSLContextFactory():
    """
    """
    _context = None

    def __init__(self, privateKeyFileName, certificateFileName, dhFileName, cipherList):
        """
        @param privateKeyFileName: Name of a file containing a private key
        @param certificateFileName: Name of a file containing a certificate
        @param cipherList: The SSL cipher list selection to use
        """
        if self._context is None:
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            # Disallow SSLv2!    It's insecure!
            ctx.set_options(SSL.OP_NO_SSLv2)
            ctx.use_certificate_file(certificateFileName)
            ctx.use_privatekey_file(privateKeyFileName)
            ctx.set_cipher_list(cipherList)
            ctx.load_tmp_dh(dhFileName)
            self._context = ctx

    def __getstate__(self):
        d = self.__dict__.copy()
        del d['_context']
        return d

    def __setstate__(self, state):
        self.__dict__ = state

    def getContext(self):
        """
        Return an SSL context.
        """
        return self._context

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

        if keyLower == "location":
            self.location = t2w.fix_link(self.obj, valueLower)
            return

        elif keyLower == 'transfer-encoding' and valueLower == 'chunked':
            self.decoderChunked = http._ChunkedTransferDecoder(self.handleResponsePart, self.handleResponseEnd)
            return

        elif keyLower == "content-encoding" and valueLower == "gzip":
            self.obj.server_response_is_gzip = True
            return

        elif keyLower == 'content-type' and re.search('text/html', valueLower):
            self.obj.contentNeedFix = True
            self.html = True
            
        elif keyLower == 'content-length':
            return

        elif keyLower == 'cache-control':
            return

        elif keyLower == 'connection' and valueLower == "keep-alive":
            self.obj.server_supports_keepalive = True
            return
        
        proxy.ProxyClient.handleHeader(self, key, value)

    def handleEndHeaders(self):
        proxy.ProxyClient.handleHeader(self, 'cache-control', 'no-cache')
        if self.location:
            proxy.ProxyClient.handleHeader(self, "location", self.location)

    def unzip(self, data, end=False):
        try:
            if self.decoderGzip == None:
                self.decoderGzip = zlib.decompressobj(16 + zlib.MAX_WBITS)

            if data != '':
                data = ''.join(self.decoderGzip.decompress(data))
            
            if end:
                data = data.join(self.decoderGzip.flush())

            return data
            
        except zlib.error:
            self.finish()

    def zip(self, data, end=False):
        if self.encoderGzip == None:
            self.stringio = StringIO()
            self.encoderGzip = gzip.GzipFile(fileobj=self.stringio, mode='w')
            self.nextseek = 0

        self.stringio.seek(self.nextseek)

        if data != '':
            self.encoderGzip.write(data)
            self.stringio.seek(self.nextseek)
            data = self.stringio.read()
            self.nextseek = self.nextseek + len(data)

        if end:
            self.encoderGzip.close()
            self.stringio.seek(self.nextseek)
            data = ''.join([data, self.stringio.read()])
            self.stringio.close()
            
        return data

    def handleResponsePart(self, data):
        if self.obj.server_response_is_gzip == True:
            if self.obj.contentNeedFix == True:
                data = self.unzip(data)
                self.bf.append(data)
            else:
                self.handleGzippedForwardPart(data)
        else:
            if self.obj.contentNeedFix == True:
                self.bf.append(data)
            else:
                self.handleCleartextForwardPart(data)
               
    def handleGzippedForwardPart(self, data, end=False):
        if self.obj.client_supports_gzip == False:
            data = self.unzip(data, end)

        self.forwardData(data, end)

    def handleCleartextForwardPart(self, data, end=False):
        if self.obj.client_supports_gzip == True:
           data = self.zip(data, end)

        self.forwardData(data, end)
    
    def handleResponseEnd(self):

        # if self.decoderGzip != None:
        #   the response part is gzipped and two conditions may have set this:
        #   - the content response has to be modified
        #   - the client does not support gzip
        #   => we have to terminate the unzip process
        #      we have to check if the content has to be modified

        if self.decoderGzip != None:
            data = self.unzip('', True)
                
            if data:
              self.bf.append(data)

        data = ''.join(self.bf)

        if data and self.obj.contentNeedFix:
            if self.html:
                data = t2w.process_html(self.obj, data)
        
        self.handleCleartextForwardPart(data, True)

    def rawDataReceived(self, data):
        if self.decoderChunked != None:
            self.decoder.dataReceived(data)
        else:
            self.handleResponsePart(data)

    def forwardData(self, data, end=False):
        if self.startedWriting == False:
            self.startedWriting = True
            if data != '':
              if self.obj.client_supports_gzip == True:
                  proxy.ProxyClient.handleHeader(self, 'content-encoding', 'gzip')
              if end:
                  proxy.ProxyClient.handleHeader(self, 'content-length', len(data))

        if data != '':
            self.father.write(data)
        
        if end:
            self.finish()

    def finish(self):
        if not self._finished:
            self._finished = True
            self.father.finish()

    def connectionLost(self, reason):
        self.handleResponseEnd()
 
class T2WProxyClientFactory(proxy.ProxyClientFactory):
    protocol = T2WProxyClient
    
    def __init__(self, command, rest, version, headers, data, father, obj):
        self.obj = obj;
        proxy.ProxyClientFactory.__init__(self, command, rest, version, headers, data, father)

    def buildProtocol(self, addr):
        return self.protocol(self.command, self.rest, self.version, self.headers, self.data, self.father, self.obj)

class T2WRequest(proxy.ProxyRequest):
    """
    Used by Tor2webProxy to implement a simple web proxy.
    """
    protocols = {'http': T2WProxyClientFactory}
    ports = {'http': 80}

    def __init__(self, *args, **kw ):
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

    def error(self, error, errormsg=None):
        self.setResponseCode(error)
        return flattenString(None, ErrorTemplate(error, errormsg)).addCallback(self.contentFinish)

    def sockserror(self, err=None):
        self.error(502, "Socks Error: " + str(err.value))
        
    def process(self):
        try:
            request = Storage()
            request.headers = self.getAllHeaders().copy()
            request.uri = self.uri
            request.host = request.headers.get('host')
            if request.host == None:
                return self.error(400)
          
            content = ""

            if self.isSecure():
                self.setHeader('strict-transport-security', 'max-age=31536000')
            else:
                self.redirect("https://" + self.getRequestHostname() + self.uri);
                self.finish()
                return
                    
            if request.uri == "/robots.txt" and config.blockcrawl:
                self.write("User-Agent: *\nDisallow: /\n")
                self.finish()
                return
                
            if request.headers.get('accept-encoding') != None:
                if re.search('gzip', request.headers.get('accept-encoding')):
                    self.obj.client_supports_gzip = True;

            if request.headers.get('connection') != None:
                if re.search('keep-alive', request.headers.get('connection')):
                    self.obj.client_supports_keepalive = True;                  

            if request.headers.get('user-agent') in t2w.blocked_ua:
                # Detected a blocked user-agent
                return self.error(410)

            if request.uri.lower().endswith(('gif','jpg','png')):
                # Avoid image hotlinking
                if request.headers.get('referer') == None or not config.basehost in request.headers.get('referer').lower():
                    self.setHeader('content-type', 'image/png')
                    return self.contentFinish(open('static/tor2web.png', 'r').read())
            
            # 1st the content requested is local? serve it directly!
            
            staticmap = '/'+config.staticmap+'/'
            if self.uri.startswith(staticmap):
                staticpath = re.sub('^'+staticmap, '', self.uri)
                try:
                    localpath = FilePath("static/")
                    localpath = localpath.child(staticpath)
                    if localpath.exists() == True:
                        filename, ext = localpath.splitext()
                        self.setHeader('content-type', mimetypes.types_map[ext])
                        content = localpath.open().read()
                    elif staticpath.startswith('notification'):
                        if 'by' in self.args and 'url' in self.args and 'comment' in self.args:
                            message = ""
                            message += "TO: %s\n" % (config.smtpmailto)
                            message += "SUBJECT: Tor2web notification for %s\n\n" % (self.args['url'][0])
                            message += "BY: %s\n" % (self.args['by'][0])
                            message += "URL: %s\n" % (self.args['url'][0])
                            message += "COMMENT: %s\n" % (self.args['comment'][0])
                            message = StringIO(message)
                            sendmail(config.smtpuser, config.smtppass, config.smtpmailto, config.smtpmailto, message, config.smtpdomain, config.smtpport);
                    else:
                        raise FileNotFoundException
                except:
                    return self.error(404)

                return self.contentFinish(content)

            # 2nd the content requested is remote: proxify the request!

            if not t2w.process_request(self.obj, request):
                return self.error(self.obj.error['code'], self.obj.error['message'])

            parsed = urlparse.urlparse(self.obj.address)
            protocol = parsed[0]
            host = parsed[1]
            if ':' in host:
                host, port = host.split(':')
                port = int(port)
            else:
                port = self.ports[protocol]

            self.rest = urlparse.urlunparse(('', '') + parsed[2:])
            if not self.rest:
                self.rest = "/"
            
            class_ = self.protocols[protocol]

            dest = client._parse(self.obj.address) # scheme, host, port, path

            endpoint = endpoints.TCP4ClientEndpoint(reactor, dest[1], dest[2])
            wrapper = SOCKSWrapper(reactor, config.sockshost, config.socksport, endpoint)
            f = class_(self.method, self.rest, self.clientproto, self.obj.headers, content, self, self.obj)
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

    def log(self, request):
        """
        Log a request's result to the logfile, by default in combined log format.
        """
        if config.logreqs and hasattr(self, "logFile"):
            line = '127.0.0.1 - - %s "%s" %d %s "%s" "%s"\n' % (
                self._logDateTime,
                '%s %s %s' % (self._escape(request.method),
                            self._escape(request.uri),
                            self._escape(request.clientproto)),
                request.code,
                request.sentLength or "-",
                self._escape(request.getHeader("referer") or "-"),
                self._escape(request.getHeader("user-agent") or "-"))
            self.logFile.write(line)

def startTor2webHTTP(t2w, f):
    return internet.TCPServer(int(t2w.config.listen_port_http), f)

def startTor2webHTTPS(t2w, f):
    return internet.SSLServer(int(t2w.config.listen_port_https), f, T2WSSLContextFactory(t2w.config.sslkeyfile, t2w.config.sslcertfile, t2w.config.ssldhfile, t2w.config.cipher_list))

sys.excepthook = MailException

factory = T2WProxyFactory()

service_https = startTor2webHTTPS(t2w, factory)
service_https.setServiceParent(application)

service_http = startTor2webHTTP(t2w, factory)
service_http.setServiceParent(application)
