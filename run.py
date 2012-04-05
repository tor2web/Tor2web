# Tor2web calamity edition.
# Arturo Filasto' <art@globaleaks.org>
#
# a re-implementation of Tor2web in Python over Tornado

import os
import sys
from pprint import pprint
import urllib
import urllib2
import urlparse
import ssl
import re
import gzip
import socket

import tornado.web

from StringIO import StringIO

from twisted.application import service, internet
from twisted.internet import reactor, endpoints
from twisted.python import log
from twisted.web import proxy, http, client, server, static
from twisted.web.http import Request
from twisted.web.resource import Resource

from socksclient import SOCKSv4ClientProtocol, SOCKSWrapper

try:
    import socks
except:
    print "Error! Unable to import socks: SocksiPy not installed!"

from tor2web import Tor2web, Config
from utils import SocksiPyConnection, SocksiPyHandler, Storage

debug_mode = True

config = Config("main")

t2w = Tor2web(config)

class Tor2webProxyClient(proxy.ProxyClient):
    def __init__(self, *args, **kwargs):
        proxy.ProxyClient.__init__(self, *args, **kwargs)
        self.bf = []
        self.contenttype = 'unknown'
        self.gzip = False
        self.html = False

    def sendCommand(self, command, path):
        # Claim that we only speak HTTP 1.0 so we
        # will hopefully don't get chunked encoding.
        # If we do then we are screwed...
        # XXX nginx responds with chunked encoding even
        #     if we claim to only support HTTP 1.0 :(
        http_cmd = '%s %s HTTP/1.0\r\n' % (command, path)
        self.transport.write(http_cmd)

    def handleHeader(self, key, value):
        print "HEADERS!!"
        print "%s: %s" % (key, value)

        if key.lower() == "content-encoding" and value == "gzip":
            print "Detected GZIP!"
            self.gzip = True
            # Ignore this
            return

        if key.lower() == 'content-type' and re.search('text/html', value):
            self.html = True

        if key.lower() == "content-length":
            pass

        elif key.lower() == 'cache-control':
            pass

        elif key.lower() == 'connection':
            pass

        else:
            proxy.ProxyClient.handleHeader(self, key, value)

    def handleEndHeaders(self):
        pass

    def handleResponsePart(self, buffer):
        self.bf.append(buffer)

    def connectionLost(self, reason):
        proxy.ProxyClient.handleResponseEnd(self)

    def handleResponseEnd(self):
        content = ''.join(self.bf)
        if self.html:
            htmlc = True
        else:
            htmlc = False

        if self.gzip:
            c_f = StringIO(content)
            content = gzip.GzipFile(fileobj=c_f).read()

        #print type(content)
        if self.html:
            content = t2w.process_html(content)

        if content:
            #print "Y0 das iz th4 c0ntent."
            if htmlc:
                content = content.encode('utf-8')
            proxy.ProxyClient.handleHeader(self, 'cache-control', 'no-cache')
            proxy.ProxyClient.handleHeader(self, "Content-Length", len(content))
            #print "INSIDE OF EndHeaders"
            proxy.ProxyClient.handleEndHeaders(self)
            proxy.ProxyClient.handleResponsePart(self, content)
            proxy.ProxyClient.handleResponseEnd(self)
            self.finish()

            return server.NOT_DONE_YET
        else:
            #print "ELSE!!"
            proxy.ProxyClient.handleResponseEnd(self)
            self.finish()
            return server.NOT_DONE_YET

    def finish(self):
        pass


class Tor2webProxyClientFactory(proxy.ProxyClientFactory):
    protocol = Tor2webProxyClient


class Tor2webProxyRequest(Request):
    """
    Used by Tor2webProxy to implement a simple web proxy.

    @ivar reactor: the reactor used to create connections.
    @type reactor: object providing L{twisted.internet.interfaces.IReactorTCP}
    """

    protocols = {'http': Tor2webProxyClientFactory}
    ports = {'http': 80}

    def __init__(self, channel, queued, reactor=reactor):
        Request.__init__(self, channel, queued)
        self.reactor = reactor

    def process(self):
        myrequest = Storage()
        myrequest.headers = self.getAllHeaders().copy()
        myrequest.uri = self.uri
        myrequest.host = myrequest.headers['host']

        if self.uri.lower() == "/robots.txt" and config.blockcrawl:
            self.write("User-Agent: *\nDisallow: /\n")
            self.finish()
            return server.NOT_DONE_YET

        if self.uri.lower().endswith(('gif','jpg','png')):
            # OMFG this is a monster!
            # XXX refactor this into another "cleaner" place
            if not 'referer' in myrequest.headers or ('referer' in myrequest.headers and \
                        not re.search(config.basehost, myrequest.headers['referer'])):
                if 'referer' in myrequest.headers:
                    print re.search(config.basehost, myrequest.headers['referer'])
                print "FUck you"
                self.write(open('static/tor2web-small.png', 'r').read())
                self.finish()
                return server.NOT_DONE_YET

        if config.debug:
            print myrequest

        t2w.process_request(myrequest)
        # Rewrite the URI with the tor2web parsed one
        self.uri = t2w.address

        parsed = urlparse.urlparse(self.uri)
        if config.debug:
            print parsed
            print self.uri

        protocol = parsed[0]
        host = parsed[1]
        port = self.ports[protocol]
        if ':' in host:
            host, port = host.split(':')
            port = int(port)
        rest = urlparse.urlunparse(('', '') + parsed[2:])
        if not rest:
            rest = rest + '/'
        class_ = self.protocols[protocol]
        headers = self.getAllHeaders().copy()
        #print headers
        if 'host' not in headers:
            headers['host'] = host

        self.content.seek(0, 0)
        s = self.content.read()
        clientFactory = class_(self.method, rest, self.clientproto, headers, s, self)

        dest = client._parse(t2w.address) # scheme, host, port, path
        proxy = (None, 'localhost', 9050, True, None, None)
        endpoint = endpoints.TCP4ClientEndpoint(reactor, dest[1], dest[2])
        wrapper = SOCKSWrapper(reactor, proxy[1], proxy[2], endpoint)

        f = clientFactory

        d = wrapper.connect(f)

        return server.NOT_DONE_YET

class Tor2webProxy(proxy.Proxy):
    requestFactory = Tor2webProxyRequest

class ProxyFactory(http.HTTPFactory):
    protocol = Tor2webProxy

def startTor2web():

    return internet.TCPServer(int(config.listen_port), ProxyFactory())

application = service.Application("Tor2web")
service = startTor2web()
service.setServiceParent(application)

