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
import gzip
import socket

import tornado.web

from StringIO import StringIO

from twisted.web import proxy, http, client, server
from twisted.web.http import Request
from twisted.internet import reactor, endpoints
from twisted.application import service, internet
from twisted.python import log

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

    def handleHeader(self, key, value):
        if config.debug:
            print "HEADERS!!"
            print "%s: %s" % (key, value)

        if key.lower() == "content-encoding" and value == "gzip":
            self.gzip = True

        if key.lower() == "content-length":
            pass

        elif key.lower() == 'cache-control':
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
        htmlc = True

        if self.gzip:
            #print "Detected GZIP"
            c_f = StringIO(content)
            content = gzip.GzipFile(fileobj=c_f).read()

        #print type(content)
        try:
            processed_content = t2w.process_html(content)
            content = processed_content
        except:
            htmlc = False
            if config.debug:
                print "Non HTML content detected!"

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
        #import traceback
        #print "McHacky McFinish"
        #traceback.print_stack()
        #proxy.ProxyClient.finish(self)
        pass


class Tor2webProxyClientFactory(proxy.ProxyClientFactory):
    protocol = Tor2webProxyClient


class Tor2webProxyRequest(Request):
    """
    Used by Tor2webProxy to implement a simple web proxy.

    @ivar reactor: the reactor used to create connections.
    @type reactor: object providing L{twisted.internet.interfaces.IReactorTCP}
    """

    #protocols = {'http': proxy.ProxyClientFactory}
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

    #reactor.listenTCP(int(config.listen_port), ProxyFactory())
    #print "Starting on %s" % (config.basehost)
    #reactor.run()
    return internet.TCPServer(int(config.listen_port), ProxyFactory())


application = service.Application("Tor2web")
service = startTor2web()
service.setServiceParent(application)

