# -*- coding: utf-8 -*-
"""
    config.py
    -------

"""

class Tor2webProxyClient(proxy.ProxyClient):
    def __init__(self, *args, **kwargs):
        proxy.ProxyClient.__init__(self, *args, **kwargs)
        self.bf = []
        self.contenttype = 'unknown'
        self.gzip = False
        self.html = False
        self.location = False
        self._chunked = False

    def handleHeader(self, key, value):

        if key.lower() == "content-encoding" and value == "gzip":
            self.gzip = True
            return

        if key.lower() == "location":
            self.location = t2w.fix_link(value)
            return

        if key.lower() == "transfer-encoding" and value == "chunked":
            self._chunked = http._ChunkedTransferDecoder(self.handleResponsePart,
                                                         self.handleResponseEnd)
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
        if self.location:
            proxy.ProxyClient.handleHeader(self, "Location", self.location)

    def rawDataReceived(self, data):
        if self.length is not None:
            data, rest = data[:self.length], data[self.length:]
            self.length -= len(data)
        else:
            rest = ''

        if self._chunked:
            self._chunked.dataReceived(data)
        else:
            self.handleResponsePart(data)

        if self.length == 0:
            self.handleResponseEnd()
            self.setLineMode(rest)

    def handleResponsePart(self, buffer):
        self.bf.append(buffer)

    def connectionLost(self, reason):
        proxy.ProxyClient.handleResponseEnd(self)

    def handleResponseEnd(self, *args, **kwargs):
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
            proxy.ProxyClient.handleHeader(self, 'cache-control', 'no-cache')
            proxy.ProxyClient.handleHeader(self, "Content-Length", len(content))
            proxy.ProxyClient.handleEndHeaders(self)
            proxy.ProxyClient.handleResponsePart(self, content)
            proxy.ProxyClient.handleResponseEnd(self)
            self.finish()

            return server.NOT_DONE_YET
        else:
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

        if myrequest.headers['user-agent'] in t2w.blocked_ua:
            # Detected a blocked user-agent
            # Setting response code to 410 and sending Blocked UA string
            self.setResponseCode(410)
            self.write("Blocked UA\n")
            self.finish()
            return server.NOT_DONE_YET

        if self.uri.lower().endswith(('gif','jpg','png')):
            # OMFG this is a monster!
            # XXX refactor this into another "cleaner" place
            if not 'referer' in myrequest.headers or not config.basehost in myrequest.headers['referer'].lower():
                self.write(open('static/tor2web-small.png', 'r').read())
                self.finish()
                return server.NOT_DONE_YET

        if config.debug:
            print myrequest

        if not t2w.process_request(myrequest):
            self.setResponseCode(t2w.error['code'])
            self.write(t2w.error['message'])
            self.finish()
            return server.NOT_DONE_YET

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
        if 'accept-encoding' in headers:
            del headers['accept-encoding']

        #Print headers
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

class Tor2webProxyFactory(http.HTTPFactory):
    protocol = Tor2webProxy
