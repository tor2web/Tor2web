# Tor2web calamity edition.
# Arturo Filasto' <art@globaleaks.org>
#
# a re-implementation of Tor2web in Python over Tornado

import os
import sys
from pprint import pprint
import urllib
import urllib2

import socket

import tornado.httpclient
import tornado.ioloop
import tornado.web

import socks

from tor2web import Tor2web, Config
from utils import SocksiPyConnection, SocksiPyHandler

config = Config("main")


from tornado.httpclient import AsyncHTTPClient

t2w = Tor2web(config)


# Disable two superflous classes, that I am too displeased of deleting
if 0:
    class Tor2webHandlerAsync(tornado.web.RequestHandler):
        def handle_response(self, response):
            for header in ("Date", "Cache-Control", "Server", "Content-Type", "Location"): 
                v = response.headers.get(header) 
                if v: 
                    self.set_header(header, v) 
    
            try:
                ret = t2w.process_html(response.body)
                self.write(ret)
                
            except:
                if response.body:
                    self.write(response.body)
                
            self.finish()
        @tornado.web.asynchronous
        def all(self):
            t2w.process_request(self.request)
            
            req = tornado.httpclient.HTTPRequest( 
                        url=t2w.address, 
                        method=self.request.method, 
                        headers=self.request.headers,
                        follow_redirects=True)
            
            AsyncHTTPClient().fetch(req, 
                    self.handle_response) 
    
        
        def get(self, *a, **b):
            self.all()
    
        def post(self, *a, **b):
            self.all()

    class Tor2webHandlerHTTPLib2(tornado.web.RequestHandler):
        def all(self):
            t2w.process_request(self.request)
            
            httpclient = httplib2.Http(
                            proxy_info = httplib2.ProxyInfo(
                                        socks.PROXY_TYPE_SOCKS5, 
                                        config.sockshost, int(config.socksport),
                                        proxy_rdns=True
                                        ))
            httpclient.force_exception_to_status_code = True
            
            print "BODY: %s" % self.request.body
            
            if self.request.body and len(self.request.body) > 0:
                body = urllib.urlencode(self.request.body)
            else:
                body = ""
    
            print "BODY HERE: %s" % body
            response, content = httpclient.request(t2w.address, 
                                method=self.request.method, 
                                headers=self.request.headers,
                                body=body)
            print response
            for header in ("date", "cache-control", "server", "content-type", "location"):
                v = response.get(header)
                if v: 
                    self.set_header(header, v)
            try:
                ret = t2w.process_html(content)
                self.write(ret)
            except:
                self.write(content)
            self.finish()
        
        def get(self, *a, **b):
            self.all()
    
        def post(self, *a, **b):
            self.all()


class Tor2webHandlerUL(tornado.web.RequestHandler):
    def all(self):
        """Handle all requests coming from the client.
        XXX This needs a serious cleanup, but it is the result
        of one day going mad over a bug...
        """
        content = None
        result = t2w.process_request(self.request)
        
        if t2w.result.error:
            
        
        if self.request.body and len(self.request.body) > 0:
            body = urllib.urlencode(self.request.body)
        else:
            body = ""

        if self.request.method == "POST":
            req = urllib2.Request(t2w.address,
                            data=body,
                            headers=self.request.headers)
        else:
            req = urllib2.Request(t2w.address,
                headers=self.request.headers)

        opener = urllib2.build_opener(SocksiPyHandler(
                                        socks.PROXY_TYPE_SOCKS4,
                                        config.sockshost, config.socksport))

        try:
            response = opener.open(req)
            header_array = response.info().headers
            headers = {}
            for h in header_array:
                name = h.split(":")[0]
                value = ':'.join(h.split(":")[1:]).strip()
                headers[name] = value
                # Ignore the Connection header
                if name != "Connection":
                    self.set_header(name, value)
            
            content = response.read()
        except:
            pass
        
        try:
            if content:
                ret = t2w.process_html(content)
                self.write(str(ret))
                self.flush()
        except:
            if content:
                self.write(content)
                self.flush()
    
    def get(self, *a, **b):
        self.all()

    def post(self, *a, **b):
        self.all()


if __name__ == "__main__":
    application = tornado.web.Application([
        (r"/(.*)", Tor2webHandlerUL),
    ])
    application.listen(8888)
    tornado.ioloop.IOLoop.instance().start()
    
    
