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
import tornado.httpserver

import tornado.ioloop
import tornado.web

import socks

from tor2web import Tor2web, Config
from utils import SocksiPyConnection, SocksiPyHandler

config = Config("main")

from tornado.httpclient import AsyncHTTPClient

t2w = Tor2web(config)

class Tor2webHandlerUL(tornado.web.RequestHandler):
    def all(self):
        """Handle all requests coming from the client.
        XXX This needs a serious cleanup, but it is the result
        of one day going mad over a bug...
        """
        content = None
        result = t2w.process_request(self.request)
        
        if t2w.result.error:
            pass
        
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
    
    if config.sslcertfile and config.sslkeyfile:
        sslopt = {'certfile': config.sslcertfile,
                  'keyfile': config.sslkeyfile
                  }
        
    http_server = tornado.httpserver.HTTPServer(application,
                                                ssl_options=sslopt)
    
    http_server.listen(int(config.listen_port))
    tornado.ioloop.IOLoop.instance().start()
    
    
