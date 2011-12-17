# Tor2web calamity edition.
# Arturo Filasto' <art@globaleaks.org>
#
# a re-implementation of Tor2web in Python over Tornado

import os
import sys
from pprint import pprint

import tornado.httpclient
import tornado.ioloop
import tornado.web
from tornado.httpclient import AsyncHTTPClient

from tor2web import Tor2web, Config

config = Config("main")
t2w = Tor2web(config)

class Tor2webHandler(tornado.web.RequestHandler):
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
                    proxy_host="socks://"+t2w.sockshost,
                    proxy_port=t2w.socksport,
                    follow_redirects=True)
        
        AsyncHTTPClient.configure("curl_httpclient_socks.CurlAsyncHTTPClient")
        AsyncHTTPClient().fetch(req, 
                self.handle_response) 

    
    def get(self, *a, **b):
        self.all()

    def post(self, *a, **b):
        self.all()

if __name__ == "__main__":
    application = tornado.web.Application([
        (r"/(.*)", Tor2webHandler),
    ])
    application.listen(8888)
    tornado.ioloop.IOLoop.instance().start()
    
    
