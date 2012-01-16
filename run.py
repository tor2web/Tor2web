# Tor2web calamity edition.
# Arturo Filasto' <art@globaleaks.org>
#
# a re-implementation of Tor2web in Python over Tornado

import os
import sys
from pprint import pprint
import urllib
import urllib2
import ssl
import gzip

from StringIO import StringIO

import socket


import ssl

import tornado.httpclient
import tornado.httpserver

import tornado.ioloop
import tornado.web

import socks

from tor2web import Tor2web, Config
from utils import SocksiPyConnection, SocksiPyHandler

config = Config("main")

t2w = Tor2web(config)

class Tor2webHandlerUL(tornado.web.RequestHandler):
    def all(self):
        """Handle all requests coming from the client.
        XXX This needs a serious cleanup, but it is the result
        of one day going mad over a bug...
        """
        print "Handling a request..."
        content = None
        t2w.error = {}
        
        result = t2w.process_request(self.request)
        
        if t2w.error:
            self.set_status(t2w.error['code'])
            self.write(t2w.error['message'])
            self.finish()
            return False
                
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
            
        except urllib2.HTTPError, e:
            self.set_status(e.code)
            self.write(e.read())
            self.finish()
            return False
        
        try:
            header_array = response.info().headers
            headers = {}
        except:
            print "Error reading headers"
        
        try:
            if config.debug:
                print "Going Through the response headers..."
            for h in header_array:
                name = h.split(":")[0]
                value = ':'.join(h.split(":")[1:]).strip()
                headers[name] = value
                # Ignore the Connection header
                disabled_headers = ['Content-Encoding',
                                    'Connection',
                                    'Vary',
                                    'Transfer-Encoding']
                
                if name not in disabled_headers:
                    self.set_header(name, value)
                    
            pprint(headers)
        except:
            print "Error in going through headers..."
        
        try: 
            content = response.read()
            
        except:
            print "ERROR: failed to process request"
            
        
        try:
            if content:
                if headers.get("Content-Encoding") == "gzip":
                    c_f = StringIO(content)
                    content = gzip.GzipFile(fileobj=c_f).read()
                ret = t2w.process_html(content)
                self.write(ret)
                self.finish()
        except:
            if content:
                self.write(content)
                self.finish()
    
    def get(self, *a, **b):
        self.all()

    def post(self, *a, **b):
        self.all()


if __name__ == "__main__":
    application = tornado.web.Application([
        (r"/"+config.staticmap+"/(.*)", tornado.web.StaticFileHandler, \
                    {"path": config.staticpath}),
        (r"/.*", Tor2webHandlerUL)
    ])

    # SSL PYTHON BUGS
    # - 1 NO EASY WAY TO DISABLE SSLv2 
    # - 2 NO WAY TO ENABLE DHE (PERFECT FORWARD SECRECY)
    
    # BUG  1 NO EASY WAY TO DISABLE SSLv2
    # http://bugs.python.org/issue4870
    # http://www.velocityreviews.com/forums/t651673-re-ssl-module-
    #        how-can-i-accept-sslv3-and-tlsv1-protocols-only.html
    # WORKAROUND: WE Leave SSLv2 enabled as a protocol, but disable SSLv2 in the
    #             Cipher selection
    # Note: SSLv3 is required due to safari, only TLSv1 doesn't work on all browsers
    #
    #
    # BUG  2 NO WAY TO ENABLE DHE (PERFECT FORWARD SECRECY)
    # WORKAROUND: NOT FONUD
    # Test with openssl s_client -connect 88.198.109.35:8888  -cipher 'DHE-RSA-AES256-SHA'
    if config.sslcertfile and config.sslkeyfile:
        sslopt = {
         'certfile': config.sslcertfile,
         'keyfile': config.sslkeyfile,
         'ca_certs': config.sslcacert,
         # FUTURE (Python 3) setup to fully disable SSLv2
         #        'ssl_version':ssl.PROTOCOL_SSLv23,
         #        'ssl_options':ssl.OP_NO_SSLv2,
         # CURRENT CIPHERLIST
         'ciphers': 'HIGH:!aNULL:!SSLv2:!MD5:@STRENGTH'
        # FUTURE (When Python support SSL DH)
        #        'ciphers': 'DHE-RSA-AES256-SHA:AES256-SHA:\
        #           !CBC:!RC4:!RC2:!ADH:!aNULL:!EDH:!eNULL:!LOW:!SSLv2:!EXP:!NULL'
        }
    else:
        sslopt = None
    
    http_server = tornado.httpserver.HTTPServer(application,
                                                ssl_options=sslopt)
    
    http_server.listen(int(config.listen_port))
    print "Starting on %s" % (config.basehost)
    tornado.ioloop.IOLoop.instance().start()
    
    
