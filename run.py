# Tor2web calamity edition.
# Arturo Filasto' <art@globaleaks.org>
#
# a re-implementation of Tor2web in Python over Tornado

import tornado.ioloop
import tornado.web
from tor2web import Tor2web

t2w = Tor2web()

class MainHandler(tornado.web.RequestHandler):
        
    def get(self, *a, **b):
        self.write(t2w.handle(self.request))
    
    def post(self, *a, **b):
        self.write(t2w.handle(self.request))

if __name__ == "__main__":
    application = tornado.web.Application([
        (r"/(.*)", MainHandler),
    ])
    application.listen(8888)
    tornado.ioloop.IOLoop.instance().start()
