import httplib
import urllib2
import socks

class Storage(dict):
    """
    A Storage object is like a dictionary except `obj.foo` can be used
    in addition to `obj['foo']`.
    
        >>> o = Storage(a=1)
        >>> o.a
        1
        >>> o['a']
        1
        >>> o.a = 2
        >>> o['a']
        2
        >>> del o.a
        >>> o.a
        None
    
    """

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError, k:
            return None

    def __setattr__(self, key, value):
        self[key] = value

    def __delattr__(self, key):
        try:
            del self[key]
        except KeyError, k:
            raise AttributeError, k

    def __repr__(self):
        return '<Storage ' + dict.__repr__(self) + '>'

    def __getstate__(self):
        return dict(self)

    def __setstate__(self, value):
        for (k, v) in value.items():
            self[k] = v

class SocksiPyConnection(httplib.HTTPConnection):
    def __init__(self, proxytype, proxyaddr, proxyport = None, 
                 rdns = True, username = None, password = None, *args, **kwargs):
        self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
        httplib.HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        self.sock = socks.socksocket()
        self.sock.setproxy(*self.proxyargs)
        if isinstance(self.timeout, float):
            self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
            
class SocksiPyHandler(urllib2.HTTPHandler):
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kw = kwargs
        urllib2.HTTPHandler.__init__(self)

    def http_open(self, req):
        def build(host, port=None, strict=None, timeout=0):    
            conn = SocksiPyConnection(*self.args, host=host, 
                                      port=port, strict=strict, 
                                      timeout=timeout, **self.kw)
            return conn
        return self.do_open(build, req)

