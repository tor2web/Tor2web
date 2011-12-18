# Tor2web calamity edition.
# Arturo Filasto' <art@globaleaks.org>
#
# a re-implementation of Tor2web in Python over Tornado

import os
import sys
import hashlib
import base64

from mimetypes import guess_type
from pprint import pprint
from urlparse import urlparse

import ConfigParser

from BeautifulSoup import BeautifulSoup
# import gevent
# from gevent import monkey

import tornado.ioloop
import tornado.web
from tornado import httpclient

from utils import Storage

http_client = httpclient.HTTPClient()

class Tor2web(object):
    def __init__(self, config):
        
        self.basehost = config.basehost
        
        # This is set if we are contacting
        # tor2web from x.tor2web.org
        self.xdns = False
        
        # The hostname of the requested HS
        self.hostname = ""

        # The path portion of the URI
        self.path = None
        
        # The full address (hostname + uri) that must be requested
        self.address = None
        
        # The headers to be sent
        self.headers = None

        # DEBUG MODE
        self.debug = True

        # Blocklist
        self.blocklist = self.parse_blocklist(config.blocklist)

        # Banner file
        self.bannerfile = config.bannerfile

        # SOCKS proxy
        self.sockshost = config.sockshost
        self.socksport = config.socksport
        
        self.result = Storage()
        
        self.error = {}

    def parse_blocklist(self, filename):
        fh = open(filename, "r")
        blocklist = []
        for l in fh.readlines():
            blocklist.append(l)
        return blocklist

    def petname_lookup(self, address):
        """ Do a lookup in the local database
        for an entry in the petname db
        """
        return address

    def verify_onion(self, address):
        """Check to see if the address
        is a .onion"""
        onion, tld = address.split(".")
        print "onion: %s tld: %s" % (onion, tld)
        if tld == "onion" and \
            len(onion) == 16 and \
            onion.isalnum():
            return address
        else:
            return False

    def resolve_hostname(self, req):
        """ Resolve the supplied request to a hostname.
        Hostnames are accepted in the <onion_url>.<tor2web_domain>.<tld>/
        or in the x.<tor2web_domain>.<tld>/<onion_url>.onion/ format.
        """
        # Detect x.tor2web.org use mode
        if req.host.split(".")[0] == "x":
            self.xdns = True
            self.hostname = self.petname_lookup(req.uri.split("/")[1]) 
            if self.debug:
                print "DETECTED x.tor2web Hostname: %s" % self.hostname
        else:
            self.xdns = False
            self.hostname = self.petname_lookup(req.host.split(".")[0]) + ".onion"
            if self.debug:
                print "DETECTED <onion_url>.tor2web Hostname: %s" % self.hostname
                
        if hashlib.md5(self.hostname) in self.blocklist:
            self.error = {'message': 'Site Blocked','code': 503}
            return False
        
        try:
            verified = self.verify_onion(self.hostname)
        except:
            return False
        
        if verified:
            print "Verified!"
            return True
        else:
            self.error = {'message': 'invalid hostname', 'code': 406}
            return False
            
    def get_uri(self, req):
        if self.xdns:
            uri = '/' + '/'.join(req.uri.split("/")[2:])
        else:
            uri = req.uri
        if self.debug:
            print "URI: %s" % uri

        return uri
    
    def get_address(self, req):
        # When connecting to HS use only HTTP
        address = "http://"
        # Resolve the hostname
        if not self.resolve_hostname(req):
            return False
        # Clean up the uri
        uri = self.get_uri(req)
        
        address += self.hostname + uri
        
        # Get the base path
        self.path = urlparse(address).path
        return address

    def process_request(self, req):
        self.address = self.get_address(req)
        if not self.address:
            return False
        self.headers = req.headers
        self.headers['Host'] = self.hostname
        if self.debug:
            print "Headers:"
            pprint(self.headers)
        return self.result

    def fix_links(self, data):
        """ Fix all possible links to properly resolve to the
        correct .onion.
        Examples:
        when visiting x.tor2web.org
        /something -> /<onion_url>.onion/something
        <other_onion_url>.onion/something/ -> /<other_onion_url>.onion/something
        
        
        when visiting <onion_url>.tor2web.org
        /something -> /something
        <other_onion_url>/something -> <other_onion_url>.tor2web.org/something
        """
        if data.startswith("/"):
            if self.debug:
                print "LINK starts with /"
            if self.xdns:
                link = "/" + self.hostname + data
            else:
                link = data
                
        elif data.startswith("http"):
            if self.debug:
                print "LINK starts with http://"
            o = urlparse(data)
            if self.xdns:
                link = "/" + o.netloc + o.path
                link += "?" + o.query if o.query else ""
            else:
                if o.netloc.endswith(".onion"):
                    o.netloc.replace(".onion", "")
                link = o.netloc + "." + self.basehost + o.path
                link += "?" + o.query if o.query else ""
        else:
            if self.debug:
                print "LINK starts with "
                print "link: %s" % data
            if self.xdns:
                link = '/' + self.hostname + '/'.join(self.path.split("/")[:-1]) + '/' + data
            else:
                link = data
        
        return link

    def process_links(self, data):
        if self.debug:
            print "processing src attributes"

        for el in data.findAll(['img','script']):
            if self.debug:
                print "el['href'] %s" % el
            try:
                el['src'] = self.fix_links(el['src'])            
            except:
                pass
            
        if self.debug:
            print "processing href attributes"
            
        for el in data.findAll(['a','link']):
            try:
                el['href'] = self.fix_links(el['href'])
            except:
                pass
        for el in data.findAll('form'):
            try:
                el['action'] = self.fix_links(el['action'])
            except:
                pass
        if self.debug:
            print "Finished processing links..."
        return data

    def process_html(self, content):
        soup = BeautifulSoup(content)        
        if self.debug:
            print "Now processing head..."
        try:
            head = self.process_links(soup.html.head)
        except:
            print "ERROR: in processing HEAD HTML"
            
        if self.debug:
            print "Now processing body..."
        try:
            body = self.process_links(soup.html.body)
        except:
            print "ERROR: in processing BODY HTML"
            
        banner = open(self.bannerfile, "r").read()
        body.insert(0, banner)
        ret = str(head) + str(body)
        return ret
    
class Config(Storage):
    """
    A Storage-like class which loads and store each attribute into a portable
    conf file.
    """
    def __init__(self, section, cfgfile="tor2web.conf"):
        super(Config, self).__init__()

        self._cfgfile = cfgfile
        # setting up confgiparser
        self._cfgparser = ConfigParser.ConfigParser()
        self._cfgparser.read([self._cfgfile])
        self._section = section

    def __getattr__(self, name):
        if name.startswith('_'):
            return self.__dict__.get(name, None)

        try:
            value = self._cfgparser.get(self._section, name)
            if value.isdigit():
                return int(value)
            elif value.lower() in ('true', 'false'):
                return value.lower() == 'true'
            else:
                return value
        except ConfigParser.NoOptionError:
            return ''  # if option doesn't exists return an empty string

    def __setattr__(self, name, value):
        # keep an open port with private attributes
        if name.startswith('_'):
            self.__dict__[name] = value
            return

        try:
            # XXX: Automagically discover variable type
            self._cfgparser.set(self._section, name, value)
        except ConfigParser.NoOptionError:
            raise NameError(name)

    def commit(self):
        """
        Commit changes in config file.
        """
        cfgfile = open(self._cfgfile, 'w')
        try:
            self._cfgparser.write(cfgfile)
        finally:
            cfgfile.close()
    

