# Tor2web Cataclysm edition.
#
# Tor2web allows users that are not using a Tor client
# to access Tor Hidden Services. It trades user anonymity
# (that is in now way guaranteed) for usability, while still
# protecting the Tor Hidden Service from disclosure.
#
# This particular version is a re-implementation of Tor2web
# in Python with the Tornado non-blocking HTTP server.
# coded by:
# Arturo Filasto' <art@globaleaks.org>
# Original concept and implementation as apache config file by:
# Aaaron Swartz
#

import os
import sys
import hashlib
import base64
import re

from mimetypes import guess_type
from pprint import pprint
from urlparse import urlparse

import ConfigParser

from utils import Storage

http_client = httpclient.HTTPClient()

rexp = {
    'href': re.compile(r'<[a-z]*\s*.*?\s*href\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*>', re.I),
    'src': re.compile(r'<[a-z]*\s*.*?\s*src\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*>', re.I),
    'action': re.compile(r'<[a-z]*\s*.*?\s*action\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*>', re.I),
    'body': re.compile(r'(<body.*?\s*>)', re.I)
    }

class Tor2web(object):
    def __init__(self, config):
        """
        Process tor2web requests, fix links, inject banner and
        all that happens between a client request and the fetching
        of the content from the Tor Hidden Service.

        :config a config object
        """
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

        # Hotlinking
        self.hotlinking = False

        self.result = Storage()

        self.error = {}

    def parse_blocklist(self, filename):
        """
        Parse the blocklist file and return a list containing
        the to be blocked sites.
        """
        fh = open(filename, "r")
        blocklist = []
        for l in fh.readlines():
            blocklist.append(l.strip())
        fh.close()
        return blocklist

    def petname_lookup(self, address):
        """
        Do a lookup in the local database
        for an entry in the petname db.

        :address the address to lookup
        """
        # XXX make me do something actually useful :P
        return address

    def verify_onion(self, address):
        """
        Check to see if the address
        is a .onion.
        returns the onion address as a string if True
        else returns False
        """
        onion, tld = address.split(".")
        if self.debug:
            print "onion: %s tld: %s" % (onion, tld)
        if tld == "onion" and \
            len(onion) == 16 and \
            onion.isalnum():
            return address
        else:
            return False

    def resolve_hostname(self, req):
        """
        Resolve the supplied request to a hostname.
        Hostnames are accepted in the <onion_url>.<tor2web_domain>.<tld>/
        or in the x.<tor2web_domain>.<tld>/<onion_url>.onion/ format.
        """
        # Detect x.tor2web.org use mode
        if self.debug:
            print "RESOLVING: %s" % req.host
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

        if hashlib.md5(self.hostname).hexdigest() in self.blocklist:
            print "SITE BLOCKED!"
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
        """
        Obtain the URI part of the request.
        This is non-trivial when the x.tor2web format is being used.
        In that case we need to remove the .onion from the requested
        URI and return the part after .onion.
        """
        if self.xdns:
            uri = '/' + '/'.join(req.uri.split("/")[2:])
        else:
            uri = req.uri
        if self.debug:
            print "URI: %s" % uri

        return uri

    def get_address(self, req):
        """
        Returns the address of the request to be
        made of the Tor Network to contact the Tor
        Hidden Service.
        returns a string being http://<some>.onion/<URI>
        """
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
        """
        Set the proper headers, "resolve" the address
        and return a result object.
        """
        self.address = self.get_address(req)
        if not self.address:
            return False
        self.headers = req.headers
        self.headers['Host'] = self.hostname
        # Hack to avoid getting GZIP
        if 'accept-encoding' in self.headers:
            del self.headers['accept-encoding']
        if self.debug:
            print "Headers:"
            pprint(self.headers)
        # XXX verify why here I return self.result, it appears to be
        # empty and it is probably an idea I had, but did not finish
        # implementing... (too much code, too little sleep...)
        return self.result

    def leaving_link(self, target):
        """
        Returns a link pointing to a resource outside of Tor2web.
        """
        link = target.netloc + target.path
        link += "?" + target.query if target.query else ""

        return 'https://leaving.' + self.basehost + '/' + link

    def fix_links(self, data):
        """
        Fix links in the result from HS to properly resolve to be pointing to
        blabla.tor2web.org or x.tor2web.org.

        Examples:
        when visiting x.tor2web.org
        /something -> /<onion_url>.onion/something
        <other_onion_url>.onion/something/ -> /<other_onion_url>.onion/something

        when visiting <onion_url>.tor2web.org
        /something -> /something
        <other_onion_url>/something -> <other_onion_url>.tor2web.org/something
        """
        allmatch = data.group(0)
        innermatch = data.group(1)
        data = innermatch

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

            if not o.netloc.endswith(".onion"):
                # This is an external link outside of the deep web!
                link = self.leaving_link(o)
                return allmatch.replace(innermatch, link)

            if self.xdns:
                link = "/" + o.netloc + o.path
                link += "?" + o.query if o.query else ""
            else:
                if o.netloc.endswith(".onion"):
                    o.netloc.replace(".onion", "")
                    link = 'https://'
                    link += o.netloc + "." + self.basehost + o.path
                    link += "?" + o.query if o.query else ""

        elif data.startswith("data:"):
            if self.debug:
                print "LINK starts with data:"
            link = data

        else:
            if self.debug:
                print "LINK starts with "
                print "link: %s" % data
            if self.xdns:
                link = '/' + self.hostname + '/'.join(self.path.split("/")[:-1]) + '/' + data
            else:
                link = data

        return allmatch.replace(innermatch, link)

    def add_banner(self, data):
        data = data.group(1)
        print "making pretty banners!!"
        banner = open(self.bannerfile, "r").read()
        return str(data)+str(banner)


    def process_links(self, data):
        """
        Process all the possible HTML tag attributes that may contain
        links.
        """
        if self.debug:
            print "processing src attributes"

        ret = re.sub(rexp['src'], self.fix_links, data)
        ret = re.sub(rexp['href'], self.fix_links, ret)
        ret = re.sub(rexp['action'], self.fix_links, ret)

        if self.debug:
            print "Finished processing links..."

        return ret

    def process_html(self, content):
        """
        Process the result from the Hidden Services HTML
        """
        ret = None
        if self.debug:
            print "Processing HTML type content"

        final = self.process_links(content)

        ret = re.sub(rexp['body'], self.add_banner, final)

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


