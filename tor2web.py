"""
    Tor2web
    Copyright (C) 2012 Hermes No Profit Association - GlobaLeaks Project

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: [GLOBALEAKS_MODULE_DESCRIPTION]

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

from config import Config 
from storage import Storage

import sys
import hashlib
import re

from urlparse import urlparse

from twisted.python import log

rexp = {
    'href': re.compile(r'<[a-z]*\s*.*?\s*href\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*.*?>', re.I),
    'src': re.compile(r'<[a-z]*\s*.*?\s*src\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*.*?>', re.I),
    'action': re.compile(r'<[a-z]*\s*.*?\s*action\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*.*?>', re.I),
    'body': re.compile(r'(<body.*?\s*>)', re.I)
    }

from functools import partial

class Tor2webObj():
    # This is set if we are contacting tor2web from x.tor2web.org
    xdns = False;
    
    onion = ""
    
    # The path portion of the URI
    path = None
    
    # The full address (hostname + uri) that must be requested
    address = None

    # The headers to be sent
    headers = None
    
    # The requested uri
    uri = None
    
    error = {}
    
    client_supports_keepalive = False
    client_supports_chunked = False
    client_supports_gzip = False

    server_response_is_keepalive = False
    server_response_is_chunked = False
    server_response_is_gzip = False

class Tor2web(object):
    def __init__(self, config):
        """
        Process tor2web requests, fix links, inject banner and
        all that happens between a client request and the fetching
        of the content from the Tor Hidden Service.

        :config a config object
        """
        self.config = config
        
        self.Tor2webLog = log.LogPublisher()

        if config.debugmode:
            stdobserver = log.PythonLoggingObserver('Tor2web')
            fileobserver = log.FileLogObserver(open(config.debuglogpath, 'w'))
            self.Tor2webLog.addObserver(stdobserver.emit)
            self.Tor2webLog.addObserver(fileobserver.emit)
        
        self.basehost = config.basehost

        # Blocklists
        self.blocklist = self.load_filelist(config.blocklist_hashed)
        
        itemlist = self.load_filelist(config.blocklist_cleartext)
        for i in itemlist:
            self.blocklist.append(hashlib.md5(i).hexdigest())
        
        self.blocklist = set(self.blocklist) # eliminate duplicates
        self.dump_filelist(config.blocklist_hashed, self.blocklist)

        self.blocked_ua = self.load_filelist(config.blocked_ua)

        # Banner
        self.banner = open(config.bannerfile, "r").read()

    def load_filelist(self, filename):
        """
        Load the list from the specified file.
        """
        fh = open(filename, "r")
        entrylist = []
        for l in fh.readlines():
            # permit comments inside list following the first space 
            entrylist.append(re.split('[ , \n,\t]', l)[0])
        fh.close()
        return entrylist

    def dump_filelist(self, filename, listtodump):
        """
        Dump the list to the specified file.
        """
        fh = open(filename, "w")
        for l in listtodump:
           fh.write(l + "\n")
        fh.close()
        return True

    def petname_lookup(self, obj, address):
        """
        Do a lookup in the local database
        for an entry in the petname db.

        :address the address to lookup
        """
        return address

    def verify_onion(self, obj, address):
        """
        Check to see if the address
        is a .onion.
        returns the onion address as a string if True
        else returns False
        """
        onion, tld = address.split(".")
        self.Tor2webLog.msg("onion: %s tld: %s" % (onion, tld))
        if tld == "onion" and len(onion) == 16 and onion.isalnum():
            obj.onion = onion
            return True
        else:
            return False

    def resolve_hostname(self, obj, host, uri):
        """
        Resolve the supplied request to a hostname.
        Hostnames are accepted in the <onion_url>.<tor2web_domain>.<tld>/
        or in the x.<tor2web_domain>.<tld>/<onion_url>.onion/ format.
        """
        # Detect x.tor2web.org use mode
        self.Tor2webLog.msg("RESOLVING: %s" % host)
        if host.split(".")[0] == "x":
            obj.xdns = True
            obj.hostname = self.petname_lookup(obj, uri.split("/")[1])
            self.Tor2webLog.msg("DETECTED x.tor2web Hostname: %s" % obj.hostname)
        else:
            obj.xdns = False
            obj.hostname = self.petname_lookup(obj, host.split(".")[0]) + ".onion"
            self.Tor2webLog.msg("DETECTED <onion_url>.tor2web Hostname: %s" % obj.hostname)
        try:
            if self.verify_onion(obj, obj.hostname):
                return True
        except:
            pass
        
        obj.error = {'message': 'invalid hostname', 'code': 406}
        return False

    def get_uri(self, obj, req):
        """
        Obtain the URI part of the request.
        This is non-trivial when the x.tor2web format is being used.
        In that case we need to remove the .onion from the requested
        URI and return the part after .onion.
        """
        if obj.xdns:
            obj.uri = '/' + '/'.join(req.uri.split("/")[2:])
        else:
            obj.uri = req.uri
        self.Tor2webLog.msg("URI: %s" % obj.uri)

        return obj.uri

    def get_address(self, obj, req):
        """
        Returns the address of the request to be
        made of the Tor Network to contact the Tor
        Hidden Service.
        returns a string being http://<some>.onion/<URI>
        """

        # Resolve the hostname
        if not self.resolve_hostname(obj, req.host, req.uri):
            return False
  
        # Clean up the uri
        uri = self.get_uri(obj, req)
   
        if hashlib.md5(obj.hostname).hexdigest() in self.blocklist:
            obj.error = {'message': 'Hidden Service Blocked','code': 403}
            return False

        if hashlib.md5(obj.hostname + uri).hexdigest() in self.blocklist:
            obj.error = {'message': 'Specific Page Blocked','code': 403}
            return False

        # When connecting to HS use only HTTP
        obj.address = "http://" + obj.hostname + uri
        
        return True

    def process_request(self, obj, req):
        """
        Set the proper headers, "resolve" the address
        and return a result object.
        """
        self.Tor2webLog.msg(req)
        
        if not self.get_address(obj, req):
            return False

        obj.headers = req.headers
        
        self.Tor2webLog.msg("Headers before fix:")
        self.Tor2webLog.msg(obj.headers)

        obj.headers.update({'X-tor2web':'encrypted'})

        obj.headers.update({'connection':'close'})

        obj.headers.update({'accept-encoding':''})

        obj.headers['host'] = obj.hostname

        self.Tor2webLog.msg("Headers after fix:")
        self.Tor2webLog.msg(obj.headers)

        return True

    def leaving_link(self, obj, target):
        """
        Returns a link pointing to a resource outside of Tor2web.
        """
        link = target.netloc + target.path
        if target.query:
            link += "?" + target.query

        return 'https://leaving.' + self.basehost + '/' + link

    def fix_link(self, obj, data):
        """
        Operates some links corrections.
        """
        parsed = urlparse(data)

        scheme = parsed.scheme

        if scheme == "http":
            scheme = "https"
            
        if scheme == "data":
            link = data
            return link;
        
        if scheme == "":
            if obj.xdns:
                link = "/" + obj.hostname + data
            else:
                link = data
        else:
            if parsed.netloc == "":
                netloc = obj.hostname
            else:
                netloc = parsed.netloc
        
            if netloc.endswith(".onion"):
                netloc = netloc.replace(".onion", "")
                
            link = scheme + "://"
            
            if netloc != obj.onion:
                link = self.leaving_link(obj, parsed)
            elif obj.xdns:
                link += '/' + netloc + '/'.join(obj.path.split("/")[:-1]) + '/' + data
            else:
                link += netloc + "." + self.basehost + parsed.path

            if parsed.query:
              link += "?" + parsed.query
        
        return link

    def fix_links(self, obj, data):
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
        link = self.fix_link(obj, data.group(1))

        return data.group(0).replace(data.group(1), link)

    def add_banner(self, obj, data):
        """
        Inject tor2web banner inside the returned page
        """
        return str(data.group(1))+str(self.banner)

    def process_links(self, obj, data):
        """
        Process all the possible HTML tag attributes that may contain links.
        """
        self.Tor2webLog.msg("processing url attributes")

        items = ["src", "href", "action"]
        for item in items:
          data = re.sub(rexp[item], partial(self.fix_links, obj), data)

        self.Tor2webLog.msg("finished processing links...")

        return data

    def process_html(self, obj, data):
        """
        Process the result from the Hidden Services HTML
        """
        self.Tor2webLog.msg("processing HTML type content")

        data = self.process_links(obj, data)

        data = re.sub(rexp['body'], partial(self.add_banner, obj), data)

        return data
