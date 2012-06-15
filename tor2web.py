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

from twisted.python import log

import os
import sys
import hashlib
import re
import pickle

from mimetypes import guess_type
from urlparse import urlparse

from config import Config 
from storage import Storage

rexp = {
    'href': re.compile(r'<[a-z]*\s*.*?\s*href\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*.*?>', re.I),
    'src': re.compile(r'<[a-z]*\s*.*?\s*src\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*.*?>', re.I),
    'action': re.compile(r'<[a-z]*\s*.*?\s*action\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*.*?>', re.I),
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

        # Debug mode
        self.debug = config.debugmode

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

        # SOCKS proxy
        self.sockshost = config.sockshost
        self.socksport = config.socksport

        # Hotlinking
        self.hotlinking = False

        self.result = Storage()

        self.error = {}

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
           fh.write(l+"\n")
        fh.close()
        return

    def petname_lookup(self, address):
        """
        Do a lookup in the local database
        for an entry in the petname db.

        :address the address to lookup
        """
        return address

    def verify_onion(self, address):
        """
        Check to see if the address
        is a .onion.
        returns the onion address as a string if True
        else returns False
        """
        onion, tld = address.split(".")
        log.msg("onion: %s tld: %s" % (onion, tld))
        if tld == "onion" and \
            len(onion) == 16 and \
            onion.isalnum():
            return address
        else:
            return False

    def resolve_hostname(self, host, uri):
        """
        Resolve the supplied request to a hostname.
        Hostnames are accepted in the <onion_url>.<tor2web_domain>.<tld>/
        or in the x.<tor2web_domain>.<tld>/<onion_url>.onion/ format.
        """
        # Detect x.tor2web.org use mode
        log.msg("RESOLVING: %s" % host)
        if host.split(".")[0] == "x":
            self.xdns = True
            self.hostname = self.petname_lookup(uri.split("/")[1])
            log.msg("DETECTED x.tor2web Hostname: %s" % self.hostname)
        else:
            self.xdns = False
            self.hostname = self.petname_lookup(host.split(".")[0]) + ".onion"
            log.msg("DETECTED <onion_url>.tor2web Hostname: %s" % self.hostname)
        try:
            verified = self.verify_onion(self.hostname)
        except:
            return False

        if verified:
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
        log.msg("URI: %s" % uri)

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
        if not self.resolve_hostname(req.host, req.uri):
            return False
  
        # Clean up the uri
        uri = self.get_uri(req)
   
        if hashlib.md5(self.hostname).hexdigest() in self.blocklist:
          self.error = {'message': 'Hidden Service Blocked','code': 403}
          return False

        if hashlib.md5(self.hostname + uri).hexdigest() in self.blocklist:
          self.error = {'message': 'Specific Page Blocked','code': 403}
          return False

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
        log.msg("Headers:")
        log.msg(self.headers)
        return self.address

    def leaving_link(self, target):
        """
        Returns a link pointing to a resource outside of Tor2web.
        """
        link = target.netloc + target.path
        link += "?" + target.query if target.query else ""

        return 'https://leaving.' + self.basehost + '/' + link

    def fix_link(self, address):
        """
        Operates some links corrections.
        """
        data = address

        if data.startswith("/"):
            log.msg("LINK starts with /")
            if self.xdns:
                link = "/" + self.hostname + data
            else:
                link = data

        elif data.startswith("http"):
            log.msg("LINK starts with http://")
            o = urlparse(data)
            if not o.netloc.endswith(".onion"):
                # This is an external link outside of the deep web!
                link = self.leaving_link(o)
                return link

            if self.xdns:
                link = "/" + o.netloc + o.path
                link += "?" + o.query if o.query else ""
            else:
                if o.netloc.endswith(".onion"):
                    netloc = o.netloc.get_addrreplace(".onion", "")
                    if o.scheme == "http":
                        link = "http://"
                    else:
                        link = 'https://'
                    link += netloc + "." + self.basehost + o.path
                    link += "?" + o.query if o.query else ""

        elif data.startswith("data:"):
            log.msg("LINK starts with data:")
            link = data

        else:
            log.msg("LINK starts with link: %s" % data)
            if self.xdns:
                link = '/' + self.hostname + '/'.join(self.path.split("/")[:-1]) + '/' + data
            else:
                link = data
        return link


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
        link = self.fix_link(data.group(1))

        return data.group(0).replace(data.group(1), link)

    def add_banner(self, data):
        """
        Inject tor2web banner inside the returned page
        """
        return str(data.group(1))+str(self.banner)


    def process_links(self, data):
        """
        Process all the possible HTML tag attributes that may contain links.
        """
        log.msg("processing url attributes")

        ret = None

        items = ["src", "href", "action"]
        for item in items:
          ret = re.sub(rexp[item], self.fix_links, data)

        log.msg("finished processing links...")

        return ret

    def process_html(self, content):
        """
        Process the result from the Hidden Services HTML
        """
        log.msg("processing HTML type content")

        ret = None

        final = self.process_links(content)

        ret = re.sub(rexp['body'], self.add_banner, final)

        return ret

