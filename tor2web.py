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

from templating import ErrorTemplate, PageTemplate, Template
from fileList import fileList, updateFileList, hashedBlockList, torExitNodeList

from twisted.python import log

import sys
import hashlib
import re

from urlparse import urlparse

from functools import partial

rexp = {
    'href': re.compile(r'<[a-z]*\s*.*?\s*href\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*.*?>', re.I),
    'src': re.compile(r'<[a-z]*\s*.*?\s*src\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*.*?>', re.I),
    'action': re.compile(r'<[a-z]*\s*.*?\s*action\s*=\s*[\\\'"]?([a-z0-9/#:\-\.]*)[\\\'"]?\s*.*?>', re.I),
    'body': re.compile(r'(<body.*?\s*>)', re.I)
    }

class Tor2webObj():

    # The destination hidden service identifier
    onion = None
    
    # The path portion of the URI
    path = None
    
    # The full address (hostname + uri) that must be requested
    address = None

    # The headers to be sent
    headers = None
    
    # The requested uri
    uri = None
    
    error = {}
    
    client_supports_chunked = False
    client_supports_gzip = False

    server_response_is_chunked = False
    server_response_is_gzip = False
    
    contentNeedFix = False

class Tor2web(object):
    def __init__(self, config):
        """
        Process tor2web requests, fix links, inject banner and
        all that happens between a client request and the fetching
        of the content from the Tor Hidden Service.

        :config a config object
        """
        self.config = config

        self.basehost = config.basehost
        
        # Load banner template that will be injected in HTML pges
        self.banner = open("templates/header.xml", 'r').read()

        # Construct blocklist merging local lists and upstram updates
        
        # schedule upstream updates
        self.blocklist = hashedBlockList(config.blocklist_hashed)

        # clear local cleartext list (load -> hash -> clear feature; for security reasons)                                        
        self.blocklist_cleartext = fileList(config.blocklist_cleartext)
        for i in self.blocklist_cleartext:
            self.blocklist.add(hashlib.md5(i).hexdigest())

        self.blocklist.dump()

        self.blocklist_cleartext.clear()
        self.blocklist_cleartext.dump()

        self.blocked_ua = fileList(config.blocked_ua)

        # Load Exit Nodes list with the refresh rate configured  in config file
        self.TorExitNodes = torExitNodeList(config.exit_node_list,
                                            "https://onionoo.torproject.org/summary?type=relay",
                                            config.exit_node_list_refresh)

    def verify_onion(self, obj, address):
        """
        Check to see if the address is a .onion.
        returns the onion address as a string if True else returns False
        """
        onion, tld = address.split(".")
        log.msg('onion: %s tld: %s' % (onion, tld))
        if tld == 'onion' and len(onion) == 16 and onion.isalnum():
            obj.onion = onion
            return True
        
        return False

    def verify_hostname(self, obj, host, uri):
        """
        Resolve the supplied request to a hostname.
        Hostnames are accepted in the <onion_url>.<tor2web_domain>.<tld>/ format
        """
        if not host:
            obj.error = {'code': 400, 'template': 'error_invalid_hostname.xml'}
            return False
        
        obj.hostname = host.split(".")[0] + ".onion"
        log.msg("detected <onion_url>.tor2web Hostname: %s" % obj.hostname)

        try:
            if self.verify_onion(obj, obj.hostname):
                return True
        except:
            pass

        obj.error = {'code': 406, 'template': 'error_invalid_hostname.xml'}

        return False

    def get_address(self, obj, req):
        """
        Returns the address of the request to be made on the Tor Network
        to contact the Tor Hidden Service.
        
        the return address format is: http://<some>.onion/<URI>
        """
 
        obj.uri = req.uri
        log.msg("URI: %s" % obj.uri)
   
        if hashlib.md5(obj.hostname).hexdigest() in self.blocklist:
            obj.error = {'code': 403, 'template': 'error_hs_completely_blocked.xml'}
            return False

        if hashlib.md5(obj.hostname + obj.uri).hexdigest() in self.blocklist:
            obj.error = {'code': 403, 'template': 'error_hs_specific_page_blocked.xml'}
            return False

        # When connecting to HS use only HTTP
        obj.address = "http://" + obj.hostname + obj.uri

        return True

    def process_request(self, obj, req):
        """
        Set the proper headers, "resolve" the address  and return a result object.
        """
        log.msg(req)
        
        if not self.get_address(obj, req):
            return False

        obj.headers = req.headers
        
        log.msg("Headers before fix:")
        log.msg(obj.headers)

        obj.headers.update({'X-tor2web':'encrypted'})
        obj.headers.update({'connection':'close'})
        obj.headers.update({'accept-encoding':'gzip, chunked'})
        obj.headers.update({'host': obj.hostname})

        log.msg("Headers after fix:")
        log.msg(obj.headers)

        return True

    def leaving_link(self, obj, target):
        """
        Returns a link pointing to a resource outside of Tor2web.
        """
        link = target.netloc + target.path
        if target.query:
            link += "?" + target.query

        return "https://leaving." + self.basehost + "/" + link

    def fix_link(self, obj, data):
        """
        Operates some links corrections.
        """
        parsed = urlparse(data)
        exiting = True

        scheme = parsed.scheme

        if scheme == 'http':
            scheme = 'https'
            
        if scheme == 'data':
            link = data
            return link;
        
        if scheme == '':
            link = data
        else:
            if parsed.netloc == '':
                netloc = obj.hostname
            else:
                netloc = parsed.netloc

            if netloc == obj.onion:
                exiting = False
            elif netloc.endswith(".onion"):
                netloc = netloc.replace(".onion", "")
                exiting = False
                
            link = scheme + "://"

            if exiting:
                # Actually not implemented: need some study.
                # link = self.leaving_link(obj, parsed)
                link = data
            else:
                link += netloc + "." + self.basehost + parsed.path

            if parsed.query:
                link += "?" + parsed.query
        
        return link

    def fix_links(self, obj, data):
        """
        Fix links in the result from HS

        example:        
            when visiting <onion_url>.tor2web.org
            /something -> /something
            <onion_url>/something -> <onion_url>.tor2web.org/something
        """
        link = self.fix_link(obj, data.group(1))

        return data.group(0).replace(data.group(1), link)

    def add_banner(self, obj, data):
        """
        Inject tor2web banner inside the returned page
        """

        return str(data.group(1)) + str(self.banner)

    def process_links(self, obj, data):
        """
        Process all the possible HTML tag attributes that may contain links.
        """
        log.msg("processing url attributes")

        items = ['src', 'href', 'action']
        for item in items:
            data = re.sub(rexp[item], partial(self.fix_links, obj), data)

        log.msg("finished processing links...")

        return data

    def process_html(self, obj, data):
        """
        Process the result from the Hidden Services HTML
        """
        log.msg("processing HTML type content")

        data = self.process_links(obj, data)

        data = re.sub(rexp['body'], partial(self.add_banner, obj), data)

        return data
