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

from config import config
from fileList import fileList

from twisted.web.template import Element, XMLString, renderer, tags
from twisted.python.filepath import FilePath

import random

domains = fileList('lists/domains.txt')

try:
    domains.remove(config.basehost)
except:
    pass


class Template(Element):
    def __init__(self, template):
        self.template = template
        self.loader = XMLString(FilePath("templates/"+self.template).getContent())
        self.rdn = random.sample(domains, 1)[0]
        self.rdu = self.rdn

    def set_obj(self, obj):
        self.obj = obj 

    @renderer
    def hostname(self, request, tag):
        return tag('%s' % config.basehost)

    @renderer
    def random_domain_name(self, request, tag):
        return tag('%s' % self.rdn)

    @renderer
    def random_domain(self, request, tag):
        tag.fillSlots(random_domain_url="https://"+self.rdu+self.obj.uri)
        return tag

class PageTemplate(Template):
    @renderer
    def header(self, request, tag):
        header = PageTemplate("header.xml")
        header.set_obj(self.obj)
        return header

class ErrorTemplate(PageTemplate):
    def __init__(self, error, errortemplate=None):
        self.error = error
        try:
            PageTemplate.__init__(self, errortemplate)
        except IOError:
            PageTemplate.__init__(self, "error_generic.xml")

    @renderer
    def errorcode(self, request, tag):
        return tag('%s' % self.error)

