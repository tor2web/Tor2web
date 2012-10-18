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

class Template(Element):
    def __init__(self, template):
        self.template = template
        self.loader = XMLString(FilePath("templates/"+self.template).getContent())

class PageTemplate(Template):
    @renderer
    def header(self, request, tag):
        yield PageTemplate("header.xml")

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

