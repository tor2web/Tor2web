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

from twisted.web.template import Element, XMLString, renderer, tags
from twisted.python.filepath import FilePath

messages = {
    200 : "OK",
    400 : "Bad Request",
    403 : "Forbidden",
    404 : "Not Found",
    406 : "Not Acceptable",
    410 : "Gone"
}

class Template(Element):
    def __init__(self, template):
        self.template = template
        self.loader = XMLString(FilePath("templates/"+self.template).getContent())

class PageTemplate(Template):
    @renderer
    def header(self, request, tag):
        yield Template("header.xml")

class ErrorTemplate(PageTemplate):
    def __init__(self, error, errormsg=None):
        self.error = error
        self.errormsg = errormsg
        PageTemplate.__init__(self, "error.xml")

    @renderer
    def content(self, request, tag):
        if self.errormsg is not None:
            self.errormsg = messages.get(self.error, 'ERROR')
        return tag(tags.h1('%s %s' % (self.error, self.errormsg)))

