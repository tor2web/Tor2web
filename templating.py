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

from config import config
from fileList import fileList

class Template(Element):
    def __init__(self, template):
        self.template = template
        template_content = FilePath("templates/"+self.template).getContent()
        self.loader = XMLString(template_content)

    def lookupRenderMethod(self, name):
        method = renderer.get(self, name, None)
        if method is None:
            def renderUsingDict(request, tag):
                if name in request.var:
                    return tag('%s' % name)
                return tag('undefined variable %s for template %s' % (name , self.template))
            return renderUsingDict
        return method

    def render(self, request):
        loader = self.loader
        if loader is None:
            raise MissingTemplateLoader(self)
        return loader.load()


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

