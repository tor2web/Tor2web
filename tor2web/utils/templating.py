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

from twisted.web.template import Element, renderer, tags
from twisted.web.error import MissingTemplateLoader

class PageTemplate(Element):
    def lookupRenderMethod(self, name):
        method = renderer.get(self, name, None)
        if method is None:
            def renderUsingDict(request, tag):
                if name.startswith("t2wvar-"):
                    prefix, var = name.split("-")
                    if var in request.var:
                        return tag('%s' % request.var[var])
                return tag('undefined-var')
            return renderUsingDict
        return method

    def render(self, request):
        loader = self.loader
        if loader is None:
            raise MissingTemplateLoader(self)
        return loader.load()

    @renderer
    def resource(self, request, tag):
        url = "https://%s.%s%s" % (request.var['onion'], request.var['basehost'], request.var['path'])
        js = 'javascript:accept_disclaimer()'
        return tags.a(href=js, title=url)(url)

    @renderer
    def mirror(self, request, tag):
        if 'mirror' in request.var and request.var['mirror'] != '':
            url = "https://%s.%s%s" % (request.var['onion'], request.var['mirror'], request.var['path'])
            return ["This page is accessible also on the following random mirror: "], tags.a(href=url, title=url)(request.var['mirror'])
        return ""
