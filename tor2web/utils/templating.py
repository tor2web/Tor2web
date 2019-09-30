"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: HTML templating routines

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

from twisted.web.error import MissingTemplateLoader
from twisted.web.template import Element, renderer, tags


class PageTemplate(Element):
    def lookupRenderMethod(self, name):
        method = renderer.get(self, name, None)
        if method is None:
            def renderUsingDict(request, tag):
                if name.startswith("t2wvar-"):
                    _, var = name.split("-")
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
            return ["This page is accessible also on the following random mirror: "], tags.a(href=url, title=url)(
                request.var['mirror'])
        return ""
