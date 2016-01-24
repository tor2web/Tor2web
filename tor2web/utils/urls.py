"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: URL Routines

.. moduleauthor:: Anuj Gupta <dev@anuj.me>

"""

# -*- coding: utf-8 -*-

import urlparse
import urllib


def sort_querystring(query_string):
    """Sort a query string using field names and urlencode it"""
    # Split the query string into parts
    qs_parts = urlparse.parse_qsl(query_string)
    # Sort the parts (by field) and remove duplicates
    qs_parts = sorted(set(qs_parts))
    # Return sorted query string
    return urllib.urlencode(qs_parts)


def normalize_url(url):
    """Produce a normalized, blockable url"""
    # Split the URL into parts
    url_parts = urlparse.urlsplit(url)
    # We don't need 'scheme' or 'fragment'
    base,path,qs = url_parts[1:4]
    # Sort the query string
    qs_norm = sort_querystring(qs)
    if qs_norm:
        qs_norm = '?' + qs_norm
    # Generate the normalized url
    url_norm = ''.join([base,path,qs_norm])
    return url_norm


def parent_urls(url, limit=0):
    """Generate parent urls above 'limit' level (0 = base)"""
    # Clean up the url
    url = normalize_url(url.rstrip('/'))
    # Yield parent urls from second-last level down to 'limit'
    for i in range(1, url.count('/')+1-limit):
        yield url.rsplit('/', i)[0] + '/'
