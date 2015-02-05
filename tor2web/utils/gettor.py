"""
    Tor2web
    Copyright (C) 2015 Hermes No Profit Association - GlobaLeaks Project

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
   :synopsis: GetTor routines

.. moduleauthor:: Israel Leiva <ilv@torproject.org>

"""

# -*- coding: utf-8 -*-

import os
import re

from twisted.protocols.basic import FileSender
from twisted.python.log import err
from twisted.internet import defer
from twisted.web.server import NOT_DONE_YET

from tor2web.utils.lists import List

REDIRECT_URLS = {
    'iphone': 'https://itunes.apple.com/us/app/onion-browser/id519296448',
    'android': 'https://play.google.com/store/apps/details?id=org.torproject.android',
    'torbrowser': 'https://www.torproject.org/projects/torbrowser.html.en#downloads'
}


def getRedirectURL(client):
    """Get the redirect URL for a given OS.

    Requests from iPhone, Android and Tor Browser itself should be
    redirected.

    :param: client (string) the user's operating system.

    :return: (string) the intended URL for redirection.

    """
    return REDIRECT_URLS[client]


def sendFile(request, filename, filepath, ctype):
    """Send file to user.

    Send file to user using producers and consumers system.

    :param: filename (string)
    :param: filepath (string)
    :param: ctype (string) the value for content-type HTTP header

    """
    request.setHeader(b'content-type', ctype)
    request.setHeader(
        b'content-disposition', 'attachment; filename=%s' %
        filename
    )

    fp = open(filepath, 'rb')
    d = FileSender().beginFileTransfer(fp, request)

    def cbFinished(ignored):
        fp.close()
        request.finish()
    d.addErrback(err).addCallback(cbFinished)


def getOSandLC(headers, t2w_lists_path):
    """Get OS and LC of user.

    The user-agent and accept-language headers of the client's browser
    are used to guess the operating system and locale.

    :return: tuple of strings with the OS and LC.

    """
    agent = str(headers.getRawHeaders(b'user-agent'))
    alang = str(headers.getRawHeaders(b'accept-language'))

    # regex to detect if the user is already using Tor Browser
    # taken from https://gitweb.torproject.org/check.git/tree/utils.go#n57
    tb_ua = 'Mozilla/5\.0 \(Windows NT 6\.1; rv:[\d]+\.0\) Gecko/20100101 Firefox/[\d]+\.0'

    # list of supported locales for Tor Browser
    locales = List('%s/gettor_locales.txt' % t2w_lists_path)
    client, lang = None, 'en'

    if re.match('Windows', agent):
        client = 'windows'

    elif re.match('Mac OS X', agent):
        client = 'osx'

    elif re.match('iPhone', agent):
        client = 'ihpone'

    elif re.match('Android', agent):
        client = 'android'

    elif re.match(tb_ua, agent):
        client = 'torbrowser'

    # find out if the user language is supported by Tor Browser
    # if not, we use English by default
    for lc in locales:
        if re.match("^\['%s[,;].*" % lc, alang):
            lang = lc
            break

    return client, lang


def processGetTorRequest(request, client, lang, type, t2w_tb_path):
    """Process a GetTor request.

    Determine the file needed and send it to the user. Only requests for
    windows and osx should call this.

    :param: request (object)
    :param: client (string) the user's operating system.
    :param: lang (string) the user's locale.
    :param: type (string) the type of request (file or signature).

    """
    # extension for signatures is standard
    ext = None
    if type == 'signature':
        ext = 'asc'

    # windows and osx files have different names and extensions
    # (although a standard format for the flename could be used)
    if client == 'windows':
        if not ext:
            ext = 'exe'

        tb_file = 'torbrowser-install-latest-%s.%s' % (lang, ext)

    elif client == 'osx':
        if not ext:
            ext = 'dmg'

        tb_file = 'TorBrowser-osx-latest-%s.%s' % (lang, ext)

    # this folder should have the latest Tor Browser files
    tb_file_path = os.path.join(t2w_tb_path, tb_file)

    # send the file according to the request received
    if type == 'file':
        sendFile(request, tb_file, tb_file_path, 'application/octet-stream')

    elif type == 'signature':
        sendFile(request, tb_file, tb_file_path, 'text/plain')

    defer.returnValue(NOT_DONE_YET)
