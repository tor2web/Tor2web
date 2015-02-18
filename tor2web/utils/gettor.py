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
from twisted.python.filepath import FilePath
from twisted.python.log import err
from twisted.internet import defer
from twisted.web.server import NOT_DONE_YET

from tor2web.utils.lists import List

REDIRECT_URLS = {
    'iphone': 'https://itunes.apple.com/us/app/onion-browser/id519296448',
    'android': 'https://play.google.com/store/apps/details?id=org.torproject.android'
}


def getRedirectURL(client):
    """Get the redirect URL for a given OS.

    Requests from iPhone, Android and Tor Browser itself should be
    redirected.

    :param: client (string) the user's operating system.

    :return: (string) the intended URL for redirection.

    """
    return REDIRECT_URLS[client]


def sendFile(request, filename, tb_path, ctype):
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

    fp = FilePath(tb_path).child(filename).open()

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

    # find out if the user language is supported by Tor Browser
    # if not, we use English by default
    for lc in locales:
        if re.match("^\['%s[,;].*" % lc, alang):
            lang = lc
            break

    return client, lang


def processGetTorRequest(request, client, lang, type, version, t2w_tb_path):
    """Process a GetTor request.

    Determine the file needed and send it to the user. Only requests for
    windows and osx should call this.

    :param: request (object)
    :param: client (string) the user's operating system.
    :param: lang (string) the user's locale.
    :param: type (string) the type of request (file or signature).
    :param: version (string) the latest version of Tor Browser to be served.
    :param: t2w_tb_path (string): path to the latest Tor Browser files.

    """
    # windows and osx files have different names and extensions
    if client == 'windows':

        if type == 'signature':
            ext = 'exe.asc'
        else:
            ext = 'exe'

        tb_file = 'torbrowser-install-%s_%s.%s' % (version, lang, ext)

    elif client == 'osx':

        if type == 'signature':
            ext = 'dmg.asc'
        else:
            ext = 'dmg'

        tb_file = 'TorBrowser-%s-osx32_%s.%s' % (version, lang, ext)

    # send the file according to the request received
    if type == 'file':
        sendFile(request, tb_file, t2w_tb_path, 'application/octet-stream')

    elif type == 'signature':
        sendFile(request, tb_file, t2w_tb_path, 'text/plain')

    defer.returnValue(NOT_DONE_YET)
