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

import re
import traceback

from OpenSSL import SSL
from StringIO import StringIO

from utils.config import config

from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.mail.smtp import ESMTPSenderFactory
from twisted.internet.ssl import ClientContextFactory

def sendmail(authenticationUsername, authenticationSecret, fromAddress, toAddress, messageFile, smtpHost, smtpPort=25):
    """
    Sends an email using SSLv3 over SMTP

    @param authenticationUsername: account username
    @param authenticationSecret: account password
    @param fromAddress: the from address field of the email
    @param toAddress: the to address field of the email
    @param messageFile: the message content
    @param smtpHost: the smtp host
    @param smtpPort: the smtp port
    """
    contextFactory = ClientContextFactory()
    contextFactory.method = SSL.SSLv3_METHOD

    resultDeferred = Deferred()

    senderFactory = ESMTPSenderFactory(
        authenticationUsername,
        authenticationSecret,
        fromAddress,
        toAddress,
        messageFile,
        resultDeferred,
        contextFactory=contextFactory)

    reactor.connectTCP(smtpHost, smtpPort, senderFactory)

    return resultDeferred



def MailException(etype, value, tb):
    """
    Formats traceback and exception data and emails the error

    @param etype: Exception class type
    @param value: Exception string value
    @param tb: Traceback string data
    """
    excType = re.sub("(<(type|class ')|'exceptions.|'>|__main__.)", "", str(etype)).strip()
    message = ""
    message += "From: Tor2web Node %s.%s <%s>\n" % (config.nodename, config.basehost, config.smtpmail)
    message += "To: %s\n" % (config.smtpmailto_exceptions)
    message += "Subject: Tor2web Node Exception (IPV4: %s, IPv6: %s)\n" % (config.listen_ipv4, config.listen_ipv6)
    message += "Content-Type: text/plain; charset=ISO-8859-1\n"
    message += "Content-Transfer-Encoding: 8bit\n\n"
    message += "%s %s" % (excType, etype.__doc__)
    for line in traceback.extract_tb(tb):
        message += "\tFile: \"%s\"\n\t\t%s %s: %s\n" %(line[0], line[2], line[1], line[3])
    while 1:
        if not tb.tb_next: break
        tb = tb.tb_next
    stack = []
    f = tb.tb_frame
    while f:
        stack.append(f)
        f = f.f_back
    stack.reverse()
    message += "\nLocals by frame, innermost last:"
    for frame in stack:
        message += "\nFrame %s in %s at line %s" % (frame.f_code.co_name, frame.f_code.co_filename, frame.f_lineno)
        for key, val in frame.f_locals.items():
            message += "\n\t%20s = " % key
            try:
                message += str(val)
            except:
                message += "<ERROR WHILE PRINTING VALUE>"

    message = StringIO(message)
    sendmail(config.smtpuser, config.smtppass, config.smtpmail, config.smtpmailto_exceptions, message, config.smtpdomain, config.smtpport)
