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

from twisted.internet import reactor, defer
from twisted.mail.smtp import ESMTPSenderFactory
from twisted.internet.ssl import ClientContextFactory

from tor2web.utils.config import VERSION, config

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

    resultDeferred = defer.Deferred()

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

    exc_type = re.sub("(<(type|class ')|'exceptions.|'>|__main__.)", "", str(etype))

    tmp = []
    tmp.append("From: Tor2web Node %s.%s <%s>\n" % (config.nodename, config.basehost, config.smtpmail))
    tmp.append("To: %s\n" % (config.smtpmailto_exceptions))
    tmp.append("Subject: Tor2web Node Exception (IPV4: %s, IPv6: %s)\n" % (config.listen_ipv4, config.listen_ipv6))
    tmp.append("Content-Type: text/plain; charset=ISO-8859-1\n")
    tmp.append("Content-Transfer-Encoding: 8bit\n\n")
    tmp.append("Exception from Node %s (IPV4: %s, IPv6: %s)\n" % (config.nodename, config.listen_ipv4, config.listen_ipv6))
    tmp.append("Tor2web version: %s\n" % (VERSION))

    error_message = "%s %s" % (exc_type.strip(), etype.__doc__)
    tmp.append(error_message)

    traceinfo = '\n'.join(traceback.format_exception(etype, value, tb))
    tmp.append(traceinfo)

    info_string = ''.join(tmp)
    message = StringIO(info_string)

    sendmail(config.smtpuser, config.smtppass, config.smtpmail, config.smtpmailto_exceptions, message, config.smtpdomain, config.smtpport)
