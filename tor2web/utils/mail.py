"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: Mail Routines

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

import re
import traceback
from StringIO import StringIO

from OpenSSL import SSL
from twisted.internet import reactor, defer
from twisted.mail.smtp import ESMTPSenderFactory
from twisted.internet.ssl import ClientContextFactory

from tor2web import __version__


def sendmail(config, messageFile):
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

    # evilaliv3:
    #   in order to understand and before change this settings please
    #   read the comment inside tor2web.utils.ssl
    contextFactory.method = SSL.SSLv23_METHOD

    resultDeferred = defer.Deferred()

    senderFactory = ESMTPSenderFactory(
        config.smtpuser.encode('utf-8'),
        config.smtppass.encode('utf-8'),
        config.smtpmail,
        config.smtpmailto_exceptions,
        messageFile,
        resultDeferred,
        contextFactory=contextFactory,
        requireAuthentication=True,
        requireTransportSecurity=(config.smtpsecurity != 'SSL'),
        retries=0,
        timeout=15)

    if config.security == "SSL":
        senderFactory = tls.TLSMemoryBIOFactory(contextFactory, True, senderFactory)

    reactor.connectTCP(config.smtpdomain, config.smtpport, senderFactory)

    return resultDeferred


def sendexceptionmail(config, etype, value, tb):
    """
    Formats traceback and exception data and emails the error

    @param etype: Exception class type
    @param value: Exception string value
    @param tb: Traceback string data
    """
    exc_type = re.sub("(<(type|class ')|'exceptions.|'>|__main__.)", "", str(etype))

    tmp = ["From: Tor2web Node %s.%s <%s>\n" % (config.nodename, config.basehost, config.smtpmail),
           "To: %s\n" % config.smtpmailto_exceptions,
           "Subject: Tor2web Node Exception (IPV4: %s, IPv6: %s)\n" % (config.listen_ipv4, config.listen_ipv6),
           "Content-Type: text/plain; charset=ISO-8859-1\n", "Content-Transfer-Encoding: 8bit\n\n",
           "Exception from Node %s (IPV4: %s, IPv6: %s)\n" % (config.nodename, config.listen_ipv4, config.listen_ipv6),
           "Tor2web version: %s\n" % __version__]

    error_message = "%s %s" % (exc_type.strip(), etype.__doc__)
    tmp.append(error_message)

    traceinfo = '\n'.join(traceback.format_exception(etype, value, tb))
    tmp.append(traceinfo)

    info_string = ''.join(tmp)
    message = StringIO(info_string)

    sendmail(config, message)

def MailExcetionHooker(config):
    def MailExceptionSender(etype, value, tb):
         sendexceptionmail(config, etype, value, tb)
    return MailExceptionSender

