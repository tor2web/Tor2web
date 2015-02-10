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
   :synopsis: Main Tor2web Server Implementation

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

import sys
import mimetypes
import random
import signal
import socket
import zlib
import hashlib
from StringIO import StringIO
from random import choice
from functools import partial
from urlparse import urlparse
from cgi import parse_header

import os
import re
from zope.interface import implements
from twisted.spread import pb
from twisted.internet import reactor, protocol, defer
from twisted.internet.abstract import isIPAddress, isIPv6Address
from twisted.internet.endpoints import TCP4ClientEndpoint, SSL4ClientEndpoint
from twisted.protocols.policies import WrappingFactory
from twisted.web import http, client, _newclient
from twisted.web.error import SchemeNotSupported
from twisted.web.http import datetimeToString, StringTransport, _IdentityTransferDecoder, _ChunkedTransferDecoder, \
    parse_qs
from twisted.web.http_headers import Headers
from twisted.web.server import NOT_DONE_YET
from twisted.web.template import flattenString, XMLString
from twisted.web.iweb import IBodyProducer
from twisted.python import log, logfile
from twisted.python.compat import networkString, intToBytes
from twisted.python.filepath import FilePath
from twisted.internet.task import LoopingCall
from tor2web import __version__
from tor2web.utils.config import Config
from tor2web.utils.daemon import T2WDaemon, set_pdeathsig, set_proctitle
from tor2web.utils.hostsmap import HostsMap
from tor2web.utils.lists import LimitedSizeDict, List, TorExitNodeList
from tor2web.utils.mail import sendmail, sendexceptionmail
from tor2web.utils.misc import listenTCPonExistingFD, listenSSLonExistingFD, re_sub, verify_onion
from tor2web.utils.socks import SOCKSError, SOCKS5ClientEndpoint, TLSWrapClientEndpoint
from tor2web.utils.ssl import T2WSSLContextFactory, HTTPSVerifyingContextFactory
from tor2web.utils.stats import T2WStats
from tor2web.utils.storage import Storage
from tor2web.utils.templating import PageTemplate

SOCKS_errors = {
    0x00: "error_sock_generic.tpl",
    0x23: "error_sock_hs_not_found.tpl",
    0x24: "error_sock_hs_not_reachable.tpl"
}


class T2WRPCServer(pb.Root):
    def __init__(self, config):
        self.config = config
        self.stats = T2WStats()
        self.white_list = []
        self.black_list = []
        self.TorExitNodes = []
        self.blocked_ua = []
        self.hosts_map = {}
        self.certs_tofu = LimitedSizeDict(size_limit=config.ssl_tofu_cache_size)

        self.load_lists()

    def load_lists(self):
        if config.mode == "WHITELIST":
            self.white_list = List(config.t2w_file_path('lists/whitelist.txt'))

        elif config.mode == "BLACKLIST":
            self.black_list = List(config.t2w_file_path('lists/blocklist_hashed.txt'),
                                   config.automatic_blocklist_updates_source,
                                   config.automatic_blocklist_updates_mode,
                                   config.automatic_blocklist_updates_refresh)

            # clear local cleartext list
            # (load -> hash -> clear feature; for security reasons)
            self.blocklist_cleartext = List(config.t2w_file_path('lists/blocklist_cleartext.txt'))
            for i in self.blocklist_cleartext:
                self.black_list.add(hashlib.md5(i).hexdigest())

            self.black_list.dump()

            self.blocklist_cleartext.clear()
            self.blocklist_cleartext.dump()

        self.blocked_ua = []
        if config.blockcrawl:
            tmp = List(config.t2w_file_path('lists/blocked_ua.txt'))
            for ua in tmp:
                self.blocked_ua.append(ua.lower())

        # Load Exit Nodes list with the refresh rate configured  in config file
        self.TorExitNodes = TorExitNodeList(config.t2w_file_path('lists/exitnodelist.txt'),
                                            'https://onionoo.torproject.org/summary?type=relay',
                                            'REPLACE',
                                            config.exit_node_list_refresh)

        self.hosts_map = HostsMap(config.t2w_file_path('lists/hosts_map.txt')).hosts
        if config.mode == "TRANSLATION":
            self.hosts_map[config.basehost] = config.onion

    def remote_get_config(self):
        return self.config.__dict__

    def remote_get_blocked_ua_list(self):
        return list(self.blocked_ua)

    def remote_get_white_list(self):
        return list(self.white_list)

    def remote_get_black_list(self):
        return list(self.black_list)

    def remote_get_tor_exits_list(self):
        return list(self.TorExitNodes)

    def remote_get_hosts_map(self):
        return dict(self.hosts_map)

    def remote_is_https(self, hostname):
        return hostname in self.certs_tofu

    def remote_verify_tls_tofu(self, hostname, cert):
        h = hashlib.sha512(cert).hexdigest()
        if hostname not in self.certs_tofu:
            self.certs_tofu[hostname] = h
            return True

        return self.certs_tofu[hostname] == h

    def remote_update_stats(self, onion):
        self.stats.update(onion)

    def remote_get_yesterday_stats(self):
        return self.stats.yesterday_stats

    def remote_log_access(self, line):
        t2w_daemon.logfile_access.write(line)

    def remote_log_debug(self, line):
        date = datetimeToString()
        t2w_daemon.logfile_debug.write(date + " " + str(line) + "\n")


@defer.inlineCallbacks
def rpc(f, *args, **kwargs):
    d = rpc_factory.getRootObject()
    d.addCallback(lambda obj: obj.callRemote(f, *args, **kwargs))
    ret = yield d
    defer.returnValue(ret)


def rpc_log(msg):
    rpc("log_debug", str(msg))


class T2WPP(protocol.ProcessProtocol):
    def __init__(self, father, childFDs, fds_https, fds_http):
        self.father = father
        self.childFDs = childFDs
        self.fds_https = fds_https
        self.fds_http = fds_http

    def connectionMade(self):
        self.pid = self.transport.pid

    def processExited(self, reason):
        for i, subprocess in enumerate(self.father.subprocesses):
            if subprocess == self.pid:
                del self.father.subprocesses[i]
                break

        if not self.father.quitting:
            subprocess = spawnT2W(self.father, self.childFDs, self.fds_https, self.fds_http)
            self.father.subprocesses.append(subprocess.pid)

        if len(self.father.subprocesses) == 0:
            try:
                reactor.stop()
            except Exception:
                pass


def spawnT2W(father, childFDs, fds_https, fds_http):
    child_env = os.environ.copy()
    child_env['T2W_FDS_HTTPS'] = fds_https
    child_env['T2W_FDS_HTTP'] = fds_http

    return reactor.spawnProcess(T2WPP(father, childFDs, fds_https, fds_http),
                                sys.executable,
                                [sys.executable, __file__] + sys.argv[1:],
                                env=child_env,
                                childFDs=childFDs)


class Tor2webObj():
    def __init__(self):
        # The destination hidden service identifier
        self.onion = None

        # The path portion of the URI
        self.path = None

        # The full address (hostname + uri) that must be requested
        self.address = None

        # The headers to be sent
        self.headers = None

        # The requested uri
        self.uri = None

        # A boolean that keeps track of client gzip support
        self.client_supports_gzip = False

        # A boolean that keeps track of server gzip support
        self.server_response_is_gzip = False

        # A boolean that keeps track of document content type
        self.html = False


class BodyReceiver(protocol.Protocol):
    def __init__(self, finished):
        self._finished = finished
        self._data = []

    def dataReceived(self, chunk):
        self._data.append(chunk)

    def write(self, chunk):
        self._data.append(chunk)

    def connectionLost(self, reason):
        self._finished.callback(''.join(self._data))


class BodyStreamer(protocol.Protocol):
    def __init__(self, streamfunction, finished):
        self._finished = finished
        self._streamfunction = streamfunction

    def dataReceived(self, data):
        self._streamfunction(data)

    def connectionLost(self, reason):
        self._finished.callback('')


class BodyProducer(object):
    implements(IBodyProducer)

    def __init__(self):
        self.length = _newclient.UNKNOWN_LENGTH
        self.finished = defer.Deferred()
        self.consumer = None
        self.can_stream = False
        self.can_stream_d = defer.Deferred()

    def startProducing(self, consumer):
        self.consumer = consumer
        self.can_stream = True
        self.can_stream_d.callback(True)
        return self.finished

    @defer.inlineCallbacks
    def dataReceived(self, data):
        if not self.can_stream:
            yield self.can_stream_d
        self.consumer.write(data)

    def allDataReceived(self):
        self.finished.callback(None)

    def resumeProducing(self): pass
    def pauseProducing(self): pass
    def stopProducing(self): pass

class Agent(client.Agent):
    def __init__(self, reactor,
                 contextFactory=client.WebClientContextFactory(),
                 connectTimeout=None, bindAddress=None,
                 pool=None, sockhost=None, sockport=None):
        self._sockhost = sockhost
        self._sockport = sockport
        client.Agent.__init__(self, reactor, contextFactory,
                               connectTimeout, bindAddress, pool)

    def _getEndpoint(self, scheme, host, port):
        def verify_tofu(hostname, cert):
            return rpc("verify_tls_tofu", hostname, cert)

        kwargs = {}
        if self._connectTimeout is not None:
            kwargs['timeout'] = self._connectTimeout
        kwargs['bindAddress'] = self._bindAddress

        if scheme == 'http':
            return SOCKS5ClientEndpoint(self._reactor, self._sockhost, self._sockport,
                                        host, port, config.socksoptimisticdata, **kwargs)
        elif scheme == 'https':
            torSockEndpoint = SOCKS5ClientEndpoint(self._reactor, self._sockhost,
                                                   self._sockport, host, port, config.socksoptimisticdata, **kwargs)
            return TLSWrapClientEndpoint(HTTPSVerifyingContextFactory(host, verify_tofu), torSockEndpoint)
        elif scheme == 'normal-http':
             return TCP4ClientEndpoint(self._reactor, host, port, **kwargs)
        elif scheme == 'normal-https':
            return SSL4ClientEndpoint(self._reactor, host, port,
                                      self._wrapContextFactory(host, port),
                                      **kwargs)
        else:
            raise SchemeNotSupported("Unsupported scheme: %r" % (scheme,))

    @defer.inlineCallbacks
    def request(self, method, uri, headers, bodyProducer=None):
        """
        Edited version of twisted Agent.request in order to make it asyncronous!
        """
        parsedURI = client._URI.fromBytes(uri)

        is_https = yield rpc("is_https", parsedURI.host)

        scheme = 'https' if is_https else 'http'

        for key, values in headers.getAllRawHeaders():
            fixed_values = [re_sub(rexp['w2t'], r'' + scheme + r'://\2.onion', value) for value in values]
            headers.setRawHeaders(key, fixed_values)

        try:
            endpoint = self._getEndpoint(parsedURI.scheme, parsedURI.host,
                                         parsedURI.port)
        except SchemeNotSupported:
            defer.returnValue(Failure())

        key = (parsedURI.scheme, parsedURI.host, parsedURI.port)
        ret = yield self._requestWithEndpoint(key, endpoint, method, parsedURI,
                                              headers, bodyProducer,
                                              parsedURI.originForm)
        defer.returnValue(ret)

class RedirectAgent(client.RedirectAgent):
    """
    Overridden client.RedirectAgent version where we evaluate and handle automatically only HTTPS redirects
    """

    def _handleResponse(self, response, method, uri, headers, redirectCount):
        locationHeaders = response.headers.getRawHeaders('location', [])
        if locationHeaders:
            location = self._resolveLocation(uri, locationHeaders[0])
            parsed = client._URI.fromBytes(location)
            if parsed.scheme == 'https':
                return client.RedirectAgent._handleResponse(self, response, method, uri, header, redirectCount)

        return response

class T2WRequest(http.Request):
    """
    Used by Tor2webProxy to implement a simple web proxy.
    """

    def __init__(self, channel, queued, reactor=reactor):
        """
        Method overridden to change some part of proxy.Request and of the base http.Request
        """
        self.reactor = reactor
        self.notifications = []
        self.channel = channel
        self.queued = queued
        self.requestHeaders = Headers()
        self.received_cookies = {}
        self.responseHeaders = Headers()
        self.cookies = []  # outgoing cookies
        self.bodyProducer = BodyProducer()
        self.proxy_d = None
        self.proxy_response = None

        self.stream = ''

        self.header_injected = False
        # If we should disable the banner,
        # say that we have already injected it.
        if config.disable_banner:
            self.header_injected = True

        if queued:
            self.transport = StringTransport()
        else:
            self.transport = self.channel.transport

        self.obj = Tor2webObj()
        self.var = Storage()
        self.var['version'] = __version__
        self.var['basehost'] = config.basehost
        self.var['errorcode'] = None

        self.html = False

        self.decoderGzip = None
        self.encoderGzip = None

        self.pool = pool

        self.translation_rexp = {}

    def finish(self):
        try:
            http.Request.finish()
        except Exception:
            pass

    def getRequestHostname(self):
        """
            Function overload to fix ipv6 bug:
                http://twistedmatrix.com/trac/ticket/6014
        """
        host = self.getHeader(b'host')
        if not host:
            return networkString(self.getHost().host)
        if host[0] == '[':
            return host.split(']', 1)[0] + "]"

        # return everything before the ':'
        return networkString(host.split(':', 1)[0])


    def forwardData(self, data, end=False):
        if not self.startedWriting:
            if self.obj.client_supports_gzip:
                self.setHeader(b'content-encoding', b'gzip')

            if config.extra_http_response_headers:
                for header, value in config.extra_http_response_headers.iteritems():
                    self.setHeader(header, value)

            if data and end:
                self.setHeader(b'content-length', intToBytes(len(data)))

        if data:
            self.write(data)

    def getForwarders(self):
        forwarders = []

        try:
            port = self.channel.transport.getPeer().port

            xForwardedFor = self.requestHeaders.getRawHeaders("X-Forwarded-For")
            for forwardHeader in xForwardedFor or []:
                forwardList = forwardHeader.replace(" ", "").split(",")

                for ip in forwardList:
                    if isIPAddress(ip):
                        forwarders.append(address.IPv4Address("TCP",
                                                              ip.strip(),
                                                              port))
                    elif isIPv6Address(ip):
                        forwarders.append(address.IPv6Address("TCP",
                                                              ip.strip(),
                                                              port))
                    else:
                        raise Exception
        except:
            return []

        return forwarders

    def requestReceived(self, command, path, version):
        """
        Method overridden to reduce the function actions
        """
        self.method, self.uri = command, path
        self.clientproto = version

        # we get the ip address of the user that can be:
        #  - written in the x-forwared-for header if a proxy is in between
        #  - the ip address of the transport endpoint
        forwarders = self.getForwarders()
        if forwarders:
            self.client = forwarders[0]
        else:
            self.client = self.channel.transport.getPeer()

        self.host = self.channel.transport.getHost()

        self.process()

    def add_banner(self, banner, data):
        """
        Inject tor2web banner inside the returned page
        """
        return str(data.group(1)) + str(banner)

    @defer.inlineCallbacks
    def handleFixPart(self, data):
        if self.obj.server_response_is_gzip:
            data = self.unzip(data)

        data = self.stream + data

        if len(data) >= 1000:
            if config.mode == 'TRANSLATION':
                data = re_sub(self.translation_rexp['from'], self.translation_rexp['to'], data)

            proto = 'http://' if config.transport == 'HTTP' else 'https://'
            data = re_sub(rexp['html_t2w'], r'\1\2' + proto + r'\3.' + config.basehost + r'\4', data)

            forward = data[:-500]
            if not self.header_injected and forward.find("<body") != -1:
                banner = yield flattenString(self, templates['banner.tpl'])
                forward = re.sub(rexp['body'], partial(self.add_banner, banner), forward)
                self.header_injected = True

            self.forwardData(self.handleCleartextForwardPart(forward))

            self.stream = data[-500:]

        else:
            self.stream = data

    @defer.inlineCallbacks
    def handleFixEnd(self, data):
        if self.obj.server_response_is_gzip:
            data = self.unzip(data, True)

        data = self.stream + data

        if config.mode == 'TRANSLATION':
            data = re_sub(self.translation_rexp['from'], self.translation_rexp['to'], data)

        proto = 'http://' if config.transport == 'HTTP' else 'https://'
        data = re_sub(rexp['html_t2w'], r'\1\2' + proto + r'\3.' + config.basehost + r'\4', data)

        if not self.header_injected and data.find("<body") != -1:
            banner = yield flattenString(self, templates['banner.tpl'])
            data = re.sub(rexp['body'], partial(self.add_banner, banner), data)
            self.header_injected = True

        data = self.handleCleartextForwardPart(data, True)
        self.forwardData(data, True)

        self.stream = ''

        self.finish()

    def handleGzippedForwardPart(self, data, end=False):
        if not self.obj.client_supports_gzip:
            data = self.unzip(data, end)

        return data

    def handleCleartextForwardPart(self, data, end=False):
        if self.obj.client_supports_gzip:
            data = self.zip(data, end)

        return data

    def handleForwardPart(self, data):
        if self.obj.server_response_is_gzip:
            data = self.handleGzippedForwardPart(data)
        else:
            data = self.handleCleartextForwardPart(data)

        self.forwardData(data)

    def handleForwardEnd(self, data):
        if self.obj.server_response_is_gzip:
            data = self.handleGzippedForwardPart(data, True)
        else:
            data = self.handleCleartextForwardPart(data, True)

        self.forwardData(data, True)
        self.finish()

    def contentFinish(self, data):
        if self.obj.client_supports_gzip:
            self.setHeader(b'content-encoding', b'gzip')
            data = self.zip(data, True)

        self.setHeader(b'content-length', intToBytes(len(data)))
        self.setHeader(b'cache-control', b'no-cache')
        
        if config.blockcrawl:
            self.setHeader(b'X-Robots-Tag', b'noindex')

        if self.isSecure():
            self.setHeader(b'strict-transport-security', b'max-age=31536000')

        if config.extra_http_response_headers:
            for header, value in config.extra_http_response_headers.iteritems():
                self.setHeader(header, value)

        self.write(data)
        self.finish()

    def sendError(self, error=500, errortemplate='error_generic.tpl'):
        self.setResponseCode(error)
        self.setHeader(b'content-type', 'text/html')
        self.var['errorcode'] = error
        return flattenString(self, templates[errortemplate]).addCallback(self.contentFinish)

    def handleError(self, failure):
        if type(failure.value) is SOCKSError:
            self.setResponseCode(404)
            self.var['errorcode'] = failure.value.code
            if failure.value.code in SOCKS_errors:
                return flattenString(self, templates[SOCKS_errors[failure.value.code]]).addCallback(self.contentFinish)
            else:
                return flattenString(self, templates[SOCKS_errors[0x00]]).addCallback(self.contentFinish)
        else:
            self.sendError()

    def unzip(self, data, end=False):
        data1, data2 = '', ''

        try:
            if self.decoderGzip is None:
                self.decoderGzip = zlib.decompressobj(16 + zlib.MAX_WBITS)

            if data:
                data1 = self.decoderGzip.decompress(data)

            if end:
                data2 = self.decoderGzip.flush()

        except Exception:
            pass

        return data1 + data2

    def zip(self, data, end=False):
        data1, data2 = '', ''

        try:
            if self.encoderGzip is None:
                self.encoderGzip = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)

            if data:
                data1 = self.encoderGzip.compress(data)

            if end:
                data2 = self.encoderGzip.flush()

        except Exception:
            pass

        return data1 + data2

    def process_request(self, req):
        """
        This function:
            - "resolves" the address;
            - alters and sets the proper headers.
        """
        rpc_log(req)

        self.obj.host_tor = "http://" + self.obj.onion
        self.obj.host_tor2web = "https://" + self.obj.onion.replace(".onion", "") + "." + config.basehost
        self.obj.address = "http://" + self.obj.onion + self.obj.uri

        self.obj.headers = req.headers

        # we remove the x-forwarded-for header that may contain a leaked ip
        self.obj.headers.removeHeader(b'x-forwarded-for')

        self.obj.headers.setRawHeaders(b'host', [self.obj.onion])
        self.obj.headers.setRawHeaders(b'connection', [b'keep-alive'])
        self.obj.headers.setRawHeaders(b'accept-encoding', [b'gzip, chunked'])
        self.obj.headers.setRawHeaders(b'x-tor2web', [b'encrypted'])

        return True

    @defer.inlineCallbacks
    def process(self):
        request = Storage()
        request.headers = self.requestHeaders
        request.host = self.getRequestHostname()
        request.uri = self.uri

        content_length = self.getHeader(b'content-length')
        transfer_encoding = self.getHeader(b'transfer-encoding')

        staticpath = request.uri
        staticpath = re.sub('/$', '/index.html', staticpath)
        staticpath = re.sub('^(/antanistaticmap/)?', '', staticpath)
        staticpath = re.sub('^/', '', staticpath)

        resource_is_local = (config.mode != "TRANSLATION" and
                             (request.host == config.basehost or
                              request.host == 'www.' + config.basehost)) or \
                            isIPAddress(request.host) or \
                            isIPv6Address(request.host) or \
                            (config.overriderobotstxt and request.uri == '/robots.txt') or \
                            request.uri.startswith('/antanistaticmap/')

        if content_length is not None:
            self.bodyProducer.length = int(content_length)
            producer = self.bodyProducer
            request.headers.removeHeader(b'content-length')
        elif transfer_encoding is not None:
            producer = self.bodyProducer
            request.headers.removeHeader(b'transfer-encoding')
        else:
            producer = None

        if config.mirror is not None:
            if config.basehost in config.mirror:
                config.mirror.remove(config.basehost)
            if len(config.mirror) > 1:
                self.var['mirror'] = choice(config.mirror)
            elif len(config.mirror) == 1:
                self.var['mirror'] = config.mirror[0]

        # we serve contents only over https
        if not self.isSecure() and (config.transport != 'HTTP'):
            self.redirect("https://" + request.host + request.uri)
            self.finish()
            defer.returnValue(None)

        # 0: Request admission control stage
        # we try to deny some ua/crawlers regardless the request is (valid or not) / (local or not)
        # we deny EVERY request to known user agents reconized with pattern matching
        if config.blockcrawl and request.headers.getRawHeaders(b'user-agent') is not None:
            for ua in blocked_ua_list:
                if re.match(ua, request.headers.getRawHeaders(b'user-agent')[0].lower()):
                    self.sendError(403, "error_blocked_ua.tpl")
                    defer.returnValue(NOT_DONE_YET)

        # 1: Client capability assessment stage
        if request.headers.getRawHeaders(b'accept-encoding') is not None:
            if re.search('gzip', request.headers.getRawHeaders(b'accept-encoding')[0]):
                self.obj.client_supports_gzip = True

        # 2: Content delivery stage
        # we need to verify if the requested resource is local (/antanistaticmap/*) or remote
        # because some checks must be done only for remote requests;
        # in fact local content is always served (css, js, and png in fact are used in errors)
        if resource_is_local:
            # the requested resource is local, we deliver it directly
            try:
                if staticpath == "dev/null":
                    content = "A" * random.randint(20, 1024)
                    self.setHeader(b'content-type', 'text/plain')
                    defer.returnValue(self.contentFinish(content))

                elif staticpath == "stats/yesterday":
                    self.setHeader(b'content-type', 'application/json')
                    content = yield rpc("get_yesterday_stats")
                    defer.returnValue(self.contentFinish(content))

                elif config.publish_lists and staticpath == "lists/whitelist":
                    self.setHeader(b'content-type', 'text/plain')
                    content = yield rpc("get_white_list")
                    content = "\n".join(item for item in content)
                    defer.returnValue(self.contentFinish(content))

                elif config.publish_lists and staticpath == "lists/blacklist":
                    self.setHeader(b'content-type', 'text/plain')
                    content = yield rpc("get_black_list")
                    content = "\n".join(item for item in content)
                    defer.returnValue(self.contentFinish(content))

                elif staticpath == "notification" and config.smtpmailto_notifications != '':
                    # if config.smtp_mail is configured we accept notifications

                    # ################################################################
                    # Here we need to parse POST data in x-www-form-urlencoded format
                    # ################################################################
                    content_receiver = BodyReceiver(defer.Deferred())
                    self.bodyProducer.startProducing(content_receiver)
                    yield self.bodyProducer.finished
                    content = ''.join(content_receiver._data)

                    args = {}

                    ctype = self.requestHeaders.getRawHeaders(b'content-type')
                    if ctype is not None:
                        ctype = ctype[0]

                    if self.method == b"POST" and ctype:
                        key, pdict = parse_header(ctype)
                        if key == b'application/x-www-form-urlencoded':
                            args.update(parse_qs(content, 1))
                    # ################################################################

                    if 'by' in args and 'url' in args and 'comment' in args:
                        tmp = ["From: Tor2web Node %s.%s <%s>\n" % (config.nodename, config.basehost, config.smtpmail),
                               "To: %s\n" % config.smtpmailto_notifications,
                               "Subject: Tor2web Node (IPv4 %s, IPv6 %s): notification for %s\n" % (
                                   config.listen_ipv4, config.listen_ipv6, args['url'][0]),
                               "Content-Type: text/plain; charset=ISO-8859-1\n", "Content-Transfer-Encoding: 8bit\n\n",
                               "BY: %s\n" % (args['by'][0]), "URL: %s\n" % (args['url'][0]),
                               "COMMENT: %s\n" % (args['comment'][0])]
                        message = StringIO(''.join(tmp))

                        try:
                            sendmail(config.smtpuser,
                                     config.smtppass,
                                     config.smtpmail,
                                     config.smtpmailto_notifications,
                                     message,
                                     config.smtpdomain,
                                     config.smtpport)
                        except Exception:
                            pass

                    self.setHeader(b'content-type', 'text/plain')
                    defer.returnValue(self.contentFinish(''))

                else:
                    if type(antanistaticmap[staticpath]) == str:
                        filename, ext = os.path.splitext(staticpath)
                        self.setHeader(b'content-type', mimetypes.types_map[ext])
                        content = antanistaticmap[staticpath]
                        defer.returnValue(self.contentFinish(content))

                    elif type(antanistaticmap[staticpath]) == PageTemplate:
                        defer.returnValue(
                            flattenString(self, antanistaticmap[staticpath]).addCallback(self.contentFinish))

            except Exception:
                pass

            self.sendError(404)
            defer.returnValue(NOT_DONE_YET)

        else:  # the requested resource is remote, we act as proxy

            self.obj.uri = request.uri

            if config.mode == 'TRANSLATION' and request.host in hosts_map:
                self.obj.onion = hosts_map[request.host]
            else:
                self.obj.onion = request.host.split(".")[0] + ".onion"

            if not request.host or not verify_onion(self.obj.onion):
                self.sendError(406, 'error_invalid_hostname.tpl')
                defer.returnValue(NOT_DONE_YET)

            # we need to verify if the user is using tor;
            # on this condition it's better to redirect on the .onion
            if self.getClientIP() in tor_exits_list:
                self.setHeader(b'X-Check-Tor', b'true')
                if not config.disable_tor_redirection:
                    self.redirect("http://" + self.obj.onion + request.uri)
                    self.finish()
                    defer.returnValue(None)
            else:
                self.setHeader(b'X-Check-Tor', b'false')


            # Avoid image hotlinking
            if config.blockhotlinking and request.uri.lower().endswith(tuple(config.blockhotlinking_exts)):
                if request.headers.getRawHeaders(b'referer') is not None and \
                        not request.host in request.headers.getRawHeaders(b'referer')[0].lower():
                    self.sendError(403)
                    defer.returnValue(NOT_DONE_YET)

            self.translation_rexp['from'] = re.compile(r'(http.?:)?//' + self.obj.onion + '(?!:\d+)', re.I)
            self.translation_rexp['to'] = r'https://' + request.host

            self.process_request(request)

            parsed = urlparse(self.obj.address)

            self.var['address'] = self.obj.address
            self.var['onion'] = self.obj.onion.replace(".onion", "")
            self.var['path'] = parsed[2]
            if parsed[3] is not None and parsed[3] != '':
                self.var['path'] += '?' + parsed[3]

            if not config.disable_disclaimer and not self.getCookie("disclaimer_accepted"):
                self.setResponseCode(401)
                self.setHeader(b'content-type', 'text/html')
                self.var['url'] = self.obj.uri
                flattenString(self, templates['disclaimer.tpl']).addCallback(self.contentFinish)
                defer.returnValue(NOT_DONE_YET)

            if config.mode != "TRANSLATION":
                rpc_log("detected <onion_url>.tor2web Hostname: %s" % self.obj.onion)
                if not verify_onion(self.obj.onion):
                    self.sendError(406, 'error_invalid_hostname.tpl')
                    defer.returnValue(NOT_DONE_YET)

                if config.mode == "WHITELIST":
                    if not self.obj.onion in white_list:
                        self.sendError(403, 'error_hs_completely_blocked.tpl')
                        defer.returnValue(NOT_DONE_YET)

                elif config.mode == "BLACKLIST":
                    if hashlib.md5(self.obj.onion).hexdigest() in black_list:
                        self.sendError(403, 'error_hs_completely_blocked.tpl')
                        defer.returnValue(NOT_DONE_YET)

            agent = Agent(reactor, sockhost=config.sockshost, sockport=config.socksport, pool=self.pool)
            ragent = RedirectAgent(agent, 1)

            if config.dummyproxy is None:
                proxy_url = self.obj.address
            else:
                proxy_url = 'normal-' + config.dummyproxy + parsed[2] + '?' + parsed[3]

            self.proxy_d = ragent.request(self.method,
                                          proxy_url,
                                          self.obj.headers, bodyProducer=producer)

            self.proxy_d.addCallback(self.cbResponse)
            self.proxy_d.addErrback(self.handleError)

            defer.returnValue(NOT_DONE_YET)

    def cbResponse(self, response):
        self.proxy_response = response
        if 600 <= int(response.code) <= 699:
            self.setResponseCode(500)
            self.var['errorcode'] = int(response.code) - 600
            if self.var['errorcode'] in SOCKS_errors:
                return flattenString(self, templates[SOCKS_errors[self.var['errorcode']]]).addCallback(
                    self.contentFinish)
            else:
                return flattenString(self, templates[SOCKS_errors[0x00]]).addCallback(self.contentFinish)

        self.setResponseCode(response.code)
        self.processResponseHeaders(response.headers)

        # if there's no response, we're done.
        if not response.length:
            self.contentFinish('')
            return defer.succeed

        finished = defer.Deferred()
        if self.obj.html:
            response.deliverBody(BodyStreamer(self.handleFixPart, finished))
            finished.addCallback(self.handleFixEnd)
        else:
            response.deliverBody(BodyStreamer(self.handleForwardPart, finished))
            finished.addCallback(self.handleForwardEnd)

        return finished


    def handleHeader(self, key, values):
        keyLower = key.lower()

        # some headers does not allow multiple occurrences
        # in case of multiple occurrences we evaluate only the first
        valueLower = values[0].lower()

        if keyLower == 'transfer-encoding' and valueLower == 'chunked':
            return

        elif keyLower == 'content-encoding' and valueLower == 'gzip':
            self.obj.server_response_is_gzip = True
            return

        elif keyLower == 'content-type' and re.search('text/html', valueLower):
            self.obj.html = True

        elif keyLower == 'content-length':
            self.receivedContentLen = valueLower
            return

        elif keyLower == 'cache-control':
            return

        if keyLower == 'set-cookie':
            values = [re_sub(rexp['set-cookie_t2w'],
                             r'domain=\1\2.' + config.basehost + r'\3', x) for x in values]

        if keyLower in 'location':

            if config.mode == 'TRANSLATION':
                values = [re_sub(self.translation_rexp['from'], self.translation_rexp['to'], x) for x in values]
            
            proto = 'http://' if config.transport == 'HTTP' else 'https://'
            values = [re_sub(rexp['t2w'], proto + r'\2.' + config.basehost, x) for x in values]

        self.responseHeaders.setRawHeaders(key, values)

    def processResponseHeaders(self, headers):
        # currently we track only responding hidden services
        # we don't need to block on the rpc now so no yield is needed
        rpc("update_stats", str(self.obj.onion.replace(".onion", "")))

        for key, values in headers.getAllRawHeaders():
            self.handleHeader(key, values)

    def connectionLost(self, reason):
        try:
            if self.proxy_d:
                self.proxy_d.cancel()
        except Exception:
            pass

        try:
            if self.proxy_response:
                self.proxy_response._transport.stopProducing()
        except Exception:
            pass

        try:
            http.Request.connectionLost(self, reason)
        except Exception:
            pass

    def finish(self):
        try:
            http.Request.finish(self)
        except Exception:
            pass


class T2WProxy(http.HTTPChannel):
    requestFactory = T2WRequest

    def headerReceived(self, line):
        """
        Overridden to reduce the function actions and
        in particular to avoid self._transferDecoder actions and
        implement a streaming proxy
        """
        header, data = line.split(b':', 1)
        header = header.lower()
        data = data.strip()
        req = self.requests[-1]
        if header == b'content-length':
            try:
                self.length = int(data)
            except ValueError:
                self.transport.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                self.length = None
                self.transport.loseConnection()
                return
            self._transferDecoder = _IdentityTransferDecoder(
                self.length, req.bodyProducer.dataReceived, self._finishRequestBody)
        elif header == b'transfer-encoding' and data.lower() == b'chunked':
            self.length = None
            self._transferDecoder = _ChunkedTransferDecoder(
                req.bodyProducer.dataReceived, self._finishRequestBody)
        reqHeaders = req.requestHeaders
        values = reqHeaders.getRawHeaders(header)
        if values is not None:
            values.append(data)
        else:
            reqHeaders.setRawHeaders(header, [data])

    def allHeadersReceived(self):
        """
        Overridden to reduce the function actions
        """
        req = self.requests[-1]
        req.parseCookies()
        self.persistent = self.checkPersistence(req, self._version)

        req.requestReceived(self._command, self._path, self._version)

    def allContentReceived(self):
        if len(self.requests):
            req = self.requests[-1]
            req.bodyProducer.allDataReceived()

        # reset ALL state variables, so we don't interfere with next request
        self.length = 0
        self._receivedHeaderCount = 0
        self._HTTPChannel__first_line = 1
        self._transferDecoder = None
        del self._command, self._path, self._version

        # Disable the idle timeout, in case this request takes a long
        # time to finish generating output.
        if self.timeOut:
            self._savedTimeOut = self.setTimeout(None)


class T2WProxyFactory(http.HTTPFactory):
    protocol = T2WProxy

    def _openLogFile(self, path):
        return log.NullFile()

    def log(self, request):
        """
        Log a request's result to the logfile, by default in combined log format.
        """
        if config.logreqs:
            line = "127.0.0.1 (%s) - - %s \"%s\" %s %s \"%s\" \"%s\"\n" % (
                self._escape(request.getHeader(b'host')),
                self._logDateTime,
                '%s %s %s' % (self._escape(request.method),
                              self._escape(request.uri),
                              self._escape(request.clientproto)),
                request.code,
                request.sentLength or "-",
                self._escape(request.getHeader(b'referer') or "-"),
                self._escape(request.getHeader(b'user-agent') or "-"))

            rpc("log_access", str(line))


class T2WLimitedRequestsFactory(WrappingFactory):
    def __init__(self, wrappedFactory, allowedRequests):
        WrappingFactory.__init__(self, wrappedFactory)
        self.requests_countdown = allowedRequests

    def registerProtocol(self, p):
        """
        Called by protocol to register itself.
        """
        WrappingFactory.registerProtocol(self, p)

        if self.requests_countdown > 0:
            self.requests_countdown -= 1

        if self.requests_countdown == 0:
            # bai bai mai friend
            #
            # known bug: currently when the limit is reached all
            # the active requests are trashed.
            # this simple solution is used to achieve
            # stronger stability.
            try:
                reactor.stop()
            except Exception:
                pass


def start_worker():
    global antanistaticmap
    global templates
    global pool
    global ports

    lc = LoopingCall(updateListsTask)
    lc.start(600)

    # ##############################################################################
    # Static Data loading
    # Here we make a file caching to not handle I/O
    # at run-time and achieve better performance
    # ##############################################################################
    antanistaticmap = {}

    # system default static files
    sys_static_dir = os.path.join(config.sysdatadir, "static/")
    if os.path.exists(sys_static_dir):
        for root, dirs, files in os.walk(os.path.join(sys_static_dir)):
            for basename in files:
                filename = os.path.join(root, basename)
                f = FilePath(filename)
                antanistaticmap[filename.replace(sys_static_dir, "")] = f.getContent()

    # user defined static files
    usr_static_dir = os.path.join(config.datadir, "static/")
    if usr_static_dir != sys_static_dir and os.path.exists(usr_static_dir):
        for root, dirs, files in os.walk(os.path.join(usr_static_dir)):
            for basename in files:
                filename = os.path.join(root, basename)
                f = FilePath(filename)
                antanistaticmap[filename.replace(usr_static_dir, "")] = f.getContent()
    # ##############################################################################

    # ##############################################################################
    # Templates loading
    # Here we make a templates cache in order to not handle I/O
    # at run-time and achieve better performance
    # ##############################################################################
    templates = {}

    # system default templates
    sys_tpl_dir = os.path.join(config.sysdatadir, "templates/")
    if os.path.exists(sys_tpl_dir):
        files = FilePath(sys_tpl_dir).globChildren("*.tpl")
        for f in files:
            f = FilePath(config.t2w_file_path(os.path.join('templates', f.basename())))
            templates[f.basename()] = PageTemplate(XMLString(f.getContent()))

    # user defined templates
    usr_tpl_dir = os.path.join(config.datadir, "templates/")
    if usr_tpl_dir != sys_tpl_dir and os.path.exists(usr_tpl_dir):
        files = FilePath(usr_tpl_dir).globChildren("*.tpl")
        for f in files:
            f = FilePath(config.t2w_file_path(os.path.join('templates', f.basename())))
            templates[f.basename()] = PageTemplate(XMLString(f.getContent()))
    # ##############################################################################

    pool = client.HTTPConnectionPool(reactor, True)
    pool.maxPersistentPerHost = config.sockmaxpersistentperhost
    pool.cachedConnectionTimeout = config.sockcachedconnectiontimeout
    pool.retryAutomatically = config.sockretryautomatically
    def nullStartedConnecting(self, connector): pass
    pool._factory.startedConnecting = nullStartedConnecting

    factory = T2WProxyFactory()

    # we do not want all workers to die in the same moment
    requests_countdown = config.requests_per_process / random.randint(1, 3)

    factory = T2WLimitedRequestsFactory(factory, requests_countdown)

    context_factory = T2WSSLContextFactory(config.ssl_key,
                                           config.ssl_cert,
                                           config.ssl_dh,
                                           config.cipher_list)


    fds_https, fds_http = [], []
    if 'T2W_FDS_HTTPS' in os.environ:
        fds_https = [int(x) for x in os.environ['T2W_FDS_HTTPS'].split(",") if x]

    if 'T2W_FDS_HTTP' in os.environ:
        fds_http = [int(x) for x in os.environ['T2W_FDS_HTTP'].split(",") if x]

    reactor.listenTCPonExistingFD = listenTCPonExistingFD
    reactor.listenSSLonExistingFD = listenSSLonExistingFD

    for fd in fds_https:
        ports.append(reactor.listenSSLonExistingFD(reactor,
                                                   fd=fd,
                                                   factory=factory,
                                                   contextFactory=context_factory))

    for fd in fds_http:
        ports.append(reactor.listenTCPonExistingFD(reactor,
                                                   fd=fd,
                                                   factory=factory))

    def MailException(etype, value, tb):
        sendexceptionmail(config, etype, value, tb)

    if config.smtpmailto_exceptions:
        # if config.smtp_mail is configured we change the excepthook
        sys.excepthook = MailException


def updateListsTask():
    def set_white_list(l):
        global white_list
        white_list = l

    def set_black_list(l):
        global black_list
        black_list = l

    def set_blocked_ua_list(l):
        global blocked_ua_list
        blocked_ua_list = l

    def set_tor_exits_list(l):
        global tor_exits_list
        tor_exits_list = l

    def set_hosts_map(d):
        global hosts_map
        hosts_map = d

    global config

    rpc("get_white_list").addCallback(set_white_list)
    rpc("get_black_list").addCallback(set_black_list)
    rpc("get_blocked_ua_list").addCallback(set_blocked_ua_list)
    rpc("get_tor_exits_list").addCallback(set_tor_exits_list)
    rpc("get_hosts_map").addCallback(set_hosts_map)


def SigQUIT(SIG, FRM):
    try:
        reactor.stop()
    except Exception:
        pass


sys.excepthook = None
set_pdeathsig(signal.SIGINT)

# #########################
# Security UMASK hardening
os.umask(077)

orig_umask = os.umask


def umask(mask):
    return orig_umask(077)


os.umask = umask
# #########################

# ##############################################################################
# Basic Safety Checks
# ##############################################################################

config = Config()

if config.transport is None:
    config.transport = 'BOTH'

if config.automatic_blocklist_updates_source is None:
    config.automatic_blocklist_updates_source = ''

if config.automatic_blocklist_updates_refresh is None:
    config.automatic_blocklist_updates_refresh = 600

if config.exit_node_list_refresh is None:
    config.exit_node_list_refresh = 600

if not os.path.exists(config.datadir):
    print "Tor2web Startup Failure: unexistent directory (%s)" % config.datadir
    exit(1)

if config.mode not in ['TRANSLATION', 'WHITELIST', 'BLACKLIST']:
    print "Tor2web Startup Failure: config.mode must be one of: TRANSLATION / WHITELIST / BLACKLIST"
    exit(1)

if config.mode == "TRANSLATION":
    if not verify_onion(config.onion):
        print "Tor2web Startup Failure: TRANSLATION config.mode require config.onion configuration"
        exit(1)

for d in ['certs', 'logs']:
    path = os.path.join(config.datadir, d)
    if not os.path.exists(path):
        print "Tor2web Startup Failure: unexistent directory (%s)" % path
        exit(1)

files = [config.ssl_key, config.ssl_cert, config.ssl_dh]
for f in files:
    try:
        if (not os.path.exists(f) or
                not os.path.isfile(f) or
                not os.access(f, os.R_OK)):
            print "Tor2web Startup Failure: unexistent file (%s)" % f
            exit(1)
    except Exception:
        print "Tor2web Startup Failure: error while accessing file (%s)" % f
        exit(1)

if config.listen_ipv6 == "::" or config.listen_ipv4 == config.listen_ipv6:
    # fix for incorrect configurations
    ipv4 = None
else:
    ipv4 = config.listen_ipv4
ipv6 = config.listen_ipv6

# ##############################################################################

rexp = {
    'body': re.compile(r'(<body.*?\s*>)', re.I),
    'w2t': re.compile(r'(https.?:)?//([a-z0-9]{16}).' + config.basehost, re.I),
    't2w': re.compile(r'(http.?:)?//([a-z0-9]{16})\.onion', re.I),
    'html_t2w': re.compile( r'(href|src|url|action)[\ ]*(=[\ ]*[\'"])http[s]?://([a-z0-9]{16})\.onion([\'"/])', re.I),
    'set-cookie_t2w': re.compile(r'domain=(\.*)([a-z0-9]{16})\.onion(\b)?', re.I)
}

if 'T2W_FDS_HTTPS' not in os.environ and 'T2W_FDS_HTTP' not in os.environ:

    set_proctitle("tor2web")

    def open_listenin_socket(ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setblocking(False)
            s.bind((ip, port))
            s.listen(1024)
            return s
        except Exception as e:
            print "Tor2web Startup Failure: error while binding on %s %s (%s)" % (ip, port, e)
            exit(1)

    def daemon_init(self):

        self.quitting = False
        self.subprocesses = []

        self.socket_rpc = open_listenin_socket('127.0.0.1', 8789)

        self.childFDs = {0: 0, 1: 1, 2: 2}

        self.fds = []

        self.fds_https = self.fds_http = ''

        i_https = i_http = 0

        for ip in [ipv4, ipv6]:
            if ip is not None:
                if config.transport in ('HTTPS', 'BOTH'):
                    if i_https != 0:
                        self.fds_https += ','
                    s = open_listenin_socket(ip, config.listen_port_https)
                    self.fds.append(s)
                    self.childFDs[s.fileno()] = s.fileno()
                    self.fds_https += str(s.fileno())
                    i_https += 1

                if config.transport in ('HTTP', 'BOTH'):
                    if i_http != 0:
                        self.fds_http += ','
                    s = open_listenin_socket(ip, config.listen_port_http)
                    self.fds.append(s)
                    self.childFDs[s.fileno()] = s.fileno()
                    self.fds_http += str(s.fileno())
                    i_http += 1


    def daemon_main(self):
        if config.logreqs:
            self.logfile_access = logfile.DailyLogFile.fromFullPath(os.path.join(config.datadir, 'logs', 'access.log'))
        else:
            self.logfile_access = log.NullFile()

        if config.debugmode:
            if config.debugtostdout and config.nodaemon:
                self.logfile_debug = sys.stdout
            else:
                self.logfile_debug = logfile.DailyLogFile.fromFullPath(
                    os.path.join(config.datadir, 'logs', 'debug.log'))
        else:
            self.logfile_debug = log.NullFile()

        log.startLogging(self.logfile_debug)

        reactor.listenTCPonExistingFD = listenTCPonExistingFD

        reactor.listenUNIX(os.path.join(config.rundir, 'rpc.socket'), factory=pb.PBServerFactory(self.rpc_server))

        for i in range(config.processes):
            subprocess = spawnT2W(self, self.childFDs, self.fds_https, self.fds_http)
            self.subprocesses.append(subprocess.pid)

        def MailException(etype, value, tb):
            sendexceptionmail(config, etype, value, tb)

        if config.smtpmailto_exceptions:
            # if config.smtp_mail is configured we change the excepthook
            sys.excepthook = MailException

        reactor.run()

    def daemon_reload(self):
        self.rpc_server.load_lists()

    def daemon_shutdown(self):
        self.quitting = True

        for pid in self.subprocesses:
            os.kill(pid, signal.SIGINT)

        self.subprocesses = []

    t2w_daemon = T2WDaemon(config)
    t2w_daemon.daemon_init = daemon_init
    t2w_daemon.daemon_main = daemon_main
    t2w_daemon.daemon_reload = daemon_reload
    t2w_daemon.daemon_shutdown = daemon_shutdown
    t2w_daemon.rpc_server = T2WRPCServer(config)

    t2w_daemon.run(config)

else:

    set_proctitle("tor2web-worker")

    white_list = []
    black_list = []
    blocked_ua_list = []
    tor_exits_list = []
    hosts_map = {}
    ports = []

    rpc_factory = pb.PBClientFactory()

    reactor.connectUNIX(os.path.join(config.rundir, "rpc.socket"), rpc_factory)
    os.chmod(os.path.join(config.rundir, "rpc.socket"), 0600)

    signal.signal(signal.SIGUSR1, SigQUIT)
    signal.signal(signal.SIGTERM, SigQUIT)
    signal.signal(signal.SIGINT, SigQUIT)

    start_worker()

    reactor.run()
