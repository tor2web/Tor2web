"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: Main Tor2web Server Implementation

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-


import hashlib
import mimetypes
import os
import random
import re
import signal
import socket
from cgi import parse_header
from functools import partial
from io import BytesIO
from random import choice
from urllib.parse import urlsplit

import sys
import zlib
from OpenSSL._util import ffi as _ffi, lib as _lib
from twisted.internet import reactor, protocol, defer, address
from twisted.internet.abstract import isIPAddress, isIPv6Address
from twisted.internet.endpoints import TCP4ClientEndpoint, SSL4ClientEndpoint
from twisted.internet.task import LoopingCall
from twisted.protocols.policies import WrappingFactory
from twisted.python import log, logfile
from twisted.python.compat import networkString, intToBytes
from twisted.python.failure import Failure
from twisted.python.filepath import FilePath
from twisted.spread import pb
from twisted.web import http, client, _newclient
from twisted.web.error import SchemeNotSupported
from twisted.web.http import datetimeToString, StringTransport, \
    _IdentityTransferDecoder, _ChunkedTransferDecoder, parse_qs
from twisted.web.http_headers import Headers
from twisted.web.iweb import IAgentEndpointFactory, IAgent, IPolicyForHTTPS
from twisted.web.server import NOT_DONE_YET
from twisted.web.template import flattenString, XMLString
from zope.interface import implementer

try:
    from twisted.web.client import URI
except ImportError:
    from twisted.web.client import _URI as URI

from tor2web import __version__
from tor2web.utils.config import Config
from tor2web.utils.daemon import Daemon, set_pdeathsig, set_proctitle
from tor2web.utils.hostsmap import HostsMap
from tor2web.utils.lists import LimitedSizeDict, List, TorExitNodeList
from tor2web.utils.mail import sendmail, MailExceptionHooker
from tor2web.utils.misc import listenTCPonExistingFD, listenSSLonExistingFD, re_sub, is_onion
from tor2web.utils.socks import SOCKSError, SOCKS5ClientEndpoint, TLSWrapClientEndpoint
from tor2web.utils.tls import T2WSSLContextFactory, HTTPSVerifyingContextFactory
from tor2web.utils.stats import T2WStats
from tor2web.utils.storage import Storage
from tor2web.utils.templating import PageTemplate
from tor2web.utils.urls import normalize_url, parent_urls


def test_file_access(f):
    return os.path.exists(f) and os.path.isfile(f) and os.access(f, os.R_OK)


class T2WRPCServer(pb.Root):
    def __init__(self, config):
        self.config = config
        self.stats = T2WStats()
        self.block_list = []
        self.block_regexps = []
        self.crawler_list = []
        self.hosts_map = {}
        self.TorExitNodes = []

        self.load_lists()

    def load_lists(self):
        if config.mode == "BLOCKLIST":
            self.block_list = List(config.t2w_file_path('lists/blocklist_hashed.txt'),
                                   config.automatic_blocklist_updates_source,
                                   config.automatic_blocklist_updates_mode,
                                   config.automatic_blocklist_updates_refresh)

            # clear local cleartext list
            # (load -> hash -> clear feature; for security reasons)
            self.blocklist_cleartext = List(config.t2w_file_path('lists/blocklist_cleartext.txt'))
            for i in self.blocklist_cleartext:
                self.block_list.add(hashlib.md5(normalize_url(i)).hexdigest())

            self.block_list.dump()

            self.blocklist_cleartext.clear()
            self.blocklist_cleartext.dump()

            self.block_regexps = List(config.t2w_file_path('lists/blocklist_regexp.txt'))
            self.block_regexps = [re.compile(regexp_pattern) for regexp_pattern in self.block_regexps]

        self.crawler_list = [ua.lower() for ua in List(config.t2w_file_path('lists/crawlers.txt'))]

        # Load Exit Nodes list with the refresh rate configured  in config file
        self.TorExitNodes = TorExitNodeList(config.t2w_file_path('lists/exitnodelist.txt'),
                                            'https://check.torproject.org/exit-addresses',
                                            'REPLACE',
                                            config.exit_node_list_refresh)

        self.hosts_map = HostsMap(config.t2w_file_path('lists/hosts_map.txt')).hosts
        if config.mode == "TRANSLATION":
            self.hosts_map[config.basehost] = {
                'onion': config.onion,
                'dp': config.dummyproxy
            }

    def remote_get_config(self):
        return self.config.__dict__

    def remote_get_crawler_list(self):
        return list(self.crawler_list)

    def remote_get_block_list(self):
        return list(self.block_list)

    def remote_get_block_regexps(self):
        return list(self.block_regexps)

    def remote_get_tor_exits_list(self):
        return list(self.TorExitNodes)

    def remote_get_hosts_map(self):
        return dict(self.hosts_map)

    def remote_update_stats(self, onion):
        self.stats.update(onion)

    def remote_get_yesterday_stats(self):
        return self.stats.yesterday_stats

    def remote_log_access(self, line):
        t2w_daemon.logfile_access.write(line)

    def remote_log_debug(self, line):
        date = datetimeToString()
        t2w_daemon.logfile_debug.write(date.decode('utf-8') + " " + str(line) + "\n")

    def remote_shutdown(self):
        reactor.stop()


def rpc(f, *args, **kwargs):
    d = rpc_factory.getRootObject()
    d.addCallback(lambda obj: obj.callRemote(f, *args, **kwargs))
    return d


def rpc_log(msg):
    return rpc("log_debug", str(msg))


def rpc_shutdown():
    return rpc("shutdown")


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


class Tor2webObj(object):
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

        # A variably that keep tracks of special contents to be parsed
        self.special_content = None


class BodyReceiver(protocol.Protocol):
    def __init__(self, finished):
        self._finished = finished
        self._data = []

    def dataReceived(self, chunk):
        self._data.append(chunk)

    def write(self, chunk):
        self._data.append(chunk)

    def connectionLost(self, reason):
        self._finished.callback(b''.join(self._data))


class BodyStreamer(protocol.Protocol):
    def __init__(self, streamfunction, finished):
        self._finished = finished
        self._streamfunction = streamfunction

    def dataReceived(self, data):
        self._streamfunction(data)

    def connectionLost(self, reason):
        self._finished.callback(b'')


class BodyProducer(object):
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

    def resumeProducing(self):
        pass

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass


class Agent(client.Agent):
    def __init__(self, reactor,
                 contextFactory=client.BrowserLikePolicyForHTTPS(),
                 connectTimeout=None, bindAddress=None,
                 pool=None, sockhost=None, sockport=None):
        self._sockhost = sockhost
        self._sockport = sockport
        client.Agent.__init__(self, reactor, contextFactory,
                              connectTimeout, bindAddress, pool)

    def request(self, method, uri, headers, bodyProducer=None):
        for key, values in headers.getAllRawHeaders():
            fixed_values = [re_sub(rexp['w2t'], b'http://\2.onion', value) for value in values]
            headers.setRawHeaders(key, fixed_values)

        return client.Agent.request(self, method, uri, headers, bodyProducer)


class RedirectAgent(client.RedirectAgent):
    """
    Overridden client.RedirectAgent version where we evaluate and handle automatically only HTTPS redirects
    """

    def _handleResponse(self, response, method, uri, headers, redirectCount):
        locationHeaders = response.headers.getRawHeaders('location', [])
        if locationHeaders:
            location = self._resolveLocation(uri, locationHeaders[0].encode('utf-8'))
            parsed = client.URI.fromBytes(location)
            if parsed.scheme == b'https':
                return client.RedirectAgent._handleResponse(self, response, method, uri, headers, redirectCount)

        return response


@implementer(IAgentEndpointFactory, IAgent)
class SOCKS5Agent(object):
    endpointFactory = SOCKS5ClientEndpoint
    _tlsWrapper = TLSWrapClientEndpoint

    def __init__(self, reactor, contextFactory=client.BrowserLikePolicyForHTTPS(),
                 connectTimeout=None, bindAddress=None, pool=None, proxyEndpoint=None, endpointArgs={}):
        if not IPolicyForHTTPS.providedBy(contextFactory):
            raise NotImplementedError(
                'contextFactory must implement IPolicyForHTTPS')
        self.proxyEndpoint = proxyEndpoint
        self.endpointArgs = endpointArgs
        self._policyForHTTPS = contextFactory
        self._wrappedAgent = Agent.usingEndpointFactory(reactor, self, pool=pool)
        self._wrappedAgent = RedirectAgent(self._wrappedAgent, 1)

    def request(self, *a, **kw):
        return self._wrappedAgent.request(*a, **kw)

    def _getEndpoint(self, scheme, host, port):
        endpoint = self.endpointFactory(host, port, self.proxyEndpoint, **self.endpointArgs)

        if scheme == b'https':
            tlsPolicy = self._policyForHTTPS.creatorForNetloc(host, port)
            endpoint = self._tlsWrapper(tlsPolicy, endpoint)

        return endpoint

    def endpointForURI(self, uri):
        return self._getEndpoint(uri.scheme, uri.host, uri.port)


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

        self.stream = b''

        self.header_injected = False
        # If we should disable the banner,
        # say that we have already injected it.
        if config.disable_banner:
            self.header_injected = True

        self.transport = StringTransport() if queued else self.channel.transport

        self.obj = Tor2webObj()
        self.var = Storage()
        self.var['version'] = __version__
        self.var['basehost'] = config.basehost
        self.var['errorcode'] = None

        self.decoderGzip = None
        self.encoderGzip = None

        self.pool = pool

    def forwardData(self, data, end=False):
        if not self.startedWriting:
            if self.obj.client_supports_gzip:
                self.setHeader(b'content-encoding', b'gzip')

            if config.extra_http_response_headers:
                for header, value in list(config.extra_http_response_headers.items()):
                    self.setHeader(header, value)

        if data:
            self.write(data)

    def getForwarders(self):
        forwarders = []

        try:
            port = self.channel.transport.getPeer().port

            xForwardedFor = self.requestHeaders.getRawHeaders(b"X-Forwarded-For")
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
        except Exception:
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

        self.proto = b'http://' if config.transport == 'HTTP' else b'https://'

        port = self.channel.transport.getHost().port
        self.port = '' if port in [80, 443] else ':%d' % port  # ).encode('utf-8')

        self.process()

    def add_banner(self, banner, data):
        """
        Inject tor2web banner inside the returned page
        """
        return data.group(1) + banner

    def handleFixPart(self, data):
        if self.obj.server_response_is_gzip:
            data = self.unzip(data)

        data = self.stream + data

        if len(data) >= config.bufsize * 2:
            if self.obj.special_content == 'HTML':
                if not self.header_injected and data.find(b"<body") != -1:
                    data = re.sub(rexp['body'], partial(self.add_banner, self.banner), data)
                    self.header_injected = True

            if config.avoid_rewriting_visible_content and self.obj.special_content == 'HTML':
                data = re_sub(rexp['html_t2w'],
                              b'\1\2' + self.proto + b'\3.' + self.var['basehost'].encode('utf-8') + self.port.encode(
                                  'utf-8') + b'\4', data)
            else:
                data = re_sub(rexp['t2w'],
                              self.proto + b'\2.' + self.var['basehost'].encode('utf-8') + self.port.encode('utf-8'),
                              data)

        if len(data) >= config.bufsize * 2:
            forward = data[:-config.bufsize]
            self.forwardData(self.handleCleartextForwardPart(forward))
            self.stream = data[-config.bufsize:]
        else:
            self.stream = data

    def handleFixEnd(self, data):
        if self.obj.server_response_is_gzip:
            data = self.unzip(data, True)

        data = self.stream + data

        if len(data) >= config.bufsize * 2:
            if self.obj.special_content == 'HTML':
                if not self.header_injected and data.find(b"<body") != -1:
                    data = re.sub(rexp['body'], partial(self.add_banner, self.banner), data)
                    self.header_injected = True

            if config.avoid_rewriting_visible_content and self.obj.special_content == 'HTML':
                data = re_sub(rexp['html_t2w'],
                              b'\1\2' + self.proto + b'\3.' + self.var['basehost'].encode('utf-8') + self.port.encode(
                                  'utf-8') + b'\4', data)
            else:
                data = re_sub(rexp['t2w'],
                              self.proto + b'\2.' + self.var['basehost'].encode('utf-8') + self.port.encode('utf-8'),
                              data)

        self.forwardData(self.handleCleartextForwardPart(data, True), True)

        self.stream = b''

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

    def setHeaders(self):
        if self.isSecure():
            self.setHeader(b'strict-transport-security', b'max-age=31536000; includeSubDomains')
            self.setHeader(b'Content-Security-Policy', b'upgrade-insecure-requests')

        self.setHeader(b'x-check-tor', b'true' if self.obj.client_uses_tor else b'false')

        if config.extra_http_response_headers:
            for header, value in list(config.extra_http_response_headers.items()):
                self.setHeader(header, value)

    def writeContent(self, data):
        self.setHeaders()

        if len(data):
            if isinstance(data, str):
                data = data.encode('utf-8')

            if self.obj.client_supports_gzip:
                self.setHeader(b'content-encoding', b'gzip')
                data = self.zip(data, True)

            self.setHeader(b'content-length', intToBytes(len(data)))
            self.write(data)
        else:
            self.setHeader(b'content-length', intToBytes(0))

        self.finish()

    def sendError(self, error=500, errortemplate='error_generic.tpl'):
        self.setResponseCode(error)
        self.setHeader(b'content-type', 'text/html')
        self.var['errorcode'] = error
        return flattenString(self, templates[errortemplate]).addCallback(self.writeContent)

    def handleError(self, failure):
        if type(failure.value) is SOCKSError:
            self.setResponseCode(502)
            self.var['errorcode'] = failure.value.code
            return flattenString(self, templates['error_sock.tpl']).addCallback(self.writeContent)
        else:
            return self.sendError()

    def unzip(self, data, end=False):
        data1, data2 = b'', b''

        try:
            if self.decoderGzip is None:
                self.decoderGzip = zlib.decompressobj(16 + zlib.MAX_WBITS)

            if data:
                data1 = self.decoderGzip.decompress(data)

            if end:
                data2 = self.decoderGzip.flush()

        except:
            pass

        return data1 + data2

    def zip(self, data, end=False):
        data1, data2 = b'', b''

        try:
            if self.encoderGzip is None:
                self.encoderGzip = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)

            if data:
                data1 = self.encoderGzip.compress(data)

            if end:
                data2 = self.encoderGzip.flush()

        except:
            pass

        return data1 + data2

    def process_request(self, req):
        """
        This function:
            - "resolves" the address;
            - alters and sets the proper headers.
        """
        self.obj.uri = req.uri.decode('utf-8')
        self.obj.host_tor = "http://" + self.obj.onion
        self.obj.address = self.obj.host_tor + self.obj.uri
        self.obj.client_proto = 'http://' if config.transport == 'HTTP' else 'https://'
        self.obj.host_tor2web = self.obj.client_proto + self.obj.onion[:-len("onion")] + self.var[
            'basehost'] + self.port

        self.obj.headers = req.headers

        # we remove the x-forwarded-for header that may contain a leaked ip
        # self.obj.headers.removeHeader(b'x-forwarded-for')

        self.obj.headers.setRawHeaders(b'host', [self.obj.onion])
        self.obj.headers.setRawHeaders(b'connection', [b'keep-alive'])
        self.obj.headers.setRawHeaders(b'accept-encoding', [b'gzip, chunked'])
        # self.obj.headers.setRawHeaders(b'x-tor2web', [b'1'])
        # self.obj.headers.setRawHeaders(b'x-forwarded-host', [req.host])
        # self.obj.headers.setRawHeaders(b'x-forwarded-proto', [b'http' if config.transport == 'HTTP' else b'https'])

        return True

    @defer.inlineCallbacks
    def process(self):
        self.banner = yield flattenString(self, templates['banner.tpl'])

        request = Storage()
        request.headers = self.requestHeaders
        request.host = self.getRequestHostname().decode('utf-8')
        request.uri = self.uri

        content_length = self.getHeader(b'content-length')
        transfer_encoding = self.getHeader(b'transfer-encoding')

        staticpath = request.uri.decode('utf-8')
        staticpath = re.sub('/$', '/index.html', staticpath)
        staticpath = re.sub('^(/antanistaticmap/)?', '', staticpath)
        staticpath = re.sub('^/', '', staticpath)

        resource_is_local = (config.mode != "TRANSLATION" and
                             (request.host == self.var['basehost'] or
                              request.host == self.var['basehost'])) or \
                            isIPAddress(request.host) or \
                            isIPv6Address(request.host) or \
                            request.uri.startswith(b'/antanistaticmap/') or \
                            request.uri.startswith(b'/checktor')

        producer = None
        if content_length is not None:
            self.bodyProducer.length = int(content_length)
            producer = self.bodyProducer
            request.headers.removeHeader(b'content-length')
        elif transfer_encoding is not None:
            producer = self.bodyProducer
            request.headers.removeHeader(b'transfer-encoding')

        if config.mirror is not None:
            if self.var['basehost'] in config.mirror:
                config.mirror.remove(self.var['basehost'])
            if len(config.mirror) > 1:
                self.var['mirror'] = choice(config.mirror)
            elif len(config.mirror) == 1:
                self.var['mirror'] = config.mirror[0]

        # we serve contents only over HTTPS
        if not self.isSecure() and (config.transport != 'HTTP'):
            if config.listen_port_https == 443:
                self.redirect("https://" + request.host + request.uri)
            else:
                self.redirect(
                    b"https://" + request.host + b":" + str(config.listen_port_https).encode('utf-8') + request.uri)

            self.finish()
            return

        # check if the user is using Tor
        self.obj.client_ip = self.getClientIP()
        self.obj.client_uses_tor = self.obj.client_ip.encode('utf-8') in tor_exits_list

        crawler = False
        if request.headers.getRawHeaders(b'user-agent') is not None:
            user_agent = request.headers.getRawHeaders(b'user-agent')[0].lower()
            for ua in crawler_list:
                if re.match(user_agent, ua.encode('utf-8')):
                    crawler = True
                    break

        # 1: Client capability assessment stage
        if request.headers.getRawHeaders(b'accept-encoding') is not None:
            if re.search(b'gzip', request.headers.getRawHeaders(b'accept-encoding')[0]):
                self.obj.client_supports_gzip = True

        # 2: Content delivery stage
        # we need to verify if the requested resource is local (/antanistaticmap/*) or remote
        # because some checks must be done only for remote requests;
        # in fact local content is always served (css, js, and png in fact are used in errors)
        if resource_is_local:
            # the requested resource is local, we deliver it directly
            try:
                if staticpath == 'checktor':
                    self.setHeader(b'access-control-allow-origin', b'*')
                    self.setHeader(b'access-control-expose-headers', b'x-check-tor')

                    # response answer compliant to https://check.torproject.org/api/ip
                    if self.obj.client_uses_tor:
                        content = "{\"IsTor\": true,\"IP\":\"" + self.obj.client_ip + "\"}"
                    else:
                        content = "{\"IsTor\": false,\"IP\":\"" + self.obj.client_ip + "\"}"

                    self.writeContent(content)
                    return

                elif staticpath == "stats/yesterday":
                    self.setHeader(b'content-type', 'application/json')
                    content = yield rpc("get_yesterday_stats")
                    self.writeContent(content)
                    return

                elif config.publish_blocklist and staticpath == "blocklist":
                    self.setHeader(b'content-type', b'text/plain')
                    content = yield rpc("get_block_list")
                    content = "\n".join(item for item in content)
                    self.writeContent(content)
                    return

                elif staticpath == "notification" and config.smtpmailto_notifications != '':
                    # ################################################################
                    # Here we need to parse POST data in x-www-form-urlencoded format
                    # ################################################################
                    content_receiver = BodyReceiver(defer.Deferred())
                    self.bodyProducer.startProducing(content_receiver)
                    yield self.bodyProducer.finished
                    content = b''.join(content_receiver._data)

                    args = {}

                    ctype = self.requestHeaders.getRawHeaders(b'content-type')
                    if ctype is not None:
                        ctype = ctype[0]

                    if self.method == b"POST" and ctype:
                        key, _ = parse_header(ctype.decode('utf-8'))
                        if key == 'application/x-www-form-urlencoded':
                            args.update(parse_qs(content, 1))
                    # ################################################################

                    if b'by' in args and b'url' in args and b'comment' in args:
                        tmp = ["From: Tor2web Node %s.%s <%s>\n" % (
                            config.nodename, self.var['basehost'], config.smtpmail),
                               "To: %s\n" % config.smtpmailto_notifications,
                               "Subject: Tor2web Node (IPv4 %s, IPv6 %s): notification for %s\n" % (
                                   config.listen_ipv4, config.listen_ipv6, args[b'url'][0]),
                               "Content-Type: text/plain; charset=ISO-8859-1\n", "Content-Transfer-Encoding: 8bit\n\n",
                               "BY: %s\n" % (args[b'by'][0]), "URL: %s\n" % (args[b'url'][0]),
                               "COMMENT: %s\n" % (args[b'comment'][0])]
                        message = BytesIO((''.join(tmp)).encode('utf-8'))

                        sendmail(config, config.smtpmailto_notifications, message)

                    self.setHeader(b'content-type', 'text/plain')
                    self.finish()
                    return

                else:
                    if type(antanistaticmap[staticpath]) == bytes:
                        _, ext = os.path.splitext(staticpath)
                        self.setHeader(b'content-type', mimetypes.types_map[ext])
                        content = antanistaticmap[staticpath]
                        self.writeContent(content)
                        return

                    elif type(antanistaticmap[staticpath]) == PageTemplate:
                        flattenString(self, antanistaticmap[staticpath]).addCallback(self.writeContent)

            except Exception:
                pass

            self.sendError(404)
            return

        else:
            if config.basehost == 'AUTO':
                self.var['basehost'] = "tor2web.org"

                try:
                    self.var['basehost'] = request.host.split('.', 1)[1]
                except:
                    pass
            else:
                self.var['basehost'] = config.basehost

            rexp['w2t'] = re.compile(
                b'(http:|https:)?//([a-z0-9\.]*[a-z0-9]{56})\.' + self.var['basehost'].encode('utf-8'), re.I)

            # the requested resource is remote, we act as proxy
            if config.mode == 'TRANSLATION' and request.host in hosts_map:
                self.obj.onion = hosts_map[request.host]['onion']
            else:
                self.obj.onion = request.host.split("." + self.var['basehost'])[0].split(".")[-1] + ".onion"
            if not request.host or not is_onion(self.obj.onion):
                self.sendError(406, 'error_invalid_hostname.tpl')
                return

            # if the user is using tor redirect directly to the hidden service
            if self.obj.client_uses_tor and not config.disable_tor_redirection:
                self.redirect(b"http://" + self.obj.onion + request.uri)
                self.finish()
                return

            # Avoid image hotlinking
            if config.blockhotlinking and request.uri.decode('utf-8').lower().endswith(
                    tuple(config.blockhotlinking_exts)):
                if request.headers.getRawHeaders(b'referer') is not None and \
                        request.host.encode('utf-8') not in request.headers.getRawHeaders(b'referer')[0].lower():
                    self.sendError(403)
                    return

            self.process_request(request)

            parsed = urlsplit(self.obj.address)

            self.var['address'] = self.obj.address
            self.var['onion'] = self.obj.onion.replace(".onion", "")
            self.var['path'] = parsed[2]

            if not crawler:
                if not config.disable_disclaimer and not self.getCookie(b"disclaimer_accepted"):
                    self.setResponseCode(401)
                    self.setHeader(b'content-type', 'text/html')
                    self.var['url'] = self.obj.uri
                    flattenString(self, templates['disclaimer.tpl']).addCallback(self.writeContent)
                    return

            blocked = False

            if config.mode == "BLOCKLIST":
                # Variations of the URL for testing against the blocklist
                full_path = self.obj.onion + self.var['path']
                full_url = full_path
                if parsed[3]:
                    full_url += '?' + parsed[3]
                normalized_url = normalize_url(full_url)

                onionset = {self.obj.onion, self.obj.onion[-22:]}
                urlset = {full_url, normalized_url, full_path}

                test_urls = []
                test_urls.extend(onionset)
                test_urls.extend(urlset)
                test_urls.extend(parent_urls(full_url, 1))
                test_urls.append(self.var['path'])

                rpc_log("detected <onion_url>.tor2web Hostname: %s" % self.obj.onion)
                if not is_onion(self.obj.onion):
                    self.sendError(406, 'error_invalid_hostname.tpl')
                    return

                blocked = False
                if any(hashlib.md5(url.encode('utf-8')).hexdigest() in block_list for url in test_urls):
                    blocked = True
                else:
                    for block_regexp in block_regexps:
                        if block_regexp.search(full_url) is not None:
                            blocked = True
                            break

            if blocked:
                self.sendError(403, 'error_blocked_page.tpl')
                return

            torEndpoint = TCP4ClientEndpoint(reactor, config.sockshost, config.socksport)
            agent = SOCKS5Agent(reactor, proxyEndpoint=torEndpoint, pool=self.pool)

            if config.mode == 'TRANSLATION' and request.host in hosts_map and hosts_map[request.host]['dp'] is not None:
                proxy_url = hosts_map[request.host]['dp'] + parsed[2] + '?' + parsed[3]
            else:
                proxy_url = self.obj.address

            self.proxy_d = agent.request(self.method,
                                         proxy_url.encode('utf-8'),
                                         self.obj.headers, bodyProducer=producer)

            self.proxy_d.addCallback(self.cbResponse)
            self.proxy_d.addErrback(self.handleError)

    def cbResponse(self, response):
        self.proxy_response = response
        if 600 <= int(response.code) <= 699:
            self.setResponseCode(500)
            self.var['errorcode'] = int(response.code) - 600
            return flattenString(self, templates['error_sock.tpl']).addCallback(self.writeContent)

        self.setResponseCode(response.code)
        self.processResponseHeaders(response.headers)

        self.setHeaders()

        # if there's no response, we're done.
        if not response.length:
            self.setHeader(b'content-length', intToBytes(0))
            self.finish()
            return defer.succeed

        finished = defer.Deferred()
        if self.obj.special_content:
            finished.addCallback(self.handleFixEnd)
            response.deliverBody(BodyStreamer(self.handleFixPart, finished))
        else:
            finished.addCallback(self.handleForwardEnd)
            response.deliverBody(BodyStreamer(self.handleForwardPart, finished))

        return finished

    def handleHeader(self, key, values):
        keyLower = key.lower()

        # some headers does not allow multiple occurrences
        # in case of multiple occurrences we evaluate only the first
        valueLower = values[0].lower()

        if keyLower == b'transfer-encoding' and valueLower == b'chunked':
            # this header needs to be stripped
            return

        elif keyLower == b'content-encoding' and valueLower == b'gzip':
            self.obj.server_response_is_gzip = True
            # this header needs to be stripped
            return

        elif keyLower == b'content-type':
            if valueLower.startswith(b'text/html'):
                self.obj.special_content = 'HTML'
            elif valueLower.startswith(b'application/javascript'):
                self.obj.special_content = 'JS'
            elif valueLower.startswith(b'text/css'):
                self.obj.special_content = 'CSS'
            elif valueLower.startswith(b'text/xml'):
                self.obj.special_content = 'XML'

        elif keyLower == b'content-length':
            self.receivedContentLen = valueLower
            # this header needs to be stripped
            return

        elif keyLower == 'set-cookie':
            values = [re_sub(rexp['set_cookie_t2w'], b'domain=\1.' + config.basehost.encode('utf-8') + b'\2', x) for x
                      in values]

        else:
            values = [
                re_sub(rexp['t2w'], self.proto + b'\2.' + config.basehost.encode('utf-8') + self.port.encode('utf-8'),
                       x) for x in values]

        self.responseHeaders.setRawHeaders(key, values)

    def processResponseHeaders(self, headers):
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

    def handleContentChunk(self, data):
        self.bodyProducer.dataReceived(data)


class T2WProxy(http.HTTPChannel):
    requestFactory = T2WRequest

    def allHeadersReceived(self):
        http.HTTPChannel.allHeadersReceived(self)

        self.requests[-1].requestReceived(self._command, self._path, self._version)

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
        self.allowed_requests = allowedRequests
        self.requests_counter = 0
        self.requests_countdown = allowedRequests

    def registerProtocol(self, p):
        """
        Called by protocol to register itself.
        """
        WrappingFactory.registerProtocol(self, p)

        self.requests_counter += 1
        if self.requests_counter == self.allowed_requests:
            for p in ports:
                try:
                    p.stopListening()
                except Exception:
                    pass

    def unregisterProtocol(self, p):
        self.requests_countdown -= 1

        if self.requests_countdown <= 0:
            try:
                reactor.stop()
            except Exception:
                pass


def open_listening_socket(ip, port):
    try:
        if isIPv6Address(ip):
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setblocking(False)
        s.bind((ip, port))
        s.listen(1024)
        return s
    except Exception as e:
        print(("Tor2web Startup Failure: error while binding on %s %s (%s)" % (ip, port, e)))
        exit(1)


class T2WDaemon(Daemon):
    def daemon_init(self):
        self.quitting = False
        self.subprocesses = []

        self.rpc_server = T2WRPCServer(self.config)

        self.childFDs = {0: 0, 1: 1, 2: 2}

        self.fds = []

        self.fds_https = self.fds_http = ''

        i_https = i_http = 0

        for ip in [ipv6, ipv4]:
            if ip is None:
                continue

            if self.config.transport in ('HTTP', 'BOTH'):
                if i_http:
                    self.fds_http += ','

                s = open_listening_socket(ip, self.config.listen_port_http)
                self.fds.append(s)
                self.childFDs[s.fileno()] = s.fileno()
                self.fds_http += str(s.fileno())
                i_http += 1

            if self.config.transport in ('HTTPS', 'BOTH'):
                if i_https:
                    self.fds_https += ','

                s = open_listening_socket(ip, self.config.listen_port_https)
                self.fds.append(s)
                self.childFDs[s.fileno()] = s.fileno()
                self.fds_https += str(s.fileno())
                i_https += 1

    def daemon_main(self):
        if self.config.logreqs:
            self.logfile_access = logfile.LogFile.fromFullPath(os.path.join(self.config.datadir, 'logs', 'access.log'),
                                                               rotateLength=1000000,
                                                               maxRotatedFiles=10)
        else:
            self.logfile_access = log.NullFile()

        if self.config.debugmode:
            if self.config.debugtostdout and self.config.nodaemon:
                self.logfile_debug = sys.stdout
            else:
                self.logfile_debug = logfile.LogFile.fromFullPath(
                    os.path.join(self.config.datadir, 'logs', 'debug.log'),
                    rotateLength=1000000,
                    maxRotatedFiles=10)
        else:
            self.logfile_debug = log.NullFile()

        log.startLogging(self.logfile_debug)

        reactor.listenUNIX(os.path.join(self.config.rundir, 'rpc.socket'), factory=pb.PBServerFactory(self.rpc_server))

        for i in range(self.config.processes):
            subprocess = spawnT2W(self, self.childFDs, self.fds_https, self.fds_http)
            self.subprocesses.append(subprocess.pid)

        if self.config.smtpmailto_exceptions:
            # if self.config.smtp_mail is configured we change the excepthook
            sys.excepthook = MailExceptionHooker(self.config)

        reactor.run()

    def daemon_reload(self):
        self.rpc_server.load_lists()

    def daemon_shutdown(self):
        self.quitting = True

        for pid in self.subprocesses:
            os.kill(pid, signal.SIGINT)

        self.subprocesses = []


def start_worker():
    if config.smtpmailto_exceptions:
        # if config.smtp_mail is configured we change the excepthook
        sys.excepthook = MailExceptionHooker(config)

    LoopingCall(updateListsTask).start(600)

    factory = T2WProxyFactory()

    # we do not want all workers to die in the same moment
    requests_countdown = config.requests_per_process / random.randint(1, 3)

    factory = T2WLimitedRequestsFactory(factory, requests_countdown)

    if 'T2W_FDS_HTTP' in os.environ:
        fds_http = [int(x) for x in os.environ['T2W_FDS_HTTP'].split(",") if x]
        for fd in fds_http:
            ports.append(listenTCPonExistingFD(reactor,
                                               fd=fd,
                                               factory=factory))

    fds_https, fds_http = [], []
    if 'T2W_FDS_HTTPS' in os.environ:
        try:
            context_factory = T2WSSLContextFactory(config.ssl_key,
                                                   config.ssl_cert,
                                                   config.ssl_intermediate,
                                                   config.cipher_list)
        except:
            rpc_log("Unable to load SSL certificate; check certificate configuration.")
            rpc_shutdown()
            return

        fds_https = [int(x) for x in os.environ['T2W_FDS_HTTPS'].split(",") if x]
        for fd in fds_https:
            ports.append(listenSSLonExistingFD(reactor,
                                               fd=fd,
                                               factory=factory,
                                               contextFactory=context_factory))


def updateListsTask():
    def set_block_list(l):
        global block_list
        block_list = l

    def set_block_regexps(l):
        global block_regexps
        block_regepxs = l

    def set_crawler_list(l):
        global crawler_list
        crawler_list = l

    def set_tor_exits_list(l):
        global tor_exits_list
        tor_exits_list = l

    def set_hosts_map(d):
        global hosts_map
        hosts_map = d

    rpc("get_block_list").addCallback(set_block_list)
    rpc("get_block_regexps").addCallback(set_block_regexps)
    rpc("get_crawler_list").addCallback(set_crawler_list)
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
os.umask(0o77)

orig_umask = os.umask


def umask(mask):
    return orig_umask(0o77)


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
    print(("Tor2web Startup Failure: unexistent directory (%s)" % config.datadir))
    exit(1)

if config.mode not in ['TRANSLATION', 'BLOCKLIST']:
    print("Tor2web Startup Failure: config.mode must be TRANSLATION or BLOCKLIST")
    exit(1)

if config.mode == "TRANSLATION":
    if not is_onion(config.onion):
        print("Tor2web Startup Failure: TRANSLATION config.mode require config.onion configuration")
        exit(1)

for d in ['certs', 'logs']:
    path = os.path.join(config.datadir, d)
    if not os.path.exists(path):
        print(("Tor2web Startup Failure: unexistent directory (%s)" % path))
        exit(1)

if config.transport in ('HTTPS', 'BOTH'):
    if not test_file_access(config.ssl_key):
        print(("Tor2web Startup Failure: unexistent file (%s)" % config.ssl_key))
        exit(1)

    if not test_file_access(config.ssl_cert) and not test_file_access(config.ssl_intermediate):
        print(("Tor2web Startup Failure: unexistent file (%s)" % config.ssl_cert))
        exit(1)

if config.listen_ipv6 == "::" or config.listen_ipv4 == config.listen_ipv6:
    # fix for incorrect configurations
    ipv4 = None
else:
    ipv4 = config.listen_ipv4
ipv6 = config.listen_ipv6

# ##############################################################################

rexp = {
    'body': re.compile(b'(<body.*?\s*>)', re.I),
    'w2t': re.compile(b'(http:|https:)?\/\/([a-z0-9\.]*[a-z0-9]{16,56})' + config.basehost.encode('utf-8'), re.I),
    't2w': re.compile(b'(http:|https:)?\/\/([a-z0-9\.]*[a-z0-9]{16,56})\.onion', re.I),
    'set_cookie_t2w': re.compile(b'domain=([a-z0-9\.]*[a-z0-9]{16,56})\.onion', re.I),
    'html_t2w': re.compile(
        b'(archive|background|cite|classid|codebase|data|formaction|href|icon|longdesc|manifest|poster|profile|src|url|usemap|)([\s]*=[\s]*[\'\"]?)(?:http:|https:)?\/\/([a-z0-9\.]*[a-z0-9]{16,56})\.onion([\ \'\"\/])',
        re.I)
}

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

def nullStartedConnecting(self, connector):
    pass


pool = client.HTTPConnectionPool(reactor, True)
pool.maxPersistentPerHost = config.sockmaxpersistentperhost
pool.cachedConnectionTimeout = config.sockcachedconnectiontimeout
pool.retryAutomatically = config.sockretryautomatically
pool._factory.startedConnecting = nullStartedConnecting

if 'T2W_FDS_HTTPS' not in os.environ and 'T2W_FDS_HTTP' not in os.environ:
    set_proctitle(b"tor2web")

    t2w_daemon = T2WDaemon(config)

    t2w_daemon.run()

else:
    set_proctitle(b"tor2web-worker")

    block_list = []
    block_regexps = []
    crawler_list = []
    tor_exits_list = []
    hosts_map = {}
    ports = []

    rpc_factory = pb.PBClientFactory()

    reactor.connectUNIX(os.path.join(config.rundir, "rpc.socket"), rpc_factory)
    os.chmod(os.path.join(config.rundir, "rpc.socket"), 0o600)

    signal.signal(signal.SIGUSR1, SigQUIT)
    signal.signal(signal.SIGTERM, SigQUIT)
    signal.signal(signal.SIGINT, SigQUIT)

    start_worker()

    reactor.run()
