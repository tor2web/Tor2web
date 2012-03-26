import socket
import struct
from zope.interface import implements
from twisted.internet import defer
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet.endpoints import _WrappingFactory

class SOCKSError(Exception):
    def __init__(self, val):
        self.val = val
    def __str__(self):
        return repr(self.val)

class SOCKSv4ClientProtocol(Protocol):
    postHandshakeEndpoint = None
    postHandshakeFactory = None
    handshakeDone = None
    buf = ''

    def SOCKSConnect(self, host, port):
        # only socksv4a for now
        ver = 4
        cmd = 1                 # stream connection
        user = '\x00'
        dnsname = ''
        try:
            addr = socket.inet_aton(host)
        except socket.error:
            addr = '\x00\x00\x00\x01'
            dnsname = '%s\x00' % host
        msg = struct.pack('!BBH', ver, cmd, port) + addr + user + dnsname
        self.transport.write(msg)

    def verifySocksReply(self, data):
        """
        Return True on success, False on need-more-data.
        Raise SOCKSError on request rejected or failed.
        """
        if len(data) < 8:
            return False
        if ord(data[0]) != 0:
            self.transport.loseConnection()
            raise SOCKSError((1, "bad data"))
        status = ord(data[1])
        if status != 0x5a:
            self.transport.loseConnection()
            raise SOCKSError((status, "request not granted: %d" % status))
        return True

    def isSuccess(self, data):
        self.buf += data
        return self.verifySocksReply(self.buf)

    def connectionMade(self):
        self.SOCKSConnect(self.postHandshakeEndpoint._host,
                          self.postHandshakeEndpoint._port)

    def dataReceived(self, data):
        if self.isSuccess(data):
            import traceback
            print "--------- I have success!!!"
            #traceback.print_stack()
            # Build protocol from provided factory and transfer control to it.
            self.transport.protocol = self.postHandshakeFactory.buildProtocol(
                self.transport.getHost())
            self.transport.protocol.transport = self.transport
            self.transport.protocol.connectionMade()
            self.handshakeDone.callback(self.transport.getPeer())


class SOCKSv4ClientFactory(ClientFactory):
    protocol = SOCKSv4ClientProtocol

    def buildProtocol(self, addr):
        r=ClientFactory.buildProtocol(self, addr)
        r.postHandshakeEndpoint = self.postHandshakeEndpoint
        r.postHandshakeFactory = self.postHandshakeFactory
        r.handshakeDone = self.handshakeDone
        return r


class SOCKSWrapper(object):
    implements(IStreamClientEndpoint)
    factory = SOCKSv4ClientFactory

    def __init__(self, reactor, host, port, endpoint):
        self._host = host
        self._port = port
        self._reactor = reactor
        self._endpoint = endpoint

    def connect(self, protocolFactory):
        """
        Return a deferred firing when the SOCKS connection is established.
        """

        def _canceller(deferred):
            connector.stopConnecting()
            deferred.errback(
                error.ConnectingCancelledError(connector.getDestination()))

        try:
            # Connect with an intermediate SOCKS factory/protocol,
            # which then hands control to the provided protocolFactory
            # once a SOCKS connection has been established.
            f = self.factory()
            f.postHandshakeEndpoint = self._endpoint
            f.postHandshakeFactory = protocolFactory
            f.handshakeDone = defer.Deferred()
            wf = _WrappingFactory(f, _canceller)
            self._reactor.connectTCP(self._host, self._port, wf)
            return f.protocol.handshakeDone
        except:
            return defer.fail()
