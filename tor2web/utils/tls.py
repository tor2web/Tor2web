"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: SSL/TLS Hacks

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-
import glob
import os

from OpenSSL import SSL
from OpenSSL._util import lib as _lib, ffi as _ffi
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from pyasn1.codec.der.decoder import decode
from pyasn1.type import univ, constraint, char, namedtype, tag
from twisted.internet import ssl

certificateAuthorityMap = {}

for certFileName in glob.glob("/etc/ssl/certs/*.pem"):
    # There might be some dead symlinks in there, so let's make sure it's real.
    if os.path.exists(certFileName):
        with open(certFileName) as f:
            data = f.read()
            x509 = load_certificate(FILETYPE_PEM, data)
            digest = x509.digest('sha1')
            # Now, de-duplicate in case the same cert has multiple names.
            certificateAuthorityMap[digest] = x509

class GeneralName(univ.Choice):
    # We are only interested in dNSNames. We use a default handler to ignore
    # other types.
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('dNSName', char.IA5String().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            )
        ),
    )

class GeneralNames(univ.SequenceOf):
    componentType = GeneralName()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, 1024)

def altnames(cert):
    altnames = []
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name() == "subjectAltName":
            dec = decode(ext.get_data(), asn1Spec=GeneralNames())
            for j in dec[0]:
                altnames.append(j[0].asOctets())
    return altnames


class T2WSSLContextFactory(ssl.ContextFactory):
    _context = None

    def __init__(self, privateKeyFilePath, certificateFilePath, intermediateFilePath, cipherList):
        self.privateKeyFilePath = privateKeyFilePath
        self.certificateFilePath = certificateFilePath
        self.intermediateFilePath = intermediateFilePath

        self.cipherList = cipherList

        # Create a context object right now.  This is to force validation of
        # the given parameters so that errors are detected earlier rather
        # than later.
        self.cacheContext()

    def cacheContext(self):
        if self._context is None:
            ctx = SSL.Context(SSL.SSLv23_METHOD)

            ctx.set_options(SSL.OP_CIPHER_SERVER_PREFERENCE |
                            SSL.OP_NO_SSLv2 |
                            SSL.OP_NO_SSLv3 |
                            SSL.OP_SINGLE_DH_USE |
                            SSL.OP_NO_COMPRESSION |
                            SSL.OP_NO_TICKET)

            ctx.set_mode(SSL.MODE_RELEASE_BUFFERS)

            first = True
            if os.path.isfile(self.certificateFilePath):
                with open(self.certificateFilePath, 'r') as f:
                    first = False
                    x509 = load_certificate(FILETYPE_PEM, f.read())
                    ctx.use_certificate(x509)

            if self.intermediateFilePath != self.certificateFilePath and \
                os.path.isfile(self.intermediateFilePath):

                if first:
                    ctx.use_certificate_chain_file(self.intermediateFilePath)
                else:
                    with open(self.intermediateFilePath, 'r') as f:
                        x509 = load_certificate(FILETYPE_PEM, f.read())
                        ctx.add_extra_chain_cert(x509)

            ctx.use_privatekey_file(self.privateKeyFilePath)

            ctx.set_cipher_list(self.cipherList)

            # If SSL_CTX_set_ecdh_auto is available then set it so the ECDH curve
            # will be auto-selected. This function was added in 1.0.2 and made a
            # noop in 1.1.0+ (where it is set automatically).
            try:
                _lib.SSL_CTX_set_ecdh_auto(ctx._context, 1) # pylint: disable=no-member
            except AttributeError:
                ecdh = _lib.EC_KEY_new_by_curve_name(_lib.NID_X9_62_prime256v1)  # pylint: disable=no-member
                ecdh = _ffi.gc(ecdh, _lib.EC_KEY_free)  # pylint: disable=no-member
                _lib.SSL_CTX_set_tmp_ecdh(ctx._context, ecdh)  # pylint: disable=no-member

            self._context = ctx

    def getContext(self):
        """
        Return an SSL context.
        """
        return self._context


class HTTPSVerifyingContextFactory(ssl.ClientContextFactory):
    def __init__(self, hostname):
        self.hostname = hostname

        # read in T2WSSLContextFactory why this settings ends in enabling only TLS
        self.method = SSL.SSLv23_METHOD

    def getContext(self):
        ctx = self._contextFactory(self.method)

        # Disallow SSL! It's insecure!
        ctx.set_options(SSL.OP_NO_SSLv2)
        ctx.set_options(SSL.OP_NO_SSLv3)

        ctx.set_options(SSL.OP_SINGLE_DH_USE)

        # http://en.wikipedia.org/wiki/CRIME_(security_exploit)
        # https://twistedmatrix.com/trac/ticket/5487
        # SSL_OP_NO_COMPRESSION = 0x00020000L
        ctx.set_options(0x00020000)

        store = ctx.get_cert_store()
        for value in list(certificateAuthorityMap.values()):
            store.add_cert(value)
        ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verifyCert)
        return ctx

    def verifyCert(self, connection, x509, errno, depth, preverifyOK):
        verify = preverifyOK

        if  depth == 0 and verify:
            cn = x509.get_subject().commonName

            if cn.startswith(b"*.") and self.hostname.split(b".")[1:] == cn.split(b".")[1:]:
                verify = True

            elif self.hostname == cn:
                verify = True

            elif self.hostname in altnames(x509):
                verify = True

        return verify
