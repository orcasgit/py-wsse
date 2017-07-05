import base64

from lxml import etree
from OpenSSL import crypto
from suds.plugin import MessageContext

from wsse.suds import WssePlugin


def test_suds_plugin_sending(
        envelope, their_cert, cert_path, key_path, their_cert_path, xp):
    plugin = WssePlugin(key_path, cert_path, their_cert_path)
    context = MessageContext()
    context.envelope = envelope

    plugin.sending(context)

    doc = etree.fromstring(context.envelope)
    bst = xp(
        doc,
        '/soap:Envelope/soap:Header/'
        'wsse:Security/wsse:BinarySecurityToken'
    )[0].text
    issuer = xp(
        doc,
        (
            '/soap:Envelope/soap:Header/'
            'wsse:Security/ds:Signature/ds:KeyInfo/'
            'wsse:SecurityTokenReference/ds:X509Data/'
            'ds:X509IssuerSerial/ds:X509IssuerName'
        ),
    )[0].text
    assert bst == base64.b64encode(
        crypto.dump_certificate(crypto.FILETYPE_ASN1, their_cert)
    ).decode('utf-8')
    assert issuer == (
        'CN=example.com,OU=Little Dead Man Island,O=Green Herons,'
        'L=La Conner,ST=Washington,C=US'
    )
