import pytest

from lxml import etree

from wsse.constants import SOAP_NS, WSSE_NS, DS_NS
from wsse.exceptions import SignatureVerificationFailed
from wsse import signing


namespaces = {
    'soap': SOAP_NS,
    'wsse': WSSE_NS,
    'ds': DS_NS,
}


def xp(node, xpath):
    """Utility to do xpath search with namespaces."""
    return node.xpath(xpath, namespaces=namespaces)


def test_sign_and_verify(envelope, cert_path, key_path):
    signed = signing.sign(envelope, key_path, cert_path)
    doc = etree.fromstring(signed)
    issuer = xp(
        doc,
        (
            '/soap:Envelope/soap:Header/'
            'wsse:Security/ds:Signature/ds:KeyInfo/'
            'wsse:SecurityTokenReference/ds:X509Data/'
            'ds:X509IssuerSerial/ds:X509IssuerName'
        ),
    )[0].text

    assert issuer == (
        'CN=example.com,OU=Little Dead Man Island,O=Green Herons,'
        'L=La Conner,ST=Washington,C=US'
    )

    # no SignatureValidationFailed exception raised
    signing.verify(signed, cert_path)


def test_verify_failed(envelope, cert_path, key_path):
    signed = signing.sign(envelope, key_path, cert_path)
    malform = signed.replace(b'<SignatureValue>', b'<SignatureValue>MALFORMED')

    with pytest.raises(SignatureVerificationFailed):
        signing.verify(malform, cert_path)
