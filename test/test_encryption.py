import base64

from lxml import etree
from OpenSSL import crypto

from wsse.constants import SOAP_NS, WSSE_NS, DS_NS, ENC_NS
from wsse import encryption


namespaces = {
    'soap': SOAP_NS,
    'wsse': WSSE_NS,
    'ds': DS_NS,
    'xenc': ENC_NS,
}


def xp(node, xpath):
    """Utility to do xpath search with namespaces."""
    return node.xpath(xpath, namespaces=namespaces)


def test_encryption(envelope, cert, cert_path, key_path):
    encrypted = encryption.encrypt(envelope, cert_path)
    doc = etree.fromstring(encrypted)
    bst = xp(
        doc,
        '/soap:Envelope/soap:Header/'
        'wsse:Security/wsse:BinarySecurityToken'
    )[0].text
    enc_key = xp(
        doc,
        '/soap:Envelope/soap:Header/'
        'wsse:Security/xenc:EncryptedKey'
    )[0]
    enc_key_kids = [c.tag[c.tag.rfind('}')+1:] for c in enc_key.getchildren()]
    encoded_cert = base64.b64encode(
        crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)).decode('utf-8')

    assert bst == encoded_cert
    assert 'EncryptionMethod' in enc_key_kids
    assert 'KeyInfo' in enc_key_kids
    assert 'CipherData' in enc_key_kids
    assert 'ReferenceList' in enc_key_kids
    assert len(xp(doc, '/soap:Envelope/soap:Body/xenc:EncryptedData')) == 1
