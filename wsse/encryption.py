"""Functions for WS-Security (WSSE) encryption and decryption.

Heavily based on test examples in https://github.com/mehcode/python-xmlsec as
well as the xmlsec documentation at https://www.aleksey.com/xmlsec/. Some
functions from https://github.com/mvantellingen/py-soap-wsse.

Reading the xmldsig, xmlenc, and ws-security standards documents, though
admittedly painful, will likely assist in understanding the code in this
module.

"""
import base64

from lxml import etree
from OpenSSL import crypto
import xmlsec

from .constants import BASE64B, X509TOKEN, DS_NS, ENC_NS, SOAP_NS, WSSE_NS
from .xml import ensure_id, ns


def encrypt(envelope, certfile):
    """Encrypt body contents of given SOAP envelope using given X509 cert.

    Currently only encrypts the first child node of the body, so doesn't really
    support a body with multiple child nodes (the later ones won't be
    encrypted), and doesn't support encryption of multiple nodes.

    Expects to encrypt an incoming document something like this (xmlns
    attributes omitted for readability):

    <soap:Envelope>
      <soap:Header>
        <wsse:Security mustUnderstand="true">
          <wsu:Timestamp>
            <wsu:Created>2015-06-25T21:53:25.246276+00:00</wsu:Created>
            <wsu:Expires>2015-06-25T21:58:25.246276+00:00</wsu:Expires>
          </wsu:Timestamp>
        </wsse:Security>
      </soap:Header>
      <soap:Body>
        ...
      </soap:Body>
    </soap:Envelope>

    Encryption results in an XML structure something like this (note the added
    wsse:BinarySecurityToken and xenc:EncryptedKey nodes in the wsse:Security
    header, and that the contents of the soap:Body have now been replaced by a
    wsse:EncryptedData node):

    <soap:Envelope>
      <soap:Header>
        <wsse:Security mustUnderstand="true">
          <wsse:BinarySecurityToken
              wsu:Id="id-31e55a42-adef-4312-aa02-6da738177b25"
              EncodingType="...-wss-soap-message-security-1.0#Base64Binary"
              ValueType=".../oasis-200401-wss-x509-token-profile-1.0#X509v3">
            MIIGRTCC...7RaVeFVB/w==
          </wsse:BinarySecurityToken>
          <xenc:EncryptedKey>
            <xenc:EncryptionMethod
                Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
            <ds:KeyInfo>
              <wsse:SecurityTokenReference
                  wsse:TokenType="...wss-x509-token-profile-1.0#X509v3">
                <wsse:Reference
                    ValueType="...-wss-x509-token-profile-1.0#X509v3"
                    URI="#id-31e55a42-adef-4312-aa02-6da738177b25"
                />
              </wsse:SecurityTokenReference>
            </ds:KeyInfo>
            <xenc:CipherData>
              <xenc:CipherValue>0m23u5UVh...YLcEcmgzng==</xenc:CipherValue>
            </xenc:CipherData>
            <xenc:ReferenceList>
              <xenc:DataReference
                  URI="#id-094305bf-f73e-4940-88d9-00688bc78718"/>
            </xenc:ReferenceList>
          </xenc:EncryptedKey>
          <wsu:Timestamp wsu:Id="id-d449ec14-f31c-4174-b51c-2a56843eeda5">
            <wsu:Created>2015-06-25T22:26:57.618091+00:00</wsu:Created>
            <wsu:Expires>2015-06-25T22:31:57.618091+00:00</wsu:Expires>
          </wsu:Timestamp>
        </wsse:Security>
      </soap:Header>
      <soap:Body wsu:Id="id-73bc3f79-1597-4e35-91d5-354fc6197858">
        <xenc:EncryptedData
            Type="http://www.w3.org/2001/04/xmlenc#Element"
            wsu:Id="id-094305bf-f73e-4940-88d9-00688bc78718">
          <xenc:EncryptionMethod
            Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
          <xenc:CipherData>
            <xenc:CipherValue>rSJC8m...js2RQfw/5</xenc:CipherValue>
          </xenc:CipherData>
        </xenc:EncryptedData>
      </soap:Body>
    </soap:Envelope>

    (In practice, we'll generally be encrypting an already-signed document, so
    the Signature node would also be present in the header, but we aren't
    encrypting it and for simplicity it's omitted in this example.)

    """
    doc = etree.fromstring(envelope)

    header = doc.find(ns(SOAP_NS, 'Header'))
    security = header.find(ns(WSSE_NS, 'Security'))

    # Create a keys manager and load the cert into it.
    manager = xmlsec.KeysManager()
    key = xmlsec.Key.from_file(certfile, xmlsec.KeyFormat.CERT_PEM, None)
    manager.add_key(key)

    # Encrypt first child node of the soap:Body.
    body = doc.find(ns(SOAP_NS, 'Body'))
    target = body[0]

    # Create the EncryptedData node we will replace the target node with,
    # and make sure it has the contents XMLSec expects (a CipherValue node,
    # a KeyInfo node, and an EncryptedKey node within the KeyInfo which
    # itself has a CipherValue).
    enc_data = xmlsec.template.encrypted_data_create(
        doc,
        xmlsec.Transform.DES3,
        type=xmlsec.EncryptionType.ELEMENT,
        ns='xenc',
    )
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
    key_info = xmlsec.template.encrypted_data_ensure_key_info(
        enc_data, ns='dsig')
    enc_key = xmlsec.template.add_encrypted_key(
        key_info, xmlsec.Transform.RSA_OAEP)
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)

    enc_ctx = xmlsec.EncryptionContext(manager)
    # Generate a per-session DES key (will be encrypted using the cert).
    enc_ctx.key = xmlsec.Key.generate(
        xmlsec.KeyData.DES, 192, xmlsec.KeyDataType.SESSION)
    # Ask XMLSec to actually do the encryption.
    enc_data = enc_ctx.encrypt_xml(enc_data, target)

    # XMLSec inserts the EncryptedKey node directly within EncryptedData,
    # but WSSE wants it in the Security header instead, and referencing the
    # EncryptedData as well as the actual cert in a BinarySecurityToken.

    # Move the EncryptedKey node up into the wsse:Security header.
    security.insert(0, enc_key)

    # Create a wsse:BinarySecurityToken node containing the cert and add it
    # to the Security header.
    cert_bst = create_binary_security_token(certfile)
    security.insert(0, cert_bst)

    # Create a ds:KeyInfo node referencing the BinarySecurityToken we just
    # created, and insert it into the EncryptedKey node.
    enc_key.insert(1, create_key_info_bst(cert_bst))

    # Add a DataReference from the EncryptedKey node to the EncryptedData.
    add_data_reference(enc_key, enc_data)

    # Remove the now-empty KeyInfo node from EncryptedData (it used to
    # contain EncryptedKey, but we moved that up into the Security header).
    enc_data.remove(key_info)

    return etree.tostring(doc)


def decrypt(envelope, keyfile):
    """Decrypt all EncryptedData, using EncryptedKey from Security header.

    EncryptedKey should be a session key encrypted for given ``keyfile``.

    Expects XML similar to the example in the ``encrypt`` docstring.

    """
    # Create a key manager and load our key into it.
    manager = xmlsec.KeysManager()
    key = xmlsec.Key.from_file(keyfile, xmlsec.KeyFormat.PEM)
    manager.add_key(key)

    doc = etree.fromstring(envelope)
    header = doc.find(ns(SOAP_NS, 'Header'))
    security = header.find(ns(WSSE_NS, 'Security'))
    enc_key = security.find(ns(ENC_NS, 'EncryptedKey'))

    # Find each referenced encrypted block (each DataReference in the
    # ReferenceList of the EncryptedKey) and decrypt it.
    ref_list = enc_key.find(ns(ENC_NS, 'ReferenceList'))
    for ref in ref_list:
        # Find the EncryptedData node referenced by this DataReference.
        ref_uri = ref.get('URI')
        referenced_id = ref_uri[1:]
        enc_data = doc.xpath(
            "//enc:EncryptedData[@Id='%s']" % referenced_id,
            namespaces={'enc': ENC_NS},
        )[0]

        # XMLSec doesn't understand WSSE, therefore it doesn't understand
        # SecurityTokenReference. It expects to find EncryptedKey within the
        # KeyInfo of the EncryptedData. So we get rid of the
        # SecurityTokenReference and replace it with the EncryptedKey before
        # trying to decrypt.
        key_info = enc_data.find(ns(DS_NS, 'KeyInfo'))
        key_info.remove(key_info[0])
        key_info.append(enc_key)

        # When XMLSec decrypts, it automatically replaces the EncryptedData
        # node with the decrypted contents.
        ctx = xmlsec.EncryptionContext(manager)
        ctx.decrypt(enc_data)

    return etree.tostring(doc)


def add_data_reference(enc_key, enc_data):
    """Add DataReference to ``enc_data`` in ReferenceList of ``enc_key``.

    ``enc_data`` should be an EncryptedData node; ``enc_key`` an EncryptedKey
    node.

    Add a wsu:Id attribute to the EncryptedData if it doesn't already have one,
    so the EncryptedKey's URI attribute can reference it.

    (See the example XML in the ``encrypt()`` docstring.)

    Return created DataReference node.

    """
    # Ensure the target EncryptedData has a wsu:Id.
    data_id = ensure_id(enc_data)

    # Ensure the EncryptedKey has a ReferenceList.
    ref_list = ensure_reference_list(enc_key)

    # Create the DataReference, with URI attribute referencing the target
    # node's id, add it to the ReferenceList, and return it.
    data_ref = etree.SubElement(ref_list, ns(ENC_NS, 'DataReference'))
    data_ref.set('URI', '#' + data_id)

    return data_ref


def ensure_reference_list(encrypted_key):
    """Ensure that given EncryptedKey node has a ReferenceList node.

    Return the found or created ReferenceList node.

    """
    ref_list = encrypted_key.find(ns(ENC_NS, 'ReferenceList'))
    if ref_list is None:
        ref_list = etree.SubElement(encrypted_key, ns(ENC_NS, 'ReferenceList'))
    return ref_list


def create_key_info_bst(security_token):
    """Create and return a KeyInfo node referencing given BinarySecurityToken.

    (See the example XML in the ``encrypt()`` docstring.)

    Modified from https://github.com/mvantellingen/py-soap-wsse.

    """
    # Create the KeyInfo node.
    key_info = etree.Element(ns(DS_NS, 'KeyInfo'), nsmap={'ds': DS_NS})

    # Create a wsse:SecurityTokenReference node within KeyInfo.
    sec_token_ref = etree.SubElement(
        key_info, ns(WSSE_NS, 'SecurityTokenReference'))
    sec_token_ref.set(
        ns(WSSE_NS, 'TokenType'), security_token.get('ValueType'))

    # Add a Reference to the BinarySecurityToken in the SecurityTokenReference.
    bst_id = ensure_id(security_token)
    reference = etree.SubElement(sec_token_ref, ns(WSSE_NS, 'Reference'))
    reference.set('ValueType', security_token.get('ValueType'))
    reference.set('URI', '#%s' % bst_id)

    return key_info


def create_binary_security_token(certfile):
    """Create a BinarySecurityToken node containing the x509 certificate.

    Modified from https://github.com/mvantellingen/py-soap-wsse.

    """
    # Create the BinarySecurityToken node with appropriate attributes.
    node = etree.Element(ns(WSSE_NS, 'BinarySecurityToken'))
    node.set('EncodingType', BASE64B)
    node.set('ValueType', X509TOKEN)

    # Set the node contents.
    with open(certfile) as fh:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, fh.read())
        node.text = base64.b64encode(
            crypto.dump_certificate(crypto.FILETYPE_ASN1, cert))

    return node
