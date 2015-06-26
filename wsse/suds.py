"""Suds plugin for WS-Security (WSSE) encryption/signing."""
from __future__ import absolute_import

from suds.plugin import MessagePlugin

from .encryption import encrypt, decrypt
from .signing import sign, verify


class WssePlugin(MessagePlugin):
    """Suds message plugin that performs WS-Security signing and encryption.

    Encrypts and signs outgoing messages (the soap:Body and the wsu:Timestamp
    security token, which must be present); decrypts and verifies signature on
    incoming messages.

    Uses X509 certificates for both encryption and signing. Requires our cert
    and its private key, and their cert (all as file paths).

    Expects to sign and encrypt an outgoing SOAP message looking something like
    this (xmlns attributes omitted for readability):

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

    The contents of the soap:Body element are specific to the receiving API;
    nothing in ``py-wsse`` knows or cares about them (except that currently
    only the first child element of the soap:Body will be encrypted).

    """
    def __init__(self, keyfile, certfile, their_certfile):
        self.keyfile = keyfile
        self.certfile = certfile
        self.their_certfile = their_certfile

    def sending(self, context):
        """Sign and encrypt outgoing message envelope."""
        context.envelope = sign(
            context.envelope, self.keyfile, self.certfile)
        context.envelope = encrypt(context.envelope, self.their_certfile)

    def received(self, context):
        """Decrypt and verify signature of incoming reply envelope."""
        if context.reply:
            context.reply = decrypt(context.reply, self.keyfile)
            verify(context.reply, self.their_certfile)
