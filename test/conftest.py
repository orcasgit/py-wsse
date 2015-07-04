from OpenSSL import crypto
import pytest

from wsse.constants import SOAP_NS, WSSE_NS, WSU_NS


@pytest.fixture
def envelope():
    """Create and return a simple SOAP envelope as string.

    Simple envelope includes wsse:Security header with wsu:Timestamp token, and
    a body with a single child element, as required by py-wsse.

    """
    return """
        <soap:Envelope
            xmlns:soap="%(soap_ns)s"
            xmlns:wsse="%(wsse_ns)s"
            xmlns:wsu="%(wsu_ns)s">
          <soap:Header>
            <wsse:Security mustUnderstand="true">
              <wsu:Timestamp>
                <wsu:Created>2015-06-25T21:53:25.246276+00:00</wsu:Created>
                <wsu:Expires>2015-06-25T21:58:25.246276+00:00</wsu:Expires>
              </wsu:Timestamp>
            </wsse:Security>
          </soap:Header>
          <soap:Body>
            <Foo xmlns="http://example.com">Text</Foo>
          </soap:Body>
        </soap:Envelope>
    """ % {
        'soap_ns': SOAP_NS,
        'wsse_ns': WSSE_NS,
        'wsu_ns': WSU_NS,
    }


@pytest.fixture
def key():
    """Create and return RSA private key object."""
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)
    return key


@pytest.fixture
def key_path(tmpdir, key):
    """Write private key to PEM file and return path."""
    key_path = str(tmpdir / 'key.pem')
    with open(key_path, 'wb') as fh:
        fh.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    return key_path


@pytest.fixture
def cert_path(tmpdir, key):
    """Create X.509 cert with ``key``, write to PEM, return path."""
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "Washington"
    cert.get_subject().L = "La Conner"
    cert.get_subject().O = "Green Herons"
    cert.get_subject().OU = "Little Dead Man Island"
    cert.get_subject().CN = 'example.com'
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha1')

    cert_path = str(tmpdir / 'cert.pem')

    with open(cert_path, 'wb') as fh:
        fh.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    return cert_path
