from OpenSSL import crypto
import pytest

from wsse.constants import DS_NS, ENC_NS, SOAP_NS, WSSE_NS, WSU_NS


namespaces = {
    'ds': DS_NS,
    'soap': SOAP_NS,
    'xenc': ENC_NS,
    'wsse': WSSE_NS,
    'wsu': WSU_NS,
}


@pytest.fixture
def xp():
    """Utility to do xpath search with namespaces."""
    def xp(node, xpath):
        return node.xpath(xpath, namespaces=namespaces)
    return xp


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


def create_cert(key, subject):
    cert = crypto.X509()
    for k, v in subject.items():
        setattr(cert.get_subject(), k, v)
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha1')
    return cert


@pytest.fixture
def cert(key):
    """Create X.509 cert with ``key``, return cert."""
    return create_cert(key, {
        'C': "US",
        'ST': "Washington",
        'L': "La Conner",
        'O': "Green Herons",
        'OU': "Little Dead Man Island",
        'CN': 'example.com',
    })


@pytest.fixture
def cert_path(tmpdir, cert):
    """Write X.509 cert to PEM, return path."""

    cert_path = str(tmpdir / 'cert.pem')

    with open(cert_path, 'wb') as fh:
        fh.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    return cert_path


@pytest.fixture
def their_cert(key):
    """Write their X.509 cert to PEM, return path."""

    return create_cert(key, {
        'C': "US",
        'ST': "Oregon",
        'L': "Bend",
        'O': "Bendistillery",
        'OU': "Development",
        'CN': 'dev.example.com',
    })


@pytest.fixture
def their_cert_path(tmpdir, their_cert):
    """Write their X.509 cert to PEM, return path."""

    cert_path = str(tmpdir / 'theircert.pem')

    with open(cert_path, 'wb') as fh:
        fh.write(crypto.dump_certificate(crypto.FILETYPE_PEM, their_cert))

    return cert_path
