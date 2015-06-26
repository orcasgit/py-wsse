# SOAP envelope
SOAP_NS = 'http://schemas.xmlsoap.org/soap/envelope/'
# xmldsig
DS_NS = 'http://www.w3.org/2000/09/xmldsig#'
# xmlenc
ENC_NS = 'http://www.w3.org/2001/04/xmlenc#'

WSS_BASE = 'http://docs.oasis-open.org/wss/2004/01/'
# WS-Security
WSSE_NS = WSS_BASE + 'oasis-200401-wss-wssecurity-secext-1.0.xsd'
# WS-Utility
WSU_NS = WSS_BASE + 'oasis-200401-wss-wssecurity-utility-1.0.xsd'

BASE64B = WSS_BASE + 'oasis-200401-wss-soap-message-security-1.0#Base64Binary'
X509TOKEN = WSS_BASE + 'oasis-200401-wss-x509-token-profile-1.0#X509v3'
