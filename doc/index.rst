Welcome to django-fernet-fields!
================================

`WS-Security`_ (WSSE) support for Python, including an optional `Suds`_ plugin.

.. _WS-Security: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf
.. _Suds: https://bitbucket.org/jurko/suds


Prerequisites
-------------

``py-wsse`` supports Python 2.7, 3.3, 3.4, pypy, and pypy3.

``py-wsse`` depends on `PyOpenSSL`_, `xmlsec`_, and `lxml`_, which in turn rely
on C headers being available on your system for ``OpenSSL``, ``libxml2``, and
``libxmlsec1``.  On Debian/Ubuntu, ``sudo apt-get install libssl-dev libxml2-dev
libxmlsec1-dev`` should take care of that. On RedHat-based systems, try ``sudo
yum install openssl-devel libxml2-devel xmlsec1-devel``.

.. _PyOpenSSL: https://pypi.python.org/pypi/pyOpenSSL
.. _xmlsec: https://pypi.python.org/pypi/xmlsec
.. _lxml: http://lxml.de/


Installation
------------

``py-wsse`` is available on `PyPI`_. Install it with::

    pip install py-wsse

Or use ``pip install py-wsse[suds]`` to pull in `Suds`_ as an additional
dependency.

.. _PyPI: https://pypi.python.org/pypi/py-wsse/


Features
--------

``py-wsse`` supports exactly what I needed and no more. If you need more, or
more flexibility, pull requests with tests and doc updates are welcome!
Current features:

* Signing a SOAP envelope ``Body`` and ``wsu:Timestamp`` security token using
  an X509 certificate and associated private key.

* Verifying WSSE signatures on a received SOAP envelope.

* Encrypting the contents of the SOAP ``Body`` using the recipient's X509
  certificate.

* Decrypting ``EncryptedData`` elements in a received SOAP envelope.


Usage
-----



Contributing
------------

See the `contributing docs`_.

.. _contributing docs: https://github.com/orcasgit/py-wsse/blob/master/CONTRIBUTING.rst
