=======
py-wsse
=======

.. image:: https://secure.travis-ci.org/orcasgit/py-wsse.png?branch=master
   :target: http://travis-ci.org/orcasgit/py-wsse
   :alt: Test status
.. image:: https://coveralls.io/repos/orcasgit/py-wsse/badge.png?branch=master
   :target: https://coveralls.io/r/orcasgit/py-wsse
   :alt: Test coverage
.. image:: https://readthedocs.org/projects/py-wsse/badge/?version=latest
   :target: https://readthedocs.org/projects/py-wsse/?badge=latest
   :alt: Documentation Status
.. image:: https://badge.fury.io/py/py-wsse.svg
   :target: https://pypi.python.org/pypi/py-wsse
   :alt: Latest version

`WS-Security`_ (SOAP WSSE) support for Python, including an optional `Suds`_
plugin.

``py-wsse`` supports Python 2.7, 3.3, and 3.4.

.. _WS-Security: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf
.. _Suds: https://bitbucket.org/jurko/suds


Getting Help
============

Documentation for py-wsse is available at https://py-wsse.readthedocs.org/

This app is available on `PyPI`_ and can be installed with ``pip install
py-wsse`` (or ``pip install py-wsse[suds]`` to also pull in `Suds`_ as a
dependency). (Due to a temporary need for a patched dependency, you have to
also include ``-f
https://github.com/orcasgit/py-wsse/raw/master/vendor/xmlsec-0.3.1.orcas1.tar.gz``
in the pip command).

.. _PyPI: https://pypi.python.org/pypi/py-wsse/


TODO
====

Tests!


Contributing
============

See the `contributing docs`_.

.. _contributing docs: https://github.com/orcasgit/py-wsse/blob/master/CONTRIBUTING.rst

