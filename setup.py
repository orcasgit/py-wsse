from os.path import join
from setuptools import setup, find_packages


long_description = (
    open('README.rst').read() + '\n\n' + open('CHANGES.rst').read())


def get_version():
    with open(join('wsse', '__init__.py')) as f:
        for line in f:
            if line.startswith('__version__ ='):
                return line.split('=')[1].strip().strip('"\'')


setup(
    name='py-wsse',
    version=get_version(),
    description="WS-Security (SOAP WSSE) signing and encryption",
    long_description=long_description,
    author='ORCAS, Inc',
    author_email='orcastech@orcasinc.com',
    url='https://github.com/orcasgit/py-wsse/',
    packages=find_packages(),
    install_requires=['xmlsec>=0.3.1', 'pyOpenSSL>=0.15.1', 'lxml>=3.4.4'],
    extras_require={'suds': ['suds-jurko>=0.6']},
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: CPython',
    ],
    zip_safe=False,
)
