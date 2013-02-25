#!/usr/bin/env python
# -*- coding: utf8 -*-

from distutils.core import setup, Extension

setup(
    name='pyicap',
    version='1.0a3',
    description='A framework for writing ICAP servers',
    author='FÁBIÁN Tamás László',
    author_email='giganetom@gmail.com',
    url='https://github.com/netom/pyicap/',
    download_url='https://github.com/netom/pyicap/tarball/1.0a3#egg=pyicap-1.0a3',
    license='BSD License',
    platforms='OS Independent',
    py_modules=['pyicap'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Plugins',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries'
    ]
)
