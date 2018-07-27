#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
""" Packaging script """

import os
from setuptools import setup

NAME = 'iamvpnlibrary'
VERSION = '0.8.2'


def read(fname):
    """ Contents of a single filename """
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name=NAME,
    packages=[NAME],
    version=VERSION,
    author='Greg Cox',
    author_email='gcox@mozilla.com',
    description=('Mozilla-specific user authorization for VPN access'),
    license='MPL',
    keywords='mozilla ldap',
    url='https://github.com/mozilla-it/iamvpnlibrary',
    long_description=read('README.rst'),
    install_requires=['ldap', 'netaddr'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
    ],
)
