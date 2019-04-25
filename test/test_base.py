#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
"""
   Base module test script
"""
# This test file calls protected methods on the ldap
# file, so, we tell pylint that we're cool with it:
# pylint: disable=protected-access

import unittest
import sys
import iamvpnlibrary.iamvpnbase
try:
    # 2.7's module:
    from ConfigParser import SafeConfigParser as ConfigParser
except ImportError:  # pragma: no cover
    # 3's module:
    from configparser import ConfigParser


sys.dont_write_bytecode = True


class TestBaseFunctions(unittest.TestCase):
    """ Class of tests """

    def setUp(self):
        """ Preparing test rig """
        self.library = iamvpnlibrary.iamvpnbase.IAMVPNLibraryBase()

    def test_init(self):
        """ Verify that the self object was initialized """
        self.assertIsInstance(self.library,
                              iamvpnlibrary.iamvpnbase.IAMVPNLibraryBase,
                              'Did not create a base object')
        self.assertIsNotNone(self.library.configfile,
                             'Did not create a config object')

    def test_ingest_config_from_file(self):
        """ Verify that the library got a configparser object """
        result = self.library._ingest_config_from_file()
        self.assertIsInstance(result, ConfigParser,
                              'Did not create a config object')

    def test_read_item_from_config(self):
        """
            This test is deliberately weaksauce, as we're in the base class
            Anything super-interesting would be in a different class.
        """
        result = self.library.read_item_from_config(
            section='testing', key='normal_user')
        self.assertIsInstance(result, str, (
            "Could not find testing/normal_user in the config file.  "
            "While not fatal, it means your tests will be boring."))

    def test_sudo_user_edge(self):
        """
            This tests the verify_sudo_user function under poor situations
            These should always return the first argument
        """
        # deliberately setting sudo users parameters:
        self.library.sudo_users = []
        self.library.sudo_username_regexp = ''

        result = self.library.verify_sudo_user(None, None)
        self.assertEqual(result, None)

        result = self.library.verify_sudo_user('before', None)
        self.assertEqual(result, 'before')

        result = self.library.verify_sudo_user(None, 'after')
        self.assertEqual(result, None)

        result = self.library.verify_sudo_user('before', 'after')
        self.assertEqual(result, 'before')

        result = self.library.verify_sudo_user('hacker', 'su-to-after')
        self.assertEqual(result, 'hacker')

        result = self.library.verify_sudo_user('before', 'su-to-after')
        self.assertEqual(result, 'before')

    def test_sudo_user_normal(self):
        """
            This tests the verify_sudo_user function under normal conditions
        """
        # deliberately setting sudo users parameters:
        self.library.sudo_users = ['before']
        self.library.sudo_username_regexp = r'^su-to-(\S+)$'

        result = self.library.verify_sudo_user(None, None)
        self.assertEqual(result, None)

        result = self.library.verify_sudo_user('before', None)
        self.assertEqual(result, 'before')

        result = self.library.verify_sudo_user(None, 'after')
        self.assertEqual(result, None)

        result = self.library.verify_sudo_user('before', 'after')
        self.assertEqual(result, 'before')

        result = self.library.verify_sudo_user('hacker', 'su-to-after')
        self.assertEqual(result, 'hacker')

        result = self.library.verify_sudo_user('before', 'su-to-after')
        self.assertEqual(result, 'after')
