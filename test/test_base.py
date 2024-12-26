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
import os
import configparser
import test.context  # pylint: disable=unused-import
import mock
from iamvpnlibrary.iamvpnbase import IAMVPNLibraryBase


class TestBaseFunctions(unittest.TestCase):
    """ Class of tests """

    def setUp(self):
        """ Preparing test rig """
        self.library = IAMVPNLibraryBase()

    def tearDown(self):
        """ Clear the test rig """
        self.library = None

    def test_00_init_no_conf(self):
        ''' If we get nothing good from a config file '''
        config = configparser.ConfigParser()
        with mock.patch.object(IAMVPNLibraryBase, '_ingest_config_from_file',
                               return_value=config):
            library = IAMVPNLibraryBase()
        self.assertEqual(library.fail_open, False)
        self.assertEqual(library.sudo_users, [])
        self.assertEqual(library.sudo_username_regexp, None)

    def test_01_init_good_conf(self):
        ''' If we get good things from a config file '''
        config = configparser.ConfigParser()
        config.add_section('failure')
        config.set('failure', 'fail_open', 'true')
        config.add_section('sudo')
        config.set('sudo', 'sudo_users', "[ 'bob' ]")
        config.set('sudo', 'sudo_username_regexp', r'^su-to-(\S+)$')
        with mock.patch.object(IAMVPNLibraryBase, '_ingest_config_from_file',
                               return_value=config):
            library = IAMVPNLibraryBase()
        self.assertEqual(library.fail_open, True)
        self.assertEqual(library.sudo_users, ['bob'])
        self.assertEqual(library.sudo_username_regexp, r'^su-to-(\S+)$')

    def test_02_init_weird_conf(self):
        ''' If we get weird things from a config file '''
        config = configparser.ConfigParser()
        config.add_section('failure')
        config.set('failure', 'fail_open', 'foo')
        config.add_section('sudo')
        config.set('sudo', 'sudo_users', 'bob')
        config.set('sudo', 'sudo_username_regexp', 'huh')
        with mock.patch.object(IAMVPNLibraryBase, '_ingest_config_from_file',
                               return_value=config):
            library = IAMVPNLibraryBase()
        self.assertEqual(library.fail_open, False)
        self.assertEqual(library.sudo_users, [])
        self.assertEqual(library.sudo_username_regexp, 'huh')

    def test_03_ingest_no_config_files(self):
        """ With no config files, get an empty ConfigParser """
        with mock.patch.object(IAMVPNLibraryBase, 'CONFIG_FILE_LOCATIONS', new=[]):
            result = self.library._ingest_config_from_file()
        self.assertIsInstance(result, configparser.ConfigParser,
                              'Did not create a config object')
        self.assertEqual(result.sections(), [],
                         'Should not have found any configfile sections.')

    def test_04_ingest_no_config_file(self):
        """ With all missing config files, get an empty ConfigParser """
        _not_a_real_file = '/tmp/no-such-file.txt'  # nosec hardcoded_tmp_directory
        with mock.patch.object(IAMVPNLibraryBase, 'CONFIG_FILE_LOCATIONS',
                               new=[_not_a_real_file]):
            result = self.library._ingest_config_from_file()
        self.assertIsInstance(result, configparser.ConfigParser,
                              'Did not create a config object')
        self.assertEqual(result.sections(), [],
                         'Should not have found any configfile sections.')

    def test_05_ingest_bad_config_file(self):
        """ With a bad config file, get an empty ConfigParser """
        with mock.patch.object(IAMVPNLibraryBase, 'CONFIG_FILE_LOCATIONS',
                               new=['test/context.py']):
            result = self.library._ingest_config_from_file()
        self.assertIsInstance(result, configparser.ConfigParser,
                              'Did not create a config object')
        self.assertEqual(result.sections(), [],
                         'Should not have found any configfile sections.')

    def test_06_ingest_config_from_file(self):
        """ With an actual config file, get a populated ConfigParser """
        _not_a_real_file = '/tmp/no-such-file.txt'  # nosec hardcoded_tmp_directory
        test_reading_file = '/tmp/test-reader.txt'  # nosec hardcoded_tmp_directory
        with open(test_reading_file, 'w', encoding='utf-8') as filepointer:
            filepointer.write('[aa]\nbb = cc\n')
        filepointer.close()
        with mock.patch.object(IAMVPNLibraryBase, 'CONFIG_FILE_LOCATIONS',
                               new=[_not_a_real_file, test_reading_file]):
            result = self.library._ingest_config_from_file()
        os.remove(test_reading_file)
        self.assertIsInstance(result, configparser.ConfigParser,
                              'Did not create a config object')
        self.assertEqual(result.sections(), ['aa'],
                         'Should have found one configfile section.')
        self.assertEqual(result.options('aa'), ['bb'],
                         'Should have found one option.')
        self.assertEqual(result.get('aa', 'bb'), 'cc',
                         'Should have read a correct value.')

    def test_07_read_item_config_good(self):
        """ Read from a config file and get what we expect """
        with mock.patch.object(self.library.configfile, 'get', return_value='cc'):
            result = self.library.read_item_from_config(section='testing', key='normal_user',
                                                        default='foo')
        self.assertEqual(result, 'cc', 'Could not retrieve a proper value from a configfile')

    def test_08_read_item_config_bad(self):
        """ Read from a config file and get what we expect """
        with mock.patch.object(self.library.configfile, 'get',
                               side_effect=configparser.NoOptionError('option', 'section')):
            result = self.library.read_item_from_config(section='testing', key='normal_user',
                                                        default='foo')
        self.assertEqual(result, 'foo', 'Could not retrieve a default value from a configfile')

    def test_09_sudo_user_edge(self):
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

    def test_10_sudo_user_normal(self):
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
