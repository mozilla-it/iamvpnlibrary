#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
""" LDAP unit test script """
# This test file is all about calling protected methods on the ldap
# file, so, we tell pylint that we're cool with it:

import unittest
import configparser
import test.context  # pylint: disable=unused-import
import netaddr
from netaddr import IPNetwork
import mock
import ldap
from iamvpnlibrary.iamvpnbase import IAMVPNLibraryBase, ParsedACL
from iamvpnlibrary.iamvpnldap import IAMVPNLibraryLDAP


class TestLDAPSpinup(unittest.TestCase):
    """
        These are intended to make sure IAMVPNLibraryLDAP initializes.
        We'll worry about actually using it in another test class.
    """
    def setUp(self):
        """ Preparing test rig """
        config = configparser.ConfigParser()
        config.add_section('ldap-bind')
        config.set('ldap-bind', 'url', 'url-string')
        config.set('ldap-bind', 'bind_dn', 'bind-user')
        config.set('ldap-bind', 'bind_password', 'hunter2')
        config.set('ldap-bind', 'base', 'dc=org')
        config.set('ldap-bind', 'groups_base', 'cn=groups,dc=org')
        config.add_section('ldap-schema-users')
        config.set('ldap-schema-users', 'mail_attribute', 'mail')
        config.set('ldap-schema-users', 'enabled_user_filter', '(cn=*)')
        config.add_section('ldap-schema-vpn-acls')
        config.set('ldap-schema-vpn-acls', 'rdn_attribute', 'cn')
        config.set('ldap-schema-vpn-acls', 'attribute_user', 'member')
        config.set('ldap-schema-vpn-acls', 'attribute_host', 'ipHostNumber')
        config.set('ldap-schema-vpn-acls', 'all_acls_filter', '(cn=acls)')
        config.set('ldap-schema-vpn-acls', 'minimum_group_filter', '(cn=default)')
        config.set('ldap-schema-vpn-acls', 'mfa_exempt_group_filter', '(cn=nope)')
        self.config = config

    def test_21_acl_parsing(self):
        """
            This tests for various cases of ACL strings that we get from
            the ldap server, and verifies that they break into chunks that
            we expect.
        """
        with self.assertRaises(TypeError):
            IAMVPNLibraryLDAP._split_vpn_acl_string([])
        self.assertEqual(
            IAMVPNLibraryLDAP._split_vpn_acl_string('1.1.1.1'),
            ParsedACL(rule='', address=IPNetwork('1.1.1.1/32'),
                      portstring='', description=''),
            'Simple IPv4 host parsing failed')
        self.assertEqual(
            IAMVPNLibraryLDAP._split_vpn_acl_string('1.1.1.1 # a test'),
            ParsedACL(rule='', address=IPNetwork('1.1.1.1/32'),
                      portstring='', description='a test'),
            'Simple commented IPv4 host parsing failed')
        self.assertEqual(
            IAMVPNLibraryLDAP._split_vpn_acl_string('1.1.1.1/30'),
            ParsedACL(rule='', address=IPNetwork('1.1.1.1/30'),
                      portstring='', description=''),
            'Simple IPv4 CIDR parsing failed')
        self.assertEqual(
            IAMVPNLibraryLDAP._split_vpn_acl_string('1.1.1.1:443'),
            ParsedACL(rule='', address=IPNetwork('1.1.1.1/32'),
                      portstring='443', description=''),
            'IPv4 host:port parsing failed')
        self.assertEqual(
            IAMVPNLibraryLDAP._split_vpn_acl_string('dead::beef'),
            ParsedACL(rule='', address=IPNetwork('dead::beef/128'),
                      portstring='', description=''),
            'Simple abbreviated IPv6 host parsing failed')
        self.assertEqual(
            IAMVPNLibraryLDAP._split_vpn_acl_string(
                'fdf2:c3cc:8c71:c263:dead:beef:dead:beef'),
            ParsedACL(rule='',
                      address=IPNetwork(
                          'fdf2:c3cc:8c71:c263:dead:beef:dead:beef/128'),
                      portstring='', description=''),
            'Simple nonabbreviated IPv6 host parsing failed')
        self.assertEqual(
            IAMVPNLibraryLDAP._split_vpn_acl_string('dead::beef/64'),
            ParsedACL(rule='', address=IPNetwork('dead::beef/64'),
                      portstring='', description=''),
            'Simple IPv6 CIDR parsing failed')
        self.assertEqual(
            IAMVPNLibraryLDAP._split_vpn_acl_string('[dead::beef]:443'),
            ParsedACL(rule='', address=IPNetwork('dead::beef/128'),
                      portstring='443', description=''),
            'IPv6 host:port parsing failed')
        self.assertEqual(
            IAMVPNLibraryLDAP._split_vpn_acl_string('hostname.domain.org'),
            ParsedACL(rule='', address='hostname.domain.org',
                      portstring='', description='hostname.domain.org'),
            'hostname parsing failed')
        with self.assertRaises(netaddr.core.AddrFormatError):
            # Bogus IPv4 address:port must be fatal
            IAMVPNLibraryLDAP._split_vpn_acl_string('1.1.1.1111:443')
        with self.assertRaises(netaddr.core.AddrFormatError):
            # Bogus IPv4 address must be fatal
            IAMVPNLibraryLDAP._split_vpn_acl_string('1.1.1.1111')

    def test_30_ldap_init(self):
        ''' A "does this call everything?" test '''
        with mock.patch.object(IAMVPNLibraryBase, '__init__') as mock_base, \
                mock.patch.object(IAMVPNLibraryLDAP, '_validate_config_file') as mock_valid, \
                mock.patch.object(IAMVPNLibraryLDAP, '_create_ldap_connection') as mock_ldap:
            IAMVPNLibraryLDAP()
        mock_base.assert_called_once_with()
        mock_valid.assert_called_once_with()
        mock_ldap.assert_called_once()

        with mock.patch.object(IAMVPNLibraryBase, '__init__') as mock_base, \
                mock.patch.object(IAMVPNLibraryLDAP, '_validate_config_file') as mock_valid, \
                mock.patch.object(IAMVPNLibraryLDAP, '_create_ldap_connection',
                                  side_effect=ldap.LDAPError) as mock_ldap, \
                self.assertRaises(RuntimeError):
            IAMVPNLibraryLDAP()
        mock_base.assert_called_once_with()
        mock_valid.assert_called_once_with()
        mock_ldap.assert_called_once()

    def test_31_validate_config_good(self):
        ''' Test that we get a good run through _validate_config_file '''
        with mock.patch.object(IAMVPNLibraryBase, '__init__'), \
                mock.patch.object(IAMVPNLibraryLDAP, '_validate_config_file'), \
                mock.patch.object(IAMVPNLibraryLDAP, '_create_ldap_connection'):
            library = IAMVPNLibraryLDAP()
        library.configfile = self.config
        result = library._validate_config_file()
        self.assertIsInstance(result, dict)

    def test_32_validate_config_bad(self):
        ''' Test that we get a bad run through _validate_config_file '''
        with mock.patch.object(IAMVPNLibraryBase, '__init__'), \
                mock.patch.object(IAMVPNLibraryLDAP, '_validate_config_file'), \
                mock.patch.object(IAMVPNLibraryLDAP, '_create_ldap_connection'):
            library = IAMVPNLibraryLDAP()
        library.configfile = self.config
        library.configfile.remove_option('ldap-bind', 'bind_dn')
        with self.assertRaises(ValueError):
            library._validate_config_file()

    def test_33_init_mock_good(self):
        ''' Test that init is mocked out. '''
        with mock.patch.object(IAMVPNLibraryBase, '_ingest_config_from_file',
                               return_value=self.config), \
                mock.patch.object(IAMVPNLibraryLDAP, '_create_ldap_connection',
                                  return_value='something2') as mock_ldap:
            result = IAMVPNLibraryLDAP()
        mock_ldap.assert_called_once()
        self.assertEqual(result.conn, 'something2')

    def test_34_init_mock_bad(self):
        ''' Test that init fails when ldap dies. '''
        with mock.patch.object(IAMVPNLibraryBase, '_ingest_config_from_file',
                               return_value=self.config), \
                mock.patch.object(IAMVPNLibraryLDAP, '_create_ldap_connection',
                                  side_effect=ldap.LDAPError('err')), \
                self.assertRaises(RuntimeError):
            IAMVPNLibraryLDAP()

    def test_36_mock_ldap_connect(self):
        ''' Test setting up an LDAP connection.  We'll do it for real in another function '''
        with self.assertRaises(ldap.INVALID_CREDENTIALS):
            IAMVPNLibraryLDAP._create_ldap_connection('someurl', 'someuser', None)
        with self.assertRaises(ldap.LDAPError):
            IAMVPNLibraryLDAP._create_ldap_connection('someurl', 'someuser', 'somepass')

        mock_ldap = mock.Mock()
        mock_ldap.start_tls_s.return_value = None
        mock_ldap.simple_bind_s.return_value = None
        with mock.patch.object(ldap, 'initialize', return_value=mock_ldap):
            conn = IAMVPNLibraryLDAP._create_ldap_connection('someurl', 'someuser', 'somepass')
        mock_ldap.start_tls_s.assert_called_once_with()
        mock_ldap.simple_bind_s.assert_called_once_with('someuser', 'somepass')
        self.assertIsInstance(conn, mock.Mock)
