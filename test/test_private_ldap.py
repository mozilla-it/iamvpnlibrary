#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
""" LDAP unit test script """
# This test file is all about calling protected methods on the ldap
# file, so, we tell pylint that we're cool with it:
# pylint: disable=protected-access

import unittest
import sys
import netaddr
from netaddr import IPNetwork
import iamvpnlibrary.iamvpnldap
from iamvpnlibrary.iamvpnbase import ParsedACL
sys.dont_write_bytecode = True


class TestLDAPFunctions(unittest.TestCase):
    """
        These are intended to exercise primarily internal functions of LDAP.
        We call the public-facing functions in the test suite, also, which
        essentially means redundant testing, but in case we have a parallel
        suite to LDAP we want to make sure we don't break this when touching
        some other area.
    """
    def setUp(self):
        """ Preparing test rig """
        self.library = iamvpnlibrary.iamvpnldap.IAMVPNLibraryLDAP()
        # This effectively tests init, _validate_config_file,
        # and _create_ldap_connection.  You're not going anywhere
        # much without those.
        self.normal_user = self.library.read_item_from_config(
            section='testing', key='normal_user', default=None)

    def test_acl_parsing(self):
        """
            This tests for various cases of ACL strings that we get from
            the ldap server, and verifies that they break into chunks that
            we expect.
        """
        self.assertEqual(
            self.library._split_vpn_acl_string('1.1.1.1'),
            ParsedACL(rule='', address=IPNetwork('1.1.1.1/32'),
                      portstring='', description=''))
        self.assertEqual(
            self.library._split_vpn_acl_string('1.1.1.1/30'),
            ParsedACL(rule='', address=IPNetwork('1.1.1.1/30'),
                      portstring='', description=''))
        self.assertEqual(
            self.library._split_vpn_acl_string('1.1.1.1:443'),
            ParsedACL(rule='', address=IPNetwork('1.1.1.1/32'),
                      portstring='443', description=''))
        self.assertEqual(
            self.library._split_vpn_acl_string('dead::beef'),
            ParsedACL(rule='', address=IPNetwork('dead::beef/128'),
                      portstring='', description=''))
        self.assertEqual(
            self.library._split_vpn_acl_string('dead::beef/64'),
            ParsedACL(rule='', address=IPNetwork('dead::beef/64'),
                      portstring='', description=''))
        self.assertEqual(
            self.library._split_vpn_acl_string('[dead::beef]:443'),
            ParsedACL(rule='', address=IPNetwork('dead::beef/128'),
                      portstring='443', description=''))
        with self.assertRaises(netaddr.core.AddrFormatError):
            self.library._split_vpn_acl_string('1.1.1.1111:443')
        with self.assertRaises(netaddr.core.AddrFormatError):
            self.library._split_vpn_acl_string('1.1.1.1111')

    def test_get_all_enabled_users(self):
        """
            Testing that we get back a reasonably sized set of user DNs
        """
        result = self.library._get_all_enabled_users()
        self.assertIsInstance(result, set)
        self.assertGreater(len(result), 500)
        self.assertRegexpMatches(
            result.pop(), ','+self.library.config['ldap_base']+'$')

    def test_get_acl_allowed_users(self):
        """
            Testing that we get back a reasonably sized set of user DNs
        """
        result = self.library._get_acl_allowed_users()
        self.assertIsInstance(result, set)
        self.assertGreater(len(result), 500)
        self.assertRegexpMatches(
            result.pop(), ','+self.library.config['ldap_base']+'$')

    def test_all_vpn_allowed_users(self):
        """
            Testing that we get back a reasonably sized set of user DNs
        """
        result = self.library._all_vpn_allowed_users()
        self.assertIsInstance(result, set)
        self.assertGreater(len(result), 500)
        self.assertRegexpMatches(
            result.pop(), ','+self.library.config['ldap_base']+'$')

    def test_fetch_vpn_acls_for_user(self):
        """
            Testing that we get back raw/ldap'ed acls for our test user.
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library._fetch_vpn_acls_for_user(self.normal_user)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 5,
                           'If this failed, someone has very few acls.')
        acl = result[0]
        self.assertIsInstance(acl, tuple)
        self.assertIsInstance(acl[0], str)
        self.assertIsInstance(acl[1], dict)
        self.assertIsInstance(acl[1][self.library.config[
            'ldap_vpn_acls_rdn_attribute']], list)
        self.assertIsInstance(acl[1][self.library.config[
            'ldap_vpn_acls_rdn_attribute']][0], str)
        self.assertIsInstance(acl[1][self.library.config[
            'ldap_vpn_acls_attribute_host']], list)
        self.assertIsInstance(acl[1][self.library.config[
            'ldap_vpn_acls_attribute_host']][0], str)

    def test_sanitized_vpn_acls(self):
        """
            Testing that we get back acls that we've flattened into being a
            list of ParsedACLs
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library._sanitized_vpn_acls_for_user(self.normal_user)
        self.assertIsInstance(result, list)
        pacl = result[0]
        self.assertIsInstance(pacl, ParsedACL)
        self.assertIsInstance(pacl.address, IPNetwork)
        self.assertIsInstance(pacl.portstring, str)
        self.assertIsInstance(pacl.description, str)

    def test_vpn_mfa_exempt_users(self):
        """
            Testing that we get the set of user DNs who are exempt from
            having to MFA
        """
        result = self.library._vpn_mfa_exempt_users()
        self.assertIsInstance(result, set)
        self.assertGreater(
            len(result), 0,
            'If this failed, check the group size.'
            "It should be small-ish, but if it's zero that's weird.")
        self.assertLess(
            len(result), 10,
            'If this failed, check the group size.'
            'It should be small-ish, but this test may be too small.')
        self.assertRegexpMatches(
            result.pop(), ','+self.library.config['ldap_base']+'$')

    def test_get_user_dn_by_username(self):
        """
            Testing that can turn an email address into a user's DN
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library._get_user_dn_by_username(self.normal_user)
        self.assertIsInstance(result, str)
        self.assertRegexpMatches(
            result, ','+self.library.config['ldap_base']+'$')

if __name__ == "__main__":
    unittest.main()
