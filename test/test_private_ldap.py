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
                      portstring='', description=''),
            'Simple IPv4 host parsing failed')
        self.assertEqual(
            self.library._split_vpn_acl_string('1.1.1.1/30'),
            ParsedACL(rule='', address=IPNetwork('1.1.1.1/30'),
                      portstring='', description=''),
            'Simple IPv4 CIDR parsing failed')
        self.assertEqual(
            self.library._split_vpn_acl_string('1.1.1.1:443'),
            ParsedACL(rule='', address=IPNetwork('1.1.1.1/32'),
                      portstring='443', description=''),
            'IPv4 host:port parsing failed')
        self.assertEqual(
            self.library._split_vpn_acl_string('dead::beef'),
            ParsedACL(rule='', address=IPNetwork('dead::beef/128'),
                      portstring='', description=''),
            'Simple abbreviated IPv6 host parsing failed')
        self.assertEqual(
            self.library._split_vpn_acl_string(
                'fdf2:c3cc:8c71:c263:dead:beef:dead:beef'),
            ParsedACL(rule='',
                      address=IPNetwork(
                          'fdf2:c3cc:8c71:c263:dead:beef:dead:beef/128'),
                      portstring='', description=''),
            'Simple nonabbreviated IPv6 host parsing failed')
        self.assertEqual(
            self.library._split_vpn_acl_string('dead::beef/64'),
            ParsedACL(rule='', address=IPNetwork('dead::beef/64'),
                      portstring='', description=''),
            'Simple IPv6 CIDR parsing failed')
        self.assertEqual(
            self.library._split_vpn_acl_string('[dead::beef]:443'),
            ParsedACL(rule='', address=IPNetwork('dead::beef/128'),
                      portstring='443', description=''),
            'IPv6 host:port parsing failed')
        with self.assertRaises(netaddr.core.AddrFormatError):
            # Bogus IPv4 address:port must be fatal
            self.library._split_vpn_acl_string('1.1.1.1111:443')
        with self.assertRaises(netaddr.core.AddrFormatError):
            # Bogus IPv4 address must be fatal
            self.library._split_vpn_acl_string('1.1.1.1111')

    def test_get_all_enabled_users(self):
        """
            Testing that we get back a reasonably sized set of user DNs
        """
        result = self.library._get_all_enabled_users()
        self.assertIsInstance(result, set,
                              'Must return a set')
        # CAUTION!  this verifies that it has 100 at test time.
        # Keep in mind what will happen if this happens at RUN time.
        self.assertGreater(len(result), 100,
                           'We expect a sizeable list of enabled users')
        self.assertRegexpMatches(
            result.pop(), ','+self.library.config['ldap_base']+'$',
            ('A random user from the enabled user set does not match '
             'the ldap base of the config.  Bad search?'))

    def test_get_acl_allowed_users(self):
        """
            Testing that we get back a reasonably sized set of user DNs
        """
        result = self.library._get_acl_allowed_users()
        self.assertIsInstance(result, set,
                              'Must return a set')
        # CAUTION!  this verifies that it has 100 at test time.
        # Keep in mind what will happen if this happens at RUN time.
        self.assertGreater(len(result), 100,
                           'We expect a sizeable list of allowed users')
        self.assertRegexpMatches(
            result.pop(), ','+self.library.config['ldap_base']+'$',
            ('A random user from the allowed user set does not match '
             'the ldap base of the config.  Bad search?'))

    def test_all_vpn_allowed_users(self):
        """
            Testing that we get back a reasonably sized set of user DNs
        """
        result = self.library._all_vpn_allowed_users()
        self.assertIsInstance(result, set,
                              'Must return a set')
        # CAUTION!  this verifies that it has 100 at test time.
        # Keep in mind what will happen if this happens at RUN time.
        self.assertGreater(len(result), 100,
                           'We expect a sizeable list of allowed users')
        self.assertRegexpMatches(
            result.pop(), ','+self.library.config['ldap_base']+'$',
            ('A random user from the allowed user set does not match '
             'the ldap base of the config.  Bad search?'))

    def test_fetch_vpn_acls_for_user(self):
        """
            Testing that we get back raw/ldap'ed acls for our test user.
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library._fetch_vpn_acls_for_user(self.normal_user)
        self.assertIsInstance(result, list,
                              'Must return a list')
        self.assertGreater(len(result), 5,
                           'If this failed, someone has very few acls.')
        # Having now verified we have a list, grab one:
        acl = result[0]
        # This should be an LDAP ACL, and that has a format,  This is an
        # exhaustive, painful check of that.  You'll either bomb early
        # because your code returned the wrong thing, or you'll wonder how
        # the LDAP format changed.  Most of this you don't need to stare at.
        self.assertIsInstance(acl, tuple,
                              'Did not get an LDAP ACL tuple')
        self.assertIsInstance(acl[0], str,
                              ('The supposed LDAP ACL tuple did not have '
                               'a DN string as arg 0'))
        self.assertIsInstance(acl[1], dict,
                              ('The supposed LDAP ACL tuple did not have '
                               'an attr dict as arg 1'))

        self.assertIn(self.library.config['ldap_vpn_acls_rdn_attribute'],
                      acl[1],
                      'The attr dict of the LDAP acl did not contain the RDN')
        _rdn = acl[1][self.library.config['ldap_vpn_acls_rdn_attribute']]
        self.assertIsInstance(_rdn, list,
                              ('The RDN in the attr dict of the '
                               'LDAP acl was not a list'))
        self.assertGreater(len(_rdn), 0,
                           ('The RDN in the attr dict of the '
                            'LDAP acl was empty'))
        self.assertIsInstance(_rdn[0], str,
                              ('The RDN in the attr dict of the '
                               'LDAP acl was not a string'))

        self.assertIn(self.library.config['ldap_vpn_acls_attribute_host'],
                      acl[1],
                      'The attr dict of the LDAP acl did not contain ACLs')
        _acl = acl[1][self.library.config['ldap_vpn_acls_attribute_host']]
        self.assertIsInstance(_acl, list,
                              ('The ACLs in the attr dict of the '
                               'LDAP acl was not a list'))
        self.assertGreater(len(_acl), 0,
                           ('The ACLs in the attr dict of the '
                            'LDAP acl was empty'))
        self.assertIsInstance(_rdn[0], str,
                              ('The ACLs in the attr dict of the '
                               'LDAP acl was not a string'))

    def test_sanitized_vpn_acls(self):
        """
            Testing that we get back acls that we've flattened into being a
            list of ParsedACLs
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library._sanitized_vpn_acls_for_user(self.normal_user)
        self.assertIsInstance(result, list,
                              'Did not return a list')
        self.assertGreater(len(result), 5,
                           'If this failed, someone has very few acls.')
        pacl = result[0]
        self.assertIsInstance(pacl, ParsedACL,
                              'Did not return a list of ParsedACLs')
        # rule can be empty
        self.assertIsInstance(pacl.rule, str,
                              'The ParsedACL rule was not a string')
        # address is an object and must be there
        self.assertIsInstance(pacl.address, IPNetwork,
                              'The ParsedACL address was not an IPNetwork')
        self.assertGreaterEqual(pacl.address.size, 1,
                                'The ParsedACL address did not have a size?')
        # portstring can be empty
        self.assertIsInstance(pacl.portstring, str,
                              'The ParsedACL portstring was not a string')
        # description can be empty
        self.assertIsInstance(pacl.description, str,
                              'The ParsedACL description was not a string')

    def test_vpn_mfa_exempt_users(self):
        """
            Testing that we get the set of user DNs who are exempt from
            having to MFA
        """
        result = self.library._vpn_mfa_exempt_users()
        self.assertIsInstance(result, set,
                              'Must return a set')
        self.assertGreater(
            len(result), 0,
            ('If this failed, check the group size. '
             "It should be small-ish, but if it's zero that's weird."))
        self.assertLess(
            len(result), 10,
            ('If this failed, check the group size. '
             'It should be small-ish, but this test may be too small.'))
        self.assertRegexpMatches(
            result.pop(), ','+self.library.config['ldap_base']+'$',
            ('A random user from the set does not match '
             'the ldap base of the config.  Bad search?'))

    def test_get_user_dn_by_username(self):
        """
            Testing that can turn an email address into a user's DN
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library._get_user_dn_by_username(self.normal_user)
        self.assertIsInstance(result, str,
                              'search for username must return a DN string')
        self.assertRegexpMatches(
            result, ','+self.library.config['ldap_base']+'$',
            ('A random user from the set does not match '
             'the ldap base of the config.  Bad search?'))

if __name__ == "__main__":
    unittest.main()
