#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
"""
    Public method unit test script.
"""

import unittest
import sys
import netaddr
from netaddr import IPNetwork
import iamvpnlibrary
from iamvpnlibrary.iamvpnbase import ParsedACL
sys.dont_write_bytecode = True


class PublicTestsMixin(object):
    """
        These are intended to exercise the public methods via
        'whatever plumbing' we default to.

        IF THERE IS ANY MENTION OF LDAP IN THIS SUITE, EVEN AN EXCEPTION,
        YOU HAVE WRITTEN A BAD TEST.  USE NO LDAP IN HERE.  NOT DNs, NOTHING.

        The name of the class must end in 'MixIn' (any case) to pass pylint
    """
    def core_setup(self):
        """ Preparing test rig """
        self.normal_user = self.library.read_item_from_config(
            section='testing', key='normal_user', default=None)
        self.normal_user_password = self.library.read_item_from_config(
            section='testing', key='normal_user_password', default=None)
        self.bad_user = self.library.read_item_from_config(
            section='testing', key='bad_user', default=None)

    def test_user_allowed_to_vpn(self):
        """
            This test seeks to verify that a user is allowed to connect
            to the VPN
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library.user_allowed_to_vpn(self.normal_user)
        self.assertIsInstance(result, bool, 'Check must return a bool')
        self.assertTrue(result, 'good user must return True')
        if self.bad_user is None:
            self.skipTest('Must provide a .bad_user to test')
        result = self.library.user_allowed_to_vpn(self.bad_user)
        self.assertIsInstance(result, bool, 'Check must return a bool')
        self.assertFalse(result, 'bad user must return False')

    def test_get_allowed_vpn_ips(self):
        """
            This test seeks to verify that a user has a valid set
            of IP addresses for them to get to.
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library.get_allowed_vpn_ips(self.normal_user)
        self.assertIsInstance(result, list, 'Check must return a list')
        self.assertGreater(len(result), 5,
                           'If this failed, someone has very few acls.')
        addr = result[0]
        self.assertIsInstance(addr, str,
                              'Check did not return IP strings')
        try:
            # verify that we're returning parseable strings
            address = netaddr.ip.IPNetwork(addr)
        except netaddr.core.AddrFormatError:
            self.fail('Non network-address-string returned')
        self.assertGreaterEqual(address.size, 1,
                                'The address did not have a size?')

    def test_get_allowed_vpn_acls(self):
        """
            This test seeks to verify that a user has a valid set
            of IP addresses + ports for them to get to.
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library.get_allowed_vpn_acls(self.normal_user)
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

    def test_does_user_require_vpn_mfa(self):
        """
            This test seeks to verify that a user connecting to VPN
            must use MFA.
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library.does_user_require_vpn_mfa(self.normal_user)
        self.assertIsInstance(result, bool, 'Check must return a bool')
        self.assertTrue(result, 'good user must return True')
        # Weird logic reminder, a fake user must be made to MFA.
        if self.bad_user is None:
            self.skipTest('Must provide a .bad_user to test')
        result = self.library.does_user_require_vpn_mfa(self.bad_user)
        self.assertIsInstance(result, bool, 'Check must return a bool')
        self.assertTrue(result, 'bad user must return True')
        # IMPROVEME - might want to list one of the excepted users

    def test_non_mfa_vpn_auth_good(self):
        """
            This test seeks to verify that a user who does not use
            MFA can authenticate.
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library.non_mfa_vpn_authentication(
            self.normal_user, 'not_my_password')
        self.assertIsInstance(result, bool, 'Check must return a bool')
        self.assertFalse(result, 'A bad password must return False')
        if self.normal_user_password is None:
            self.skipTest('Must provide a .normal_user_password to test')
        result = self.library.non_mfa_vpn_authentication(
            self.normal_user, self.normal_user_password)
        self.assertIsInstance(result, bool, 'Check must return a bool')
        self.assertTrue(result, 'A good password must return True')

    def test_non_mfa_vpn_auth_bad(self):
        """
            This test seeks to verify that a user who does not exist
            is given a hard time.
        """
        if self.bad_user is None:
            self.skipTest('Must provide a .bad_user to test')
        result = self.library.non_mfa_vpn_authentication(
            self.normal_user, 'user_obviously_has_no_pass')
        self.assertIsInstance(result, bool, 'Check must return a bool')
        # Someone who doesn't exist must be false, to indicate they
        # are MFA-required
        self.assertFalse(result, 'A bad user must return False')

# When there's a future authentication class, you'll want this:
# class TestPublicFunctionsFUTURE(PublicTestsMixin, unittest.TestCase):
#     """
#         Test the public methods by calling into a future library
#     """
#     def setUp(self):
#         """ Prepare test rig """
#         self.library = iamvpnlibrary.iamvpnldap.IAMVPNLibraryFUTURE()
#         self.core_setup()


class TestPublicFunctionsLDAP(PublicTestsMixin, unittest.TestCase):
    """
        Test the public methods by calling into the LDAP library
    """
    def setUp(self):
        """ Prepare test rig """
        self.library = iamvpnlibrary.iamvpnldap.IAMVPNLibraryLDAP()
        self.core_setup()


class TestPublicFunctionsMAIN(PublicTestsMixin, unittest.TestCase):
    """
        Test the public methods by calling into the main/exposed library
    """
    def setUp(self):
        """ Prepare test rig """
        self.library = iamvpnlibrary.IAMVPNLibrary()
        self.core_setup()


if __name__ == "__main__":
    unittest.main()
