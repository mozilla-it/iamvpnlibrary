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
        self.assertIsInstance(result, bool)
        self.assertTrue(result)
        if self.bad_user is None:
            self.skipTest('Must provide a .bad_user to test')
        result = self.library.user_allowed_to_vpn(self.bad_user)
        self.assertIsInstance(result, bool)
        self.assertFalse(result)

    def test_get_allowed_vpn_ips(self):
        """
            This test seeks to verify that a user has a valid set
            of IP addresses for them to get to.
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library.get_allowed_vpn_ips(self.normal_user)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 5,
                           'If this failed, someone has very few acls.')
        self.assertIsInstance(result[0], str)

    def test_get_allowed_vpn_acls(self):
        """
            This test seeks to verify that a user has a valid set
            of IP addresses + ports for them to get to.
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library.get_allowed_vpn_acls(self.normal_user)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 5,
                           'If this failed, someone has very few acls.')
        self.assertIsInstance(result[0], ParsedACL)
        self.assertIsInstance(result[0].address, IPNetwork)
        self.assertIsInstance(result[0].portstring, str)
        self.assertIsInstance(result[0].description, str)

    def test_does_user_require_vpn_mfa(self):
        """
            This test seeks to verify that a user connecting to VPN
            must use MFA.
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        result = self.library.does_user_require_vpn_mfa(self.normal_user)
        self.assertIsInstance(result, bool)
        self.assertTrue(result)
        if self.bad_user is None:
            self.skipTest('Must provide a .bad_user to test')
        result = self.library.does_user_require_vpn_mfa(self.bad_user)
        self.assertIsInstance(result, bool)
        self.assertTrue(result)

    def test_non_mfa_vpn_authentication(self):
        """
            This test seeks to verify that a user who does not use
            MFA can authenticate.
        """
        if self.normal_user is None:
            self.skipTest('Must provide a .normal_user to test')
        self.assertFalse(
            self.library.non_mfa_vpn_authentication(
                self.normal_user, 'not_my_password'))
        if self.normal_user_password is None:
            self.skipTest('Must provide a .normal_user_password to test')
        self.assertTrue(
            self.library.non_mfa_vpn_authentication(
                self.normal_user, self.normal_user_password))


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
