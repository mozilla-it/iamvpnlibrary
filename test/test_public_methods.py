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
        'whatever plumbing' we default to, when the server is up.

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

    # user_allowed_to_vpn 01
    def test_01_serverup_good(self):
        """
            This test seeks to verify that a user is allowed to connect
            to the VPN
        """
        if self.normal_user is None:  # pragma: no cover
            self.skipTest('Must provide a .normal_user to test')
        result = self.library.user_allowed_to_vpn(self.normal_user)
        self.assertIsInstance(result, bool, 'Check must return a bool')
        self.assertTrue(result, 'good user must return True')

    def test_01_serverup_bad(self):
        """
            This test seeks to verify that a bad user is never allowed
            to connect to the VPN
        """
        with self.assertRaises(TypeError):
            self.library.user_allowed_to_vpn([])
        if self.bad_user is None:  # pragma: no cover
            self.skipTest('Must provide a .bad_user to test')
        result = self.library.user_allowed_to_vpn(self.bad_user)
        self.assertIsInstance(result, bool, 'Check must return a bool')
        self.assertFalse(result, 'bad user must return False')

    # get_allowed_vpn_ips 02
    def test_02_serverup_good(self):
        """
            This test seeks to verify that a user has a valid set
            of IP addresses for them to get to.
        """
        if self.normal_user is None:  # pragma: no cover
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

    def test_02_serverup_bad(self):
        """
            This test seeks to verify that a bad user has a valid set
            of IP addresses for them to get to.
        """
        with self.assertRaises(TypeError):
            self.library.get_allowed_vpn_ips([])
        if self.bad_user is None:  # pragma: no cover
            self.skipTest('Must provide a .bad_user to test')
        result = self.library.get_allowed_vpn_ips(self.bad_user)
        self.assertIsInstance(result, list, 'Check must return a list')
        self.assertEqual(len(result), 0,
                         'A bad user should have no allowed IPs')

    # get_allowed_vpn_acls 03
    def test_03_serverup_good(self):
        """
            This test seeks to verify that a user has a valid set
            of IP addresses + ports for them to get to.
        """
        if self.normal_user is None:  # pragma: no cover
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

    def test_03_serverup_bad(self):
        """
            This test seeks to verify that a bad user has a no IPs/ports
        """
        with self.assertRaises(TypeError):
            self.library.get_allowed_vpn_acls([])
        if self.bad_user is None:  # pragma: no cover
            self.skipTest('Must provide a .bad_user to test')
        result = self.library.get_allowed_vpn_acls(self.bad_user)
        self.assertIsInstance(result, list,
                              'Did not return a list')
        self.assertEqual(len(result), 0,
                         'A bad user should have no allowed IPs')

    # does_user_require_vpn_mfa 04
    def test_04_serverup_good(self):
        """
            This test seeks to verify that a user connecting to VPN
            must use MFA.
        """
        if self.normal_user is None:  # pragma: no cover
            self.skipTest('Must provide a .normal_user to test')
        result = self.library.does_user_require_vpn_mfa(self.normal_user)
        self.assertIsInstance(result, bool, 'Check must return a bool')
        self.assertTrue(result, 'good user must return True')
        # IMPROVEME - might want to list one of the excepted users

    def test_04_serverup_bad(self):
        """
            This test seeks to verify that a user connecting to VPN
            must use MFA.
        """
        with self.assertRaises(TypeError):
            self.library.does_user_require_vpn_mfa([])
        if self.bad_user is None:  # pragma: no cover
            self.skipTest('Must provide a .bad_user to test')
        result = self.library.does_user_require_vpn_mfa(self.bad_user)
        self.assertIsInstance(result, bool, 'Check must return a bool')
        # Weird logic reminder, a fake user must be made to MFA.
        self.assertTrue(result, 'bad user must return True')

    # non_mfa_vpn_authentication 05
    def test_05_serverup_good(self):
        """
            This test seeks to verify that a user who does not use
            MFA can authenticate.
        """
        if self.normal_user is None:  # pragma: no cover
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

    def test_05_serverup_bad(self):
        """
            This test seeks to verify that a user who does not exist
            is given a hard time.
        """
        with self.assertRaises(TypeError):
            self.library.non_mfa_vpn_authentication('foo', [])
        with self.assertRaises(TypeError):
            self.library.non_mfa_vpn_authentication([], 'foo')
        if self.bad_user is None:  # pragma: no cover
            self.skipTest('Must provide a .bad_user to test')
        result = self.library.non_mfa_vpn_authentication(
            self.normal_user, 'user_obviously_has_no_pass')
        self.assertIsInstance(result, bool, 'Check must return a bool')
        # Someone who doesn't exist must be false, to indicate they
        # are MFA-required
        self.assertFalse(result, 'A bad user must return False')


class PublicTestsServerDownMixin(object):
    """
        These are intended to exercise the public methods
        when the server is down

        The name of the class must end in 'MixIn' (any case) to pass pylint
    """
    # user_allowed_to_vpn 01
    def test_01_serverdown(self):
        """
            This test seeks to verify that, when the server is down,
            a user follows the fail_open guidelines
        """
        for fail_open_mode in [True, False]:
            self.library.fail_open = fail_open_mode
            with self.assertRaises(TypeError):
                self.library.user_allowed_to_vpn([])
            result = self.library.user_allowed_to_vpn('dummy_user')
            self.assertIsInstance(result, bool, 'Check must return a bool')
            self.assertEqual(result, fail_open_mode,
                             ('user_allowed_to_vpn must follow '
                              'the value of fail_open'))

    # get_allowed_vpn_ips 02
    def test_02_serverdown(self):
        """
            This test seeks to verify that, when the server is down,
            a user gets no IPs.
        """
        for fail_open_mode in [True, False]:
            self.library.fail_open = fail_open_mode
            with self.assertRaises(TypeError):
                self.library.get_allowed_vpn_ips([])
            result = self.library.get_allowed_vpn_ips('dummy_user')
            self.assertIsInstance(result, list, 'Check must return a list')
            self.assertEqual(len(result), 0,
                             'No allowed IPs when the server is off')

    # get_allowed_vpn_acls 03
    def test_03_serverdown(self):
        """
            This test seeks to verify that, when the server is down,
            a user gets no ACLs.
        """
        for fail_open_mode in [True, False]:
            self.library.fail_open = fail_open_mode
            result = self.library.get_allowed_vpn_acls('dummy_user')
            self.assertIsInstance(result, list,
                                  'Did not return a list')
            self.assertEqual(len(result), 0,
                             'No allowed ACLs when the server is off')

    # does_user_require_vpn_mfa 04
    def test_04_serverdown(self):
        """
            This test seeks to verify that, when the server is down,
            a user's MFA requirements follow fail_open reqs.
        """
        for fail_open_mode in [True, False]:
            self.library.fail_open = fail_open_mode
            with self.assertRaises(TypeError):
                self.library.does_user_require_vpn_mfa([])
            result = self.library.does_user_require_vpn_mfa('dummy_user')
            self.assertIsInstance(result, bool, 'Check must return a bool')
            # Weird logic reminder, a fake user must be made to MFA.
            self.assertEqual(result, fail_open_mode,
                             ('does_user_require_vpn_mfa must track '
                              'to fail_open'))

    # non_mfa_vpn_authentication 05
    def test_05_serverdown(self):
        """
            This test seeks to verify that, when the server is down,
            a user's MFA requirements follow fail_open reqs.
        """
        for fail_open_mode in [True, False]:
            self.library.fail_open = fail_open_mode
            with self.assertRaises(TypeError):
                self.library.non_mfa_vpn_authentication('foo', [])
            with self.assertRaises(TypeError):
                self.library.non_mfa_vpn_authentication([], 'foo')
            result = self.library.non_mfa_vpn_authentication(
                'dummy_user', 'user_obviously_has_no_pass')
            self.assertIsInstance(result, bool, 'Check must return a bool')
            self.assertEqual(result, fail_open_mode,
                             ('non_mfa_vpn_authentication must track '
                              'to fail_open'))


# When there's a future authentication class, you'll want this:
# class TestPublicFunctionsFUTURE(PublicTestsMixin, unittest.TestCase):
#     """
#         Test the public methods by calling into a future library
#     """
#     def setUp(self):
#         """ Prepare test rig """
#         self.library = iamvpnlibrary.iamvpnldap.IAMVPNLibraryFUTURE()
#         self.core_setup()


class TestPubFuncsLDAPup(PublicTestsMixin, unittest.TestCase):
    """
        Test the public methods by calling into the LDAP library
    """
    def setUp(self):
        """ Prepare test rig """
        try:
            # This should never fail.  But if it does, I have no
            # idea why it would, so, catch all exceptions deliberately.
            # Keep in mind that we don't want to detail LDAP-specific
            # reasons here.  "It failed" is enough for testing.
            self.library = iamvpnlibrary.iamvpnldap.IAMVPNLibraryLDAP()
        except Exception as err:  # pragma: no cover  pylint: disable=broad-except
            self.fail(err)
        self.core_setup()


class TestPubFuncsLDAPdown(PublicTestsServerDownMixin, unittest.TestCase):
    """
        Test the public methods by calling into the LDAP library,
        but disconnect from the server first so there's no server to talk to.

        Note that we test this as the LDAP method only, not the abstracted
        method-doesn't-matter way.
    """
    def setUp(self):
        """ Prepare test rig """
        try:
            # This should never fail.  But if it does, I have no
            # idea why it would, so, catch all exceptions deliberately.
            # Keep in mind that we don't want to detail LDAP-specific
            # reasons here.  "It failed" is enough for testing.
            self.library = iamvpnlibrary.iamvpnldap.IAMVPNLibraryLDAP()
        except Exception as err:  # pragma: no cover  pylint: disable=broad-except
            self.fail(err)
        self.library.conn.unbind_s()


class TestPubFuncsMAIN(PublicTestsMixin, unittest.TestCase):
    """
        Test the public methods by calling into the main/exposed library
    """
    def setUp(self):
        """ Prepare test rig """
        self.library = iamvpnlibrary.IAMVPNLibrary()
        self.core_setup()
