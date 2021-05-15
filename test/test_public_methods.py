#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
"""
    Public method unit test script.
"""

import unittest
import test.context  # pylint: disable=unused-import
import netaddr
from netaddr import IPNetwork
import mock
import ldap
import six
from iamvpnlibrary import IAMVPNLibrary
from iamvpnlibrary.iamvpnbase import ParsedACL
from iamvpnlibrary.iamvpnldap import IAMVPNLibraryLDAP


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
        self.assertIsInstance(addr, six.string_types,
                              'Check did not return IP strings')
        try:
            # verify that we're returning parseable strings
            address = netaddr.ip.IPNetwork(addr)
        except netaddr.core.AddrFormatError:  # pragma: no cover
            # since this is a live-data test we may never trigger this.
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
        self.assertIsInstance(pacl.rule, six.string_types,
                              'The ParsedACL rule was not a string')
        # address is an object and must be there
        self.assertIsInstance(pacl.address, IPNetwork,
                              'The ParsedACL address was not an IPNetwork')
        self.assertGreaterEqual(pacl.address.size, 1,
                                'The ParsedACL address did not have a size?')
        # portstring can be empty
        self.assertIsInstance(pacl.portstring, six.string_types,
                              'The ParsedACL portstring was not a string')
        # description can be empty
        self.assertIsInstance(pacl.description, six.string_types,
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
        if self.normal_user_password is None:  # pragma: no cover
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
            self.bad_user, 'user_obviously_has_no_pass')
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
            with mock.patch.object(self.library, 'is_online', return_value=False):
                self.assertEqual(self.library.user_allowed_to_vpn('x'), fail_open_mode)
            with mock.patch.object(self.library, 'is_online', return_value=True):
                with mock.patch.object(self.library, '_all_vpn_allowed_users',
                                       side_effect=ldap.SERVER_DOWN):
                    self.assertEqual(self.library.user_allowed_to_vpn('x'), fail_open_mode)
                with mock.patch.object(self.library, '_all_vpn_allowed_users',
                                       side_effect=ldap.BUSY):
                    self.assertEqual(self.library.user_allowed_to_vpn('x'), fail_open_mode)
            with mock.patch.object(self.library, 'is_online', return_value=True):
                with mock.patch.object(self.library, '_all_vpn_allowed_users',
                                       return_value=['a', 'b']):
                    with mock.patch.object(self.library, '_get_user_dn_by_username',
                                           return_value='a'):
                        self.assertEqual(self.library.user_allowed_to_vpn('x'), True)
                    with mock.patch.object(self.library, '_get_user_dn_by_username',
                                           return_value='z'):
                        self.assertEqual(self.library.user_allowed_to_vpn('x'), False)
                    with mock.patch.object(self.library, '_get_user_dn_by_username',
                                           side_effect=ldap.NO_SUCH_OBJECT):
                        self.assertEqual(self.library.user_allowed_to_vpn('x'), False)
                    with mock.patch.object(self.library, '_get_user_dn_by_username',
                                           side_effect=ldap.SERVER_DOWN):
                        self.assertEqual(self.library.user_allowed_to_vpn('x'), fail_open_mode)
                    with mock.patch.object(self.library, '_get_user_dn_by_username',
                                           side_effect=ldap.BUSY):
                        self.assertEqual(self.library.user_allowed_to_vpn('x'), fail_open_mode)

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
            with mock.patch.object(self.library, 'is_online', return_value=False):
                self.assertEqual(self.library.get_allowed_vpn_ips('x'), [])
            with mock.patch.object(self.library, 'is_online', return_value=True):
                cidr_a = '192.168.20.0/30'
                cidr_b = '10.8.0.0/16'
                pacl_a = ParsedACL(rule='a', address=netaddr.ip.IPNetwork(cidr_a),
                                   portstring='', description='acl a')
                pacl_b = ParsedACL(rule='a', address=netaddr.ip.IPNetwork(cidr_b),
                                   portstring='', description='acl b')
                with mock.patch.object(self.library, 'get_allowed_vpn_acls',
                                       return_value=[pacl_a, pacl_b]):
                    result = self.library.get_allowed_vpn_ips('dummy_user')
                    self.assertEqual(result, [cidr_a, cidr_b])

    # get_allowed_vpn_acls 03
    def test_03_serverdown(self):
        """
            This test seeks to verify that, when the server is down,
            a user gets no ACLs.
        """
        for fail_open_mode in [True, False]:
            self.library.fail_open = fail_open_mode
            with self.assertRaises(TypeError):
                self.library.get_allowed_vpn_acls([])
            with mock.patch.object(self.library, 'is_online', return_value=False):
                self.assertEqual(self.library.get_allowed_vpn_acls('x'), [])
            with mock.patch.object(self.library, 'is_online', return_value=True):
                with mock.patch.object(self.library, '_sanitized_vpn_acls_for_user',
                                       side_effect=ldap.NO_SUCH_OBJECT):
                    self.assertEqual(self.library.get_allowed_vpn_acls('x'), [])
                with mock.patch.object(self.library, '_sanitized_vpn_acls_for_user',
                                       side_effect=ldap.SERVER_DOWN):
                    self.assertEqual(self.library.get_allowed_vpn_acls('x'), [])
                with mock.patch.object(self.library, '_sanitized_vpn_acls_for_user',
                                       side_effect=ldap.BUSY):
                    self.assertEqual(self.library.get_allowed_vpn_acls('x'), [])
                with mock.patch.object(self.library, '_sanitized_vpn_acls_for_user',
                                       return_value=['a', 'b']):
                    self.assertEqual(self.library.get_allowed_vpn_acls('x'), ['a', 'b'])

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
            with mock.patch.object(self.library, 'is_online', return_value=False):
                self.assertEqual(self.library.does_user_require_vpn_mfa('x'), fail_open_mode)
            with mock.patch.object(self.library, 'is_online', return_value=True):
                with mock.patch.object(self.library, '_vpn_mfa_exempt_users',
                                       return_value=['a', 'b']):
                    with mock.patch.object(self.library, '_get_user_dn_by_username',
                                           return_value='a'):
                        self.assertEqual(self.library.does_user_require_vpn_mfa('x'), False)
                    with mock.patch.object(self.library, '_get_user_dn_by_username',
                                           return_value='z'):
                        self.assertEqual(self.library.does_user_require_vpn_mfa('x'), True)
                    with mock.patch.object(self.library, '_get_user_dn_by_username',
                                           side_effect=ldap.NO_SUCH_OBJECT):
                        self.assertEqual(self.library.does_user_require_vpn_mfa('x'), True)
                    with mock.patch.object(self.library, '_get_user_dn_by_username',
                                           side_effect=ldap.SERVER_DOWN):
                        self.assertEqual(self.library.does_user_require_vpn_mfa('x'),
                                         fail_open_mode)
                    with mock.patch.object(self.library, '_get_user_dn_by_username',
                                           side_effect=ldap.BUSY):
                        self.assertEqual(self.library.does_user_require_vpn_mfa('x'),
                                         fail_open_mode)

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
            with mock.patch.object(self.library, 'is_online', return_value=False):
                self.assertEqual(self.library.non_mfa_vpn_authentication('x', 'y'), fail_open_mode)
            with mock.patch.object(self.library, 'is_online', return_value=True):
                with mock.patch.object(self.library, '_get_user_dn_by_username',
                                       side_effect=ldap.NO_SUCH_OBJECT):
                    self.assertEqual(self.library.non_mfa_vpn_authentication('x', 'y'), False)
            with mock.patch.object(self.library, 'is_online', return_value=True):
                with mock.patch.object(self.library, '_get_user_dn_by_username', return_value='a'):
                    with mock.patch.object(self.library, '_create_ldap_connection',
                                           side_effect=ldap.SERVER_DOWN):
                        self.assertEqual(self.library.non_mfa_vpn_authentication('x', 'y'),
                                         fail_open_mode)
                    with mock.patch.object(self.library, '_create_ldap_connection',
                                           side_effect=ldap.BUSY):
                        self.assertEqual(self.library.non_mfa_vpn_authentication('x', 'y'),
                                         fail_open_mode)
                    with mock.patch.object(self.library, '_create_ldap_connection',
                                           side_effect=ldap.LDAPError):
                        self.assertEqual(self.library.non_mfa_vpn_authentication('x', 'y'),
                                         False)
                    with mock.patch.object(self.library, '_create_ldap_connection',
                                           return_value=None):
                        self.assertEqual(self.library.non_mfa_vpn_authentication('x', 'y'),
                                         True)


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
            self.library = IAMVPNLibraryLDAP()
        except Exception as err:  # pragma: no cover  pylint: disable=broad-except
            self.fail(err)
        self.core_setup()

    def tearDown(self):
        """ Clear the test rig """
        self.library = None


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
            self.library = IAMVPNLibraryLDAP()
        except Exception as err:  # pragma: no cover  pylint: disable=broad-except
            self.fail(err)
        self.library.conn.unbind_s()

    def tearDown(self):
        """ Clear the test rig """
        self.library = None


class TestPubFuncsMAIN(PublicTestsMixin, unittest.TestCase):
    """
        Test the public methods by calling into the main/exposed library
    """
    def setUp(self):
        """ Prepare test rig """
        self.library = IAMVPNLibrary()
        self.core_setup()

    def tearDown(self):
        """ Clear the test rig """
        self.library = None
