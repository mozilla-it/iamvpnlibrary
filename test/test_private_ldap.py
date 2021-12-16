#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
""" LDAP unit test script """

import unittest
import test.context  # pylint: disable=unused-import
from netaddr import IPNetwork
import mock
import ldap
import six
from iamvpnlibrary.iamvpnldap import IAMVPNLibraryLDAP
from iamvpnlibrary.iamvpnbase import ParsedACL


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
        self.library = IAMVPNLibraryLDAP()
        self.normal_user = self.library.read_item_from_config(
            section='testing', key='normal_user', default=None)

    def tearDown(self):
        """ Clear the test rig """
        self.library = None

    def test_00_is_online(self):
        """ exercise is_online function """
        with mock.patch.object(self.library.conn, 'result', return_value=None):
            self.assertTrue(self.library.is_online())
        with mock.patch.object(self.library.conn, 'result', side_effect=ldap.LDAPError):
            self.assertFalse(self.library.is_online())

    def test_get_all_enabled_users(self):
        """
            Testing that we get back a reasonably sized set of user DNs
        """
        # First, simulation tests:
        with mock.patch.object(self.library.conn, 'search_s',
                               return_value=[('mail=dn3', {}), ('mail=dn9', {})]):
            result = self.library._get_all_enabled_users()
            self.assertEqual(result, set(['mail=dn3', 'mail=dn9']))

        # Now, test it live:
        result = self.library._get_all_enabled_users()
        self.assertIsInstance(result, set,
                              'Must return a set')
        # CAUTION!  this verifies that it has 100 at test time.
        # Keep in mind what will happen if this happens at RUN time.
        self.assertGreater(len(result), 100,
                           'We expect a sizeable list of enabled users')
        self.assertIn(','+self.library.config['ldap_base'], result.pop(),
                      ('A random user from the set does not match '
                       'the ldap base of the config.  Bad search?'))

    def test_get_acl_allowed_users(self):
        """
            Testing that we get back a reasonably sized set of user DNs
        """
        # First, simulation tests:
        with mock.patch.object(self.library.conn, 'search_s',
                               return_value=[('cn=vpn_allowed_folks', {'member': ['a', 'b']})]):
            result = self.library._get_acl_allowed_users()
            self.assertEqual(result, set(['a', 'b']))
        # Now, test it live:
        result = self.library._get_acl_allowed_users()
        self.assertIsInstance(result, set,
                              'Must return a set')
        # CAUTION!  this verifies that it has 100 at test time.
        # Keep in mind what will happen if this happens at RUN time.
        self.assertGreater(len(result), 100,
                           'We expect a sizeable list of allowed users')
        self.assertIn(','+self.library.config['ldap_base'], result.pop(),
                      ('A random user from the set does not match '
                       'the ldap base of the config.  Bad search?'))

    def test_all_vpn_allowed_users(self):
        """
            Testing that we get back a reasonably sized set of user DNs
        """
        # First, simulation tests:
        with mock.patch.object(self.library, '_get_all_enabled_users',
                               return_value=set(['a', 'b', 'C'])), \
                mock.patch.object(self.library, '_get_acl_allowed_users',
                                  return_value=set(['B', 'c', 'd'])):
            result = self.library._all_vpn_allowed_users()
            self.assertEqual(result, set(['b', 'c']))
        # Now, test it live:
        result = self.library._all_vpn_allowed_users()
        self.assertIsInstance(result, set,
                              'Must return a set')
        # CAUTION!  this verifies that it has 100 at test time.
        # Keep in mind what will happen if this happens at RUN time.
        self.assertGreater(len(result), 100,
                           'We expect a sizeable list of allowed users')
        self.assertIn(','+self.library.config['ldap_base'], result.pop(),
                      ('A random user from the set does not match '
                       'the ldap base of the config.  Bad search?'))

    def test_fetch_vpn_acls_for_user(self):
        """
            Testing that we get back raw/ldap'ed acls for our test user.
        """
        with self.assertRaises(TypeError):
            self.library._fetch_vpn_acls_for_user([])
        # First, simulation tests:
        # This is going to just be an assert-how-you're-called mock
        # because the basis of this function is "return a thing from ldap"
        with mock.patch.object(self.library.conn, 'search_s') as mock_ldap, \
                mock.patch.object(self.library, '_get_user_dn_by_username', return_value='ddn'), \
                mock.patch.dict(self.library.config,
                                {'ldap_groups_base': 'ou=groupz,dc=myplace',
                                 'ldap_vpn_acls_all_acls_filter':
                                     '(&(objectClass=GroupOfNames)(%(rdn_attribute)s=vpn_*))',
                                 'ldap_vpn_acls_attribute_user': 'uzer',
                                 'ldap_vpn_acls_rdn_attribute': 'cn',
                                 'ldap_vpn_acls_attribute_host': 'hostattr'}):
            self.library._fetch_vpn_acls_for_user('dude')
            expect_filter = '(&(&(objectClass=GroupOfNames)(%(rdn_attribute)s=vpn_*))(uzer=ddn))'
            mock_ldap.assert_called_with('ou=groupz,dc=myplace', ldap.SCOPE_SUBTREE,
                                         filterstr=expect_filter,
                                         attrlist=['cn', 'hostattr'])
        # Now, test it live:
        if self.normal_user is None:  # pragma: no cover
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
        self.assertIsInstance(acl[0], six.string_types,
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

    def test_sanitized_vpn_acls(self):
        """
            Testing that we get back acls that we've flattened into being a
            list of ParsedACLs
        """
        with self.assertRaises(TypeError):
            self.library._sanitized_vpn_acls_for_user([])
        # First, simulation tests:
        with mock.patch.dict(self.library.config, {'ldap_vpn_acls_rdn_attribute': 'cn',
                                                   'ldap_vpn_acls_attribute_host': 'hostattr'}):
            # User with no ACLs:
            with mock.patch.object(self.library, '_fetch_vpn_acls_for_user',
                                   return_value=[]):
                result = self.library._sanitized_vpn_acls_for_user('anyone')
                self.assertEqual(result, [])
            # User with empty ACLs:
            with mock.patch.object(self.library, '_fetch_vpn_acls_for_user',
                                   return_value=[('_cn', {})]):
                result = self.library._sanitized_vpn_acls_for_user('anyone')
                self.assertEqual(result, [])
            # User with a normal ACL:
            with mock.patch.object(self.library, '_fetch_vpn_acls_for_user',
                                   return_value=[('_cn', {'cn': ['vpn_something'],
                                                          'hostattr': ['1.1.1.1 # foo.m.c']})]):
                result = self.library._sanitized_vpn_acls_for_user('anyone')
                self.assertEqual(result, [ParsedACL(rule='vpn_something',
                                                    address=IPNetwork('1.1.1.1/32'),
                                                    portstring='', description='foo.m.c')])
            # User with a bogus ACL:
            with mock.patch.object(self.library, '_fetch_vpn_acls_for_user',
                                   return_value=[('_cn', {'cn': ['vpn_something'],
                                                          'hostattr': ['999.999.999.999']})]):
                result = self.library._sanitized_vpn_acls_for_user('anyone')
                self.assertEqual(result, [])
            # User with a hostname ACL:
            with mock.patch.object(self.library, '_fetch_vpn_acls_for_user',
                                   return_value=[('_cn', {'cn': ['vpn_lh'],
                                                          'hostattr': ['localhost # lokal']})]):
                result = self.library._sanitized_vpn_acls_for_user('anyone')
                self.assertEqual(result, [ParsedACL(rule='vpn_lh',
                                                    address=IPNetwork('127.0.0.1/32'),
                                                    portstring='', description='lokal')])
            # User with a null hostname ACL somehow:
            with mock.patch.object(self.library, '_fetch_vpn_acls_for_user',
                                   return_value=[('_cn', {'cn': ['vpn_badstr'],
                                                          'hostattr': ['']})]):
                result = self.library._sanitized_vpn_acls_for_user('anyone')
                self.assertEqual(result, [])

        # Now, test it live:
        if self.normal_user is None:  # pragma: no cover
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

    def test_vpn_mfa_exempt_users(self):
        """
            Testing that we get the set of user DNs who are exempt from
            having to MFA
        """
        # First, simulation tests:
        with mock.patch.object(self.library.conn, 'search_s',
                               return_value=[('cn=vpn_allowed_folks', {'member': ['r', 'w']})]):
            result = self.library._vpn_mfa_exempt_users()
            self.assertEqual(result, set(['r', 'w']))
        # Now, test it live:
        result = self.library._vpn_mfa_exempt_users()
        self.assertIsInstance(result, set,
                              'Must return a set')
        self.assertGreater(
            len(result), 0,
            ('If this failed, check the group size or your bind user perms. '
             "It should be small-ish, but if it's zero that's weird."))
        self.assertLess(
            len(result), 10,
            ('If this failed, check the group size. '
             'It should be small-ish, but this test may be too small.'))
        self.assertIn(','+self.library.config['ldap_base'], result.pop(),
                      ('A random user from the set does not match '
                       'the ldap base of the config.  Bad search?'))

    def test_get_user_dn_by_username(self):
        """
            Testing that can turn an email address into a user's DN
        """
        with self.assertRaises(TypeError):
            self.library._get_user_dn_by_username([])
        # First, simulation tests:
        with self.assertRaises(ldap.NO_SUCH_OBJECT), \
                mock.patch.object(self.library.conn, 'search_s', return_value=[]):
            self.library._get_user_dn_by_username('somename')
        with self.assertRaises(ldap.LDAPError), \
                mock.patch.object(self.library.conn, 'search_s',
                                  return_value=[('dnX', {}), ('dnY', {})]):
            self.library._get_user_dn_by_username('somename')
        with mock.patch.object(self.library.conn, 'search_s',
                               return_value=[('dn1', {})]):
            result = self.library._get_user_dn_by_username('somename')
            self.assertEqual(result, 'dn1')
        # Now, test it live:
        if self.normal_user is None:  # pragma: no cover
            self.skipTest('Must provide a .normal_user to test')
        result = self.library._get_user_dn_by_username(self.normal_user)
        self.assertIsInstance(result, six.string_types,
                              'search for username must return a DN string')
        self.assertIn(','+self.library.config['ldap_base'], result,
                      ('A random user from the set does not match '
                       'the ldap base of the config.  Bad search?'))
