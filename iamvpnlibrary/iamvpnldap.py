#!/usr/bin/env python
"""
    This file handles LDAP-based / 'classic' work for IAM VPN
    access information.  Instead of libraries for VPN implementing
    direct calls to LDAP, our goal here is to have them ask the
    high-level questions about users and their access, and let us
    do the work.  At the time of writing, LDAP was the only game
    in town, but RESTful APIs were on the horizon.
"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation

import re
import ldap
import netaddr
from .iamvpnbase import IAMVPNLibraryBase, ParsedACL


class IAMVPNLibraryLDAP(IAMVPNLibraryBase):
    """
        This class does the heavy lifting.  We get the config from our
        base parent, and if that checks out, we do the LDAP queries and
        return the results.

        One thing to keep in mind is, while we do LDAP things in here,
        methods without _ are external facing and MUST NOT return
        any LDAP-specific information downstream (like DNs or subDNs).

        The design principle here is that the things calling into us
        have no idea about LDAP.

        Any methods with _ prepended are intended as internal calls.
        They CAN return LDAP-specific information.
    """

    def __init__(self):
        """
            instantiate the object, and validate the config file contents.
        """
        super(IAMVPNLibraryLDAP, self).__init__()
        self.config = self._validate_config_file()
        self.conn = self._create_ldap_connection(
            self.config.get('ldap_url'),
            self.config.get('ldap_bind_dn'),
            self.config.get('ldap_bind_password'))

    def _validate_config_file(self):
        """
            Here we go through the options we reqire to come from the
            config file.  We'll explode if things aren't there.  This
            is actually pretty awful, as a library, to do this.  But,
            the notion here is that there's no recovering if you have
            a bad ldap setup, so, explode noisily at spinup, rather than
            during runtime.
        """
        config = {}

        for (config_key, required, tup) in [
                ['ldap_url', True,
                 ('ldap-bind', 'url', None)],
                ['ldap_bind_dn', True,
                 ('ldap-bind', 'bind_dn', None)],
                ['ldap_bind_password', True,
                 ('ldap-bind', 'bind_password', None)],
                ['ldap_base', True,
                 ('ldap-bind', 'base', None)],
                ['ldap_groups_base', True,
                 ('ldap-bind', 'groups_base', None)],
                ['ldap_user_mail_attribute', True,
                 ('ldap-schema-users', 'mail_attribute', 'mail')],
                ['ldap_user_enabled_user_filter', True,
                 ('ldap-schema-users', 'enabled_user_filter', None)],
                # LDAP ACLs are almost guaranteed to be groupOfNames
                # Those require 'cn' and 'member'.  So we can spot those
                # as supremely likely defaults.
                ['ldap_vpn_acls_rdn_attribute', True,
                 ('ldap-schema-vpn-acls',
                  'rdn_attribute', 'cn')],
                ['ldap_vpn_acls_attribute_user', True,
                 ('ldap-schema-vpn-acls',
                  'attribute_user', 'member')],
                ['ldap_vpn_acls_attribute_host', True,
                 ('ldap-schema-vpn-acls',
                  'attribute_host', 'ipHostNumber')],
                ['ldap_vpn_acls_all_acls_filter', True,
                 ('ldap-schema-vpn-acls',
                  'all_acls_filter', None)],
                ['ldap_vpn_acls_minimum_group_filter', True,
                 ('ldap-schema-vpn-acls',
                  'minimum_group_filter', None)],
                ['ldap_vpn_acls_mfa_exempt_group_filter', True,
                 ('ldap-schema-vpn-acls',
                  'mfa_exempt_group_filter', None)]]:
            value = self.read_item_from_config(*tup)
            if required and value is None:
                raise ValueError(
                    'Unable to locate config item {0} / {1}'.format(
                        tup[0], tup[1]))
            config[config_key] = value

        return config

    @staticmethod
    def _create_ldap_connection(url, bind_dn, bind_passwd):
        """
            Establish a new connection and do nothing with it.

            When we initialize this class, we keep A connection object for
            future reference / querying.  That's the primary use.  There's
            a public method for "hey, I'd like to authenticate a user by
            password" and so we have this available as a staticmethod so
            we can test that (and then throw away the resulting object).
        """
        ldap.set_option(ldap.OPT_X_TLS_DEMAND, 1)
        if bind_passwd is None:
            raise ldap.INVALID_CREDENTIALS(bind_dn, (
                'You need to authenticate via password'))
        conn = ldap.initialize(url)
        conn.start_tls_s()
        conn.simple_bind_s(bind_dn, bind_passwd)
        return conn

    def _get_user_dn_by_username(self, input_username):
        """
            Return a user's DN

            input_username: "user" (if they are a nonhuman) or
                            "foo@mozilla.com"
            return: str of their DN
            raises if there's no such user.
        """
        if not isinstance(input_username, basestring):
            raise TypeError(input_username, 'Argument must be a string')
        res = self.conn.search_s(
            self.config.get('ldap_base'), ldap.SCOPE_SUBTREE,
            filterstr=('(' + self.config.get('ldap_user_mail_attribute') +
                       '=' + input_username + ')'),
            attrlist=[]
            )
        # res should be a list of a tuple of a string and a dict:
        #   [
        #    ('mail=foo@mozilla.com,o=com,dc=mozilla',
        #     {'mail': ['foo@mozilla.com']}
        #    )
        #   ]
        # res should be a list of just one user tuple:
        if len(res) < 1:
            #  If there's no user, that's a problem
            raise ldap.NO_SUCH_OBJECT(input_username,
                                      'Could not find any entry in LDAP')
        elif len(res) > 1:
            # If there's more than one user with this email, that's bad.
            # Fail out here out of an abundance of caution.
            raise ldap.LDAPError(input_username,
                                 'Multiple entries found in LDAP')
        # res[0] is now be a single user's (dn,attrs) tuple:
        #   (
        #    'mail=foo@mozilla.com,o=com,dc=mozilla',
        #    {'mail': ['foo@mozilla.com']}
        #   )
        #    res[0][0] grabs just their DN
        return res[0][0]

    def _get_all_enabled_users(self):
        """
            search for all non-disabled users and return their DNs.

            return: set(['mail=user@foo.com,o=com,dc=company',
                         'mail=user2@foo.com,o=com,dc=company', ...])
        """
        users = set()
        res = self.conn.search_s(
            self.config.get('ldap_base'), ldap.SCOPE_SUBTREE,
            filterstr=(
                '(&' + self.config.get('ldap_user_enabled_user_filter') +
                '(' + self.config.get('ldap_user_mail_attribute') + '=*)' +
                ')'),
            attrlist=['dn'])
        for user_dn, _attr in res:
            users.add(user_dn)
        return users

    def _get_acl_allowed_users(self):
        """
            search for all user DNs that belong to the group which we
            have said is "you must be in this to connect to the VPN"

            return: set(['mail=user@foo.com,o=com,dc=company',
                         'mail=user2@foo.com,o=com,dc=company' ...])
        """
        users = set()
        res = self.conn.search_s(
            self.config.get('ldap_groups_base'), ldap.SCOPE_SUBTREE,
            filterstr=self.config.get('ldap_vpn_acls_minimum_group_filter'),
            attrlist=[self.config.get('ldap_vpn_acls_attribute_user')])
        for _dn, attr in res:
            for userdn in attr[
                    self.config.get('ldap_vpn_acls_attribute_user')]:
                users.add(userdn)
        return users

    def _vpn_mfa_exempt_users(self):
        """
            search for all user DNs that belong to the group which we
            have said is "you do not have to MFA into the VPN"

            return: set(['mail=user@foo.com,o=com,dc=company',
                         'mail=user2@foo.com,o=com,dc=company' ...])
        """
        users = set()
        res = self.conn.search_s(
            self.config.get('ldap_groups_base'), ldap.SCOPE_SUBTREE,
            filterstr=self.config.get('ldap_vpn_acls_mfa_exempt_group_filter'),
            attrlist=[self.config.get('ldap_vpn_acls_attribute_user')])
        for _dn, attr in res:
            for userdn in attr[
                    self.config.get('ldap_vpn_acls_attribute_user')]:
                users.add(userdn)
        return users

    def _all_vpn_allowed_users(self):
        """
            An allowed user is someone:
                whose account is enabled via ldap AND
                who is in the acl for minimum LDAP privs.
            Pull either access, and they should be off VPN.

            return: set(['mail=user@foo.com,o=com,dc=company',
                         'mail=user2@foo.com,o=com,dc=company' ...])
        """
        ldap_enabled_users = self._get_all_enabled_users()
        vpn_acl_enabled_users = self._get_acl_allowed_users()
        allowed_users = ldap_enabled_users & vpn_acl_enabled_users
        return allowed_users

    @staticmethod
    def _split_vpn_acl_string(input_string):
        """
            breaks apart a string into component pieces
            This could possibly move up to the base layer instead of LDAP.
            But until we know what lines look like there, we have to
            assume that the ACL strings in LDAP are unique to LDAP.

            input_string: "1.1.1.1" or "1.1.1.1/30" or
                          "1.1.1.1:443" or "1.1.1.1 # somecomment"
            return: ParsedACL
                    raise for horrible inputs
        """
        if not isinstance(input_string, basestring):
            raise TypeError(input_string, 'Argument must be a string')
        # input_string should be:
        #    '1.1.1.1 # foo.m.c'
        _split_host_entry = input_string.split('#', 1)
        unparsed_destination = _split_host_entry[0].strip()
        if len(_split_host_entry) > 1:
            # It's 1 or 2
            description = _split_host_entry[1].strip()
        else:
            description = ''
        if unparsed_destination.count(':') > 1:
            # There's more than 1 colon.  That means we need to think ipv6.
            # We are somewhat in dangerous territory, as I'm writing this
            # before we really have ipv6 ACLs going on.
            v6_match = re.search(r'^\[(.*)\]:(.*)', unparsed_destination)
            if v6_match:
                # First case, let's see if we have '[::]:443':
                # The brackets will be there if we have a port to strip
                test_string = v6_match.group(1)
                port_string = v6_match.group(2)
            else:
                # There's no brackets, so it's probably a plain v6 address.
                test_string = unparsed_destination
                port_string = ''
        elif unparsed_destination.count(':') > 0:
            # There's 1 colon, so that's almost certainly a v4 address
            # with a port attached.
            test_string, port_string = unparsed_destination.split(":", 1)
        else:
            # There's no colon, so that's almost certainly a v4 address
            # with nothing else.
            test_string = unparsed_destination
            port_string = ''
        # At this point we have something that's PROBABLY an address.
        # Let's have the experts handle it.
        address = netaddr.ip.IPNetwork(test_string)
        # We will raise here if the address was not parseable.
        # This is intentional.  We mainly care about this from
        # within the 'is valid' call.
        #
        # At this point, time to return.  Populate a ParsedACL.
        # We don't know the rule that caused this string at this point.
        # That's okay.  Just fire it back upstream, someone can add in
        # the rule if they care to track it.
        return ParsedACL(rule='',
                         address=address,
                         portstring=port_string,
                         description=description)

    def _fetch_vpn_acls_for_user(self, input_email):
        """
            Raw-query LDAP to obtain the network ACLs of a given user.
            input_email: "user@company.com"
            return: ldap response
        """
        if not isinstance(input_email, basestring):
            raise TypeError(input_email, 'Argument must be a string')
        user_dn = self._get_user_dn_by_username(input_email)
        res = self.conn.search_s(
            self.config.get('ldap_groups_base'), ldap.SCOPE_SUBTREE,
            filterstr=(
                '(&' + self.config.get('ldap_vpn_acls_all_acls_filter') +
                '(' + self.config.get('ldap_vpn_acls_attribute_user') +
                '=' + user_dn + ')' + ')'),
            attrlist=[self.config.get('ldap_vpn_acls_rdn_attribute'),
                      self.config.get('ldap_vpn_acls_attribute_host')],
            )
        # res should be:
        # [
        #  ('cn=vpn_X,ou=groups,dc=mozilla',
        #   {'ipHostNumber': ['1.1.1.1 # foo.m.c', '2.2.2.2 # bar.m.c'],
        #    'cn': 'vpn_X'}
        #   ),
        #  ]
        return res

    def _sanitized_vpn_acls_for_user(self, input_email):
        """
            Find what ACLs a person is entitled to.
            input_email: "user@company.com"
            return: [ParsedACL, ParsedACL, ...]

            NOTE: this returns a LIST and not a SET.

            Someone could have two ACLs assigned to them that provide
            the exact same ACL, and we don't go detecting that because
            it's fundamentally expensive to figure out overlaps, and
            different people want different results (every ACL? every IP?
            Just the IPs?  What about a CIDR that encapsulates another?)
        """
        if not isinstance(input_email, basestring):
            raise TypeError(input_email, 'Argument must be a string')
        raw_acls = self._fetch_vpn_acls_for_user(input_email)
        acls = []
        for _dn, attrs_dict in raw_acls:
            if self.config.get('ldap_vpn_acls_attribute_host') \
                    not in attrs_dict:
                # ^ ACLs can be empty.
                continue
            # The rulename is the 'cn'.  The [0] will always work
            # because it's the rule RDN, and thus will be present
            # and unique.
            rulename = attrs_dict[
                self.config.get('ldap_vpn_acls_rdn_attribute')][0]
            for host_entry in attrs_dict[
                    self.config.get('ldap_vpn_acls_attribute_host')]:
                try:
                    raw_acl_object = self._split_vpn_acl_string(host_entry)
                except netaddr.core.AddrFormatError:
                    raw_acl_object = None
                if raw_acl_object:
                    # If something ISN'T valid, silently ignore it.
                    # The idea here is, if it's invalid, they won't
                    # get access to something anyway, so, failing
                    # silently is fine.  If they need access, someone
                    # will complain, and someone will find the bad ACL.
                    #
                    # Now, if it WAS valid, repack the namedtuple ParsedACL
                    # to include the name of the rule that got us this
                    # particular ACL line.
                    acl_object = ParsedACL(
                        rule=rulename,
                        address=raw_acl_object.address,
                        portstring=raw_acl_object.portstring,
                        description=raw_acl_object.description,
                    )
                    # Add it to the list we're sending back.
                    acls.append(acl_object)
        return acls

    ######################################################
    # Below here are world-exposed functions.

    def user_allowed_to_vpn(self, input_email):
        """
            An allowed user is someone:
                whose account is enabled via ldap AND
                who is in the acl for minimum LDAP privs.

            input_email: "user@company.com"
            return: bool

            Outside user: duo_openvpn
            Outside user: duo_openvpn kill script
        """
        if not isinstance(input_email, basestring):
            raise TypeError(input_email, 'Argument must be a string')
        all_allowed_users = self._all_vpn_allowed_users()
        try:
            user_dn = self._get_user_dn_by_username(input_email)
        except ldap.NO_SUCH_OBJECT:
            return False
        return user_dn in all_allowed_users

    def does_user_require_vpn_mfa(self, input_email):
        """
            Someone can bypass MFA if they're in a group that says they can.

            CAUTION: beware mental logic errors here.
            True  = 'must mfa' vs
            False = 'are exempt from mfa'
            It's a small function.  Read it carefully.

            input_email: "user@company.com"
            return: bool

            Outside user: duo_openvpn
        """
        if not isinstance(input_email, basestring):
            raise TypeError(input_email, 'Argument must be a string')
        exempted_users = self._vpn_mfa_exempt_users()
        try:
            user_dn = self._get_user_dn_by_username(input_email)
        except ldap.NO_SUCH_OBJECT:
            # True : they don't exist, so we're into a
            # don'tcare edge case.  They are not exempt.
            return True
        # If they exist and are NOT in this list, then we want MFA
        return user_dn not in exempted_users

    def get_allowed_vpn_ips(self, input_email):
        """
            Get the CIDR string of places a user is allowed to VPN to.

            input_email: "user@company.com"
            return: ['cidr1/32', 'cidr2/30', ...]

            Outside user: get_user_routes
       """
        if not isinstance(input_email, basestring):
            raise TypeError(input_email, 'Argument must be a string')
        try:
            user_acls = self._sanitized_vpn_acls_for_user(input_email)
        except ldap.NO_SUCH_OBJECT:
            # A nonexistent user has no ACLs
            user_acls = []
        results = []
        for acl_object in user_acls:
            address_object = acl_object.address
            results.append(str(address_object.cidr))
        return results

    def get_allowed_vpn_acls(self, input_email):
        """
            Get the ParsedACLs of places a user is allowed to VPN to.

            input_email: "user@company.com"
            return: [ParsedACL, ParsedACL, ...]

            Outside user: openvpn-netfilter
       """
        if not isinstance(input_email, basestring):
            raise TypeError(input_email, 'Argument must be a string')
        return self._sanitized_vpn_acls_for_user(input_email)

    def non_mfa_vpn_authentication(self, input_username, input_password):
        """
            This test seeks to verify that a user can authenticate to ldap.

            input_email: "user@company.com"
            input_password: "s0m3p@ssw0rd"
            return: bool

            Outside user: duo_openvpn
        """
        if not isinstance(input_username, basestring):
            raise TypeError(input_username, 'Argument must be a string')
        if not isinstance(input_password, basestring):
            raise TypeError(input_password, 'Argument must be a string')

        try:
            user_dn = self._get_user_dn_by_username(input_username)
        except ldap.NO_SUCH_OBJECT:
            # A user who does not exist obviously fails auth.
            # That they don't exist is a larger question that you
            # should probably answer elsewhere.
            return False
        try:
            self._create_ldap_connection(
                self.config.get('ldap_url'), user_dn, input_password)
            return True
        except ldap.LDAPError:
            return False
