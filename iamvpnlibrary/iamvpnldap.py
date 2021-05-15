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
import socket
import ldap
import six
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
        try:
            self.conn = self._create_ldap_connection(
                self.config.get('ldap_url'),
                self.config.get('ldap_bind_dn'),
                self.config.get('ldap_bind_password'))
        except ldap.LDAPError as ldaperr:
            raise RuntimeError('Error connecting to LDAP IAM: {}'.format(ldaperr))

    def is_online(self):
        """
            Determine if we should give answers from the server, or
            perform our best guess while offline.

            This check looks for an offline server.  There may be
            more/better ways to do this.
        """
        try:
            # Try to grab a result.  Since we only do synch calls,
            # this will always return.  Unless we're disconnected.
            self.conn.result(timeout=0)
            return True
        except ldap.LDAPError:
            return False

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

        for (config_key, tup) in [
                ['ldap_url', ('ldap-bind', 'url', None)],
                ['ldap_bind_dn', ('ldap-bind', 'bind_dn', None)],
                ['ldap_bind_password', ('ldap-bind', 'bind_password', None)],
                ['ldap_base', ('ldap-bind', 'base', None)],
                ['ldap_groups_base', ('ldap-bind', 'groups_base', None)],
                ['ldap_user_mail_attribute',
                 ('ldap-schema-users', 'mail_attribute', 'mail')],
                ['ldap_user_enabled_user_filter',
                 ('ldap-schema-users', 'enabled_user_filter', None)],
                # LDAP ACLs are almost guaranteed to be groupOfNames
                # Those require 'cn' and 'member'.  So we can spot those
                # as supremely likely defaults.
                ['ldap_vpn_acls_rdn_attribute',
                 ('ldap-schema-vpn-acls', 'rdn_attribute', 'cn')],
                ['ldap_vpn_acls_attribute_user',
                 ('ldap-schema-vpn-acls', 'attribute_user', 'member')],
                ['ldap_vpn_acls_attribute_host',
                 ('ldap-schema-vpn-acls', 'attribute_host', 'ipHostNumber')],
                ['ldap_vpn_acls_all_acls_filter',
                 ('ldap-schema-vpn-acls', 'all_acls_filter', None)],
                ['ldap_vpn_acls_minimum_group_filter',
                 ('ldap-schema-vpn-acls', 'minimum_group_filter', None)],
                ['ldap_vpn_acls_mfa_exempt_group_filter',
                 ('ldap-schema-vpn-acls', 'mfa_exempt_group_filter', None)]]:
            value = self.read_item_from_config(*tup)
            if value is None:
                raise ValueError(
                    'Unable to locate config item {0} / {1}'.format(tup[0], tup[1]))
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
        if not isinstance(input_username, six.string_types):
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
        if len(res) > 1:
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
            attrlist=[])
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
        sought_attr = self.config.get('ldap_vpn_acls_attribute_user')
        if not isinstance(sought_attr, str):  # pragma: no cover
            sought_attr = sought_attr.encode('utf-8')
        res = self.conn.search_s(
            self.config.get('ldap_groups_base'), ldap.SCOPE_SUBTREE,
            filterstr=self.config.get('ldap_vpn_acls_minimum_group_filter'),
            attrlist=[sought_attr])
        for _dn, attr in res:
            if sought_attr in attr:
                for userdn in attr[sought_attr]:
                    if isinstance(userdn, bytes):
                        userdn = userdn.decode('utf-8')
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
        sought_attr = self.config.get('ldap_vpn_acls_attribute_user')
        if not isinstance(sought_attr, str):  # pragma: no cover
            sought_attr = sought_attr.encode('utf-8')
        res = self.conn.search_s(
            self.config.get('ldap_groups_base'), ldap.SCOPE_SUBTREE,
            filterstr=self.config.get('ldap_vpn_acls_mfa_exempt_group_filter'),
            attrlist=[sought_attr])
        for _dn, attr in res:
            if sought_attr in attr:
                for userdn in attr[sought_attr]:
                    if isinstance(userdn, bytes):
                        userdn = userdn.decode('utf-8')
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
    def _split_vpn_acl_string(input_string):  # pylint: disable=too-many-branches
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
        if not isinstance(input_string, six.string_types):
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
        # Let's have the experts handle it:
        try:
            address = netaddr.ip.IPNetwork(test_string)
            # If this doesn't bomb, it was a CIDR-like address.
        except ValueError:  # pragma: no cover
            # This catches a stupid error in old netaddr before 0.7.11
            # https://github.com/drkjam/netaddr/issues/58
            # We form the 'proper' error to raise, because in the future
            # this is what will happen when netaddr is patched.
            error_to_raise = netaddr.core.AddrFormatError('invalid ACL entry: %r!' % test_string)
        except netaddr.core.AddrFormatError as errcode:
            error_to_raise = errcode
        else:
            # At this point, time to return.  Populate a ParsedACL.
            # We don't know the rule that caused this string at this point.
            # That's okay.  Just fire it back upstream, someone can add in
            # the rule if they care to track it.
            return ParsedACL(rule='',
                             address=address,
                             portstring=port_string,
                             description=description)

        # We got a string that wasn't valid as a CIDR.  Time to see if
        # it was a hostname (let's save that) or garbage (discard)
        # There's guesswork here.  If something resolves as hostname
        # it's probably a hostname.  If it doesn't, it's something we
        # didn't expect.  But either way, it's not a useful ACL.
        try:
            socket.gethostbyname(test_string)
        except socket.error:
            # We will raise here if the address was not parseable.
            # This is intentional.  We mainly care about this from
            # within the 'is valid' call.
            raise error_to_raise
        else:
            # Populate a ParsedACL BUT BADLY.
            # We are putting the hostNAME in 'address' instead of the majority
            # case of an IPNetwork.  Since we've validated this enough to know
            # that we're not sending garbage, we'll rely on someone upstream
            # to turn this into multiple ACLs.  We only want to return ONE
            # thing from this function.
            if not description:
                # If someone didn't include a comment, make the
                # hostname be the description.
                description = test_string
            return ParsedACL(rule='',
                             address=test_string,
                             portstring=port_string,
                             description=description)

    def _fetch_vpn_acls_for_user(self, input_email):
        """
            Raw-query LDAP to obtain the network ACLs of a given user.
            input_email: "user@company.com"
            return: ldap response
        """
        if not isinstance(input_email, six.string_types):
            raise TypeError(input_email, 'Argument must be a string')
        user_dn = self._get_user_dn_by_username(input_email)
        rdn_attr = self.config.get('ldap_vpn_acls_rdn_attribute')
        if not isinstance(rdn_attr, str):  # pragma: no cover
            rdn_attr = rdn_attr.encode('utf-8')
        host_attr = self.config.get('ldap_vpn_acls_attribute_host')
        if not isinstance(host_attr, str):  # pragma: no cover
            host_attr = host_attr.encode('utf-8')
        res = self.conn.search_s(
            self.config.get('ldap_groups_base'), ldap.SCOPE_SUBTREE,
            filterstr=(
                '(&' + self.config.get('ldap_vpn_acls_all_acls_filter') +
                '(' + self.config.get('ldap_vpn_acls_attribute_user') +
                '=' + user_dn + ')' + ')'),
            attrlist=[rdn_attr, host_attr],
            )
        # res should be:
        # [
        #  ('cn=vpn_X,ou=groups,dc=mozilla',
        #   {'ipHostNumber': ['1.1.1.1 # foo.m.c', '2.2.2.2 # bar.m.c'],
        #    'cn': 'vpn_X'}
        #   ),
        #  ]
        return res

    def _sanitized_vpn_acls_for_user(self, input_email):  # pylint: disable=too-many-branches
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
        if not isinstance(input_email, six.string_types):
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
            rulename = attrs_dict[self.config.get('ldap_vpn_acls_rdn_attribute')][0]
            if isinstance(rulename, bytes):
                rulename = rulename.decode('utf-8')
            for host_entry in attrs_dict[self.config.get('ldap_vpn_acls_attribute_host')]:
                if isinstance(host_entry, bytes):
                    host_entry = host_entry.decode('utf-8')
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

                    # the address field is likely an IPNetwork, but could
                    # be a string that is a hostname.  Let's check:
                    raw_addr = raw_acl_object.address

                    if isinstance(raw_addr, netaddr.ip.IPNetwork):
                        # A list of 1, for easy looping below
                        all_addresses = [raw_addr]
                    else:
                        # we got a hostname.  Prior testing said it
                        # resolves so we shouldn't error here.
                        try:
                            # caution, gethostbyname_ex is ipv4-only.
                            # caution: lookups from the server may not
                            # be the same as lookups for a client.
                            # Short of ingesting all routes and DNS from them,
                            # we can never know for sure, but, we're trying.
                            lookup = socket.gethostbyname_ex(raw_addr)
                        except socket.error:
                            # somehow, er did error, oh well.  No ACL.
                            all_addresses = []
                        else:
                            all_addresses = [netaddr.ip.IPNetwork(x) for x in lookup[2]]

                    # Now, if it WAS valid, repack the namedtuple ParsedACL
                    # to include the name of the rule that got us this
                    # particular ACL line.
                    for address in all_addresses:
                        acl_object = ParsedACL(
                            rule=rulename,
                            address=address,
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
        if not isinstance(input_email, six.string_types):
            raise TypeError(input_email, 'Argument must be a string')
        if not self.is_online():
            return self.fail_open
        try:
            all_allowed_users = self._all_vpn_allowed_users()
        except (ldap.SERVER_DOWN, ldap.BUSY):
            return self.fail_open
        try:
            user_dn = self._get_user_dn_by_username(input_email)
        except ldap.NO_SUCH_OBJECT:
            return False
        except (ldap.SERVER_DOWN, ldap.BUSY):
            return self.fail_open
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
        if not isinstance(input_email, six.string_types):
            raise TypeError(input_email, 'Argument must be a string')
        if not self.is_online():
            # This is going to be a bit of mental gymnastics.
            # This is ridiculously overthought.
            #
            # We tried to get the list of exempt users from LDAP
            # and LDAP failed us, for whatever reason.  Now, having
            # done so, what do we do, with regards to failing
            # open.  An LDAP failure doesn't mean we've had a
            # Duo failure.  So what we do here is we return
            # the fail_open mode.  This is more complex than it
            # should maybe be.
            #
            # If we return False, we're into a dangerous path,
            # because you have no LDAP right now, which means
            # that you could end up on a path whereby someone
            # is then given a fail_open that lets them bypass
            # a password, and then you have people logging in
            # with ZERO credentials.
            # If we return True, anyone who normally doesn't
            # have an MFA token is going to lose, because they
            # never had a token to begin with.
            #
            # BUT.  If this is an LDAP burp and Duo is still
            # working, then saying True here will make Duo
            # make a decision for us.  and if the box is in
            # isolation mode, then how are you even talking to it.
            #
            # The better move is to have your upstream code go and
            # say "I can't talk to LDAP, that's a requirement,
            # game over."  And then, it doesn't matter what this
            # library calls, because it'll never be in that
            # situation.  But, we need to have a decision, so...
            # IMPROVEME
            return self.fail_open
        exempted_users = self._vpn_mfa_exempt_users()
        try:
            user_dn = self._get_user_dn_by_username(input_email)
        except ldap.NO_SUCH_OBJECT:
            # True : they don't exist, so we're into a
            # don'tcare edge case.  They are not exempt.
            return True
        except (ldap.SERVER_DOWN, ldap.BUSY):
            return self.fail_open
        # If the user exists and are NOT in a list, then we want MFA.
        return user_dn not in exempted_users

    def get_allowed_vpn_ips(self, input_email):
        """
            Get the CIDR string of places a user is allowed to VPN to.

            input_email: "user@company.com"
            return: ['cidr1/32', 'cidr2/30', ...]

            Outside user: openvpn-client-connect
        """
        if not isinstance(input_email, six.string_types):
            raise TypeError(input_email, 'Argument must be a string')
        if not self.is_online():
            # Absentee server means no IPs
            return []
        results = []
        user_acls = self.get_allowed_vpn_acls(input_email)
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
        if not isinstance(input_email, six.string_types):
            raise TypeError(input_email, 'Argument must be a string')
        if not self.is_online():
            # Absentee server means no ACLs
            return []
        try:
            return self._sanitized_vpn_acls_for_user(input_email)
        except ldap.NO_SUCH_OBJECT:
            # A nonexistent user has no ACLs
            return []
        except (ldap.SERVER_DOWN, ldap.BUSY):
            return []

    def non_mfa_vpn_authentication(self, input_username, input_password):
        """
            This test seeks to verify that a user can authenticate to ldap.

            input_email: "user@company.com"
            input_password: "s0m3p@ssw0rd"
            return: bool

            Outside user: duo_openvpn
        """
        if not isinstance(input_username, six.string_types):
            raise TypeError(input_username, 'Argument must be a string')
        if not isinstance(input_password, six.string_types):
            raise TypeError(input_password, 'Argument must be a string')
        if not self.is_online():
            # A user could not be looked up.  fail open as needed.
            return self.fail_open

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
        except (ldap.SERVER_DOWN, ldap.BUSY):
            return self.fail_open
        except ldap.LDAPError:
            return False
