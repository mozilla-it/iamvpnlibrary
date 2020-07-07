#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
"""
    This file creates a base object for IAM VPN access information.
"""

import re
import collections
import ast
try:
    import configparser
except ImportError:  # pragma: no cover
    from six.moves import configparser
import six

ParsedACL = collections.namedtuple(
    'ParsedACL', ['rule', 'address', 'portstring', 'description'])


class IAMVPNLibraryBase(object):
    """
        This class is responsible for very little.  Its job is to get a
        config file imported and prepared for any downstream classes.

        We don't validate the contents of the conf file, beyond importing it.
        If we can't import, we're going to raise out of here, because
        life is so bad that we have nowhere to go.
    """
    CONFIG_FILE_LOCATIONS = ['iamvpnlibrary.conf',
                             '/usr/local/etc/iamvpnlibrary.conf',
                             '/etc/iamvpnlibrary.conf']

    def __init__(self):
        """
            ingest the config file so upstream classes can use it
        """
        self.configfile = self._ingest_config_from_file()
        try:
            self.fail_open = self.configfile.getboolean('failure', 'fail_open')
        except (ValueError, configparser.Error):
            self.fail_open = False

        try:
            sudo_users = ast.literal_eval(self.configfile.get('sudo', 'sudo_users'))
        except (ValueError, configparser.Error):
            sudo_users = []
        self.sudo_users = sudo_users

        try:
            # Note that we do a 'raw' get here because of regexp's
            self.sudo_username_regexp = self.configfile.get('sudo', 'sudo_username_regexp',
                                                            raw=True)
        except (configparser.Error):
            self.sudo_username_regexp = None

    def _ingest_config_from_file(self):
        """
            pull in config variables from a system file
        """
        config = configparser.ConfigParser()
        for filename in self.__class__.CONFIG_FILE_LOCATIONS:
            try:
                config.read(filename)
                break
            except (configparser.Error):
                pass
        return config

    def read_item_from_config(self, section=None, key=None, default=None):
        """
            grab items from the post-parsed config.  This gets better in py3.
        """
        try:
            return self.configfile.get(section, key)
        except (configparser.Error):
            return default

    def verify_sudo_user(self, username_is=None, username_as=None):
        """
            This function exists to allow for us to determine if someone is
            sudo'ing to someone else.
            Input is a "before" and "after" user.
            Output is the "after" user if the sudo is allowed, the "before" if they're not.
        """
        result = username_is
        # Yes, result is BY DEFAULT set to '_is', because sudo'ing is a rare case.
        # We will override this only after going through a gauntlet:
        if username_is and username_as:
            # ^ bypass on deletes
            if (isinstance(self.sudo_username_regexp, six.string_types) and
                    isinstance(self.sudo_users, list) and username_is in self.sudo_users):
                # ^ This is deliberately unforgiving, as a safety measure.
                # At this point we have:
                # username_is - a cert-defined user, who is in the sudoers list, and
                # username_as - a string that MAY indicate who the user wants to become.
                try:
                    as_match = re.match(self.sudo_username_regexp, username_as)
                    # If the sudoer person typed in a string that regexp matches
                    # our private pattern, we gather their target user out of the
                    # regexp match, and assign it into username_as.
                    result = as_match.group(1)
                except (re.error, AttributeError):
                    pass
        return result
