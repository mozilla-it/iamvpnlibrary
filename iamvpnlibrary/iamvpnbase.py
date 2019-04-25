#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
"""
    This file creates a base object for IAM VPN access information.
"""

import os
import collections
try:
    # 2.7's module:
    from ConfigParser import SafeConfigParser as ConfigParser
    from ConfigParser import NoOptionError, NoSectionError, \
        InterpolationMissingOptionError
except ImportError:  # pragma: no cover
    # 3's module:
    from configparser import ConfigParser
    from configparser import NoOptionError, NoSectionError, \
        InterpolationMissingOptionError


ParsedACL = collections.namedtuple(
    'ParsedACL', ['rule', 'address', 'portstring', 'description'])


class IAMVPNLibraryBase(object):  # pylint: disable=too-few-public-methods
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
            self.fail_open = self.configfile.getboolean('failure',
                                                        'fail_open')
        except (NoOptionError, NoSectionError):  # pragma: no cover
            self.fail_open = False

    def _ingest_config_from_file(self, conf_file=None):
        """
            pull in config variables from a system file
        """
        if conf_file is None:
            conf_file = self.__class__.CONFIG_FILE_LOCATIONS
        if not isinstance(conf_file, list):
            conf_file = [conf_file]
        config = ConfigParser()
        for filename in conf_file:
            if os.path.isfile(filename):
                try:
                    config.read(filename)
                    break
                except:  # pragma: no cover  pylint: disable=bare-except
                    # This bare-except is due to 2.7
                    # limitations in configparser.
                    pass
        return config

    def read_item_from_config(self, section=None, key=None, default=None):
        """
            grab items from the post-parsed config
        """
        try:
            return self.configfile.get(section, key)
        except (NoOptionError, NoSectionError, InterpolationMissingOptionError):
            return default
