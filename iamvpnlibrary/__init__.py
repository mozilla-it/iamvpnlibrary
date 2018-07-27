#!/usr/bin/env python
"""
    This file creates the 'public facing' object for IAM VPN
    access information.  It shows very little on its own, instead
    relying on parentage to handle calls.
"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation

from .iamvpnldap import IAMVPNLibraryLDAP
# If you ever want to change the underpinning to not be LDAP,
# change your imports above, and your class parentage below,
# then run tests.


class IAMVPNLibrary(IAMVPNLibraryLDAP):
    """
        This class does nothing, by design.  The upstream class should
        implement and return structures that remain consistent if you
        change from one to another.  So if you're reading this, you are
        likely more interested in either the parent class of this, OR
        the test suite that calls into this.

        The test suite for this class covers the public-facing calls.
        So if tests pass, your upstream class implements the things
        we have found that we care about.
    """
    pass
