iamvpnlibrary
==========

Python lib for common VPN-related access queries at Mozilla.
This abstracts away the (presently LDAP) query layer and prepares for a future where LDAP is replaced by... something else queryable.

Building
~~~~~~~
   fpm -s python -t rpm --rpm-dist "$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" --iteration 1 iamvpnlibrary/setup.py

Testing
~~~~~~~
Fill in the [testing] subsection of the config file, then ```make test```

Python dependencies
~~~~~~~~~~~~~~~~~~~

* python-ldap
* python-netaddr

Usage
-----

Login/pass:

.. code::

    import iamvpnlibrary

    l = iamvpnlibrary.IAMVPNLibrary()
    print l.user_allowed_to_vpn('me@company.com')
    print l.does_user_require_vpn_mfa('me@company.com')
    print l.get_allowed_vpn_ips('me@company.com')
    print l.get_allowed_vpn_acls('me@company.com')

