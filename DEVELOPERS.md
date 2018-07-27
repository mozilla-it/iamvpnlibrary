# Development Notes

The classes of this module are designed as:

```
              +-----------------+
              |IAMVPNLibraryBase|
              +-----------------+
               /               \
              /                 \
             /                   \
+-----------------+          +-----------------+
|IAMVPNLibraryLDAP|          |some future class|
+-----------------+          +-----------------+
             ^
             |
               \
                +-------------+
                |IAMVPNLibrary|
                +-------------+

```

The notion here is that LDAP is on its way out, and LDAP is not the only way we have to provide access information.  So ```IAMVPNLibrary``` is a 'gateway' class: it answers questions in terms of users and true/false statements that are abstracted away from LDAP particulars.  When a future auth method comes along, we should build a sibling class to LDAP.  When its test suite returns the same answers, ```IAMVPNLibrary``` can switch its inheritance pointer from ```IAMVPNLibraryLDAP``` and use some-future-class with a simple redeploy of this library, without having to change LDAP queries in downstream portions of the VPN libraries.

As such, ```IAMVPNLibrary``` (the class) doesn't have public methods.  It passes through to whoever is upstream.  It COULD have methods, but make sure you're doing a smart thing if you do this.

The mail library should have NO knowledge of LDAP.  Shouldn't pass anything upstream that looks like a DN, shouldn't raise any errors that need LDAP.  None of those shenanigans.

# Testing

The ```test``` subdir has unit tests.  You can ```make test``` in the root to run the test suite.

In the ```test``` subdir, the ```test_public_methods.py``` unit test runs uniform tests against the public methods.  It runs them once against the LDAP library, and once against the main library.  Obviously in the current form, where we have just the one access method in LDAP, these are redundant tests.  In the future, when there are multiple access methods, this multi-inheritance setup will let you compare different libraries with the same tests and see if one fails where the other succeeds.

We also test the private methods within the ldap class, to try to find issues.
