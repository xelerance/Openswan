The liboswkeys library concerns itself with loading and managing public
and private keys.  It should deal with keys from a variety of places:
    - ipsec.secrets
    - libnss (if compiled in)
    - certificates on disk
    - eventually raw rsa keys from DNS

liboswkeys might get linked in at some point into utilities, but for the
moment it exists outside of pluto in order to facilitate unit testing.
