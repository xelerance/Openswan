This directory contains a very basic CA for managing the certificates the
the unit tests.

The script in:

    signCA.sh

should be run once every three years to resign the CA.

The script in

    signall.sh

should be run every year to update the individual certificates.

It is suggested that this be done every labour day
(first Monday in September).

These are all *RSA* keys.  When it time to do ECDSA and EDDSA keys, then
draft-moskowitz-ecdsa-pki should be used.


