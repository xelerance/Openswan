#!/bin/sh

# New style cert generation -- Paul

source ../../umlsetup.sh

sed -e "s,@BUILDTOP@,$BUILDTOP," nic/etc/openssl/openssl.cnf.in >nic/etc/openssl/openssl.cnf

( cd ../x509/ ; sh dist_certs )

