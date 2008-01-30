#!/bin/sh

# this script is used by "west" UMLs that want to have per-test
# configuration files, and will be hitting sunrise-oe to test with.

mkdir -p /tmp/$TESTNAME
mkdir -p /tmp/$TESTNAME/ipsec.d/cacerts
mkdir -p /tmp/$TESTNAME/ipsec.d/crls
mkdir -p /tmp/$TESTNAME/ipsec.d/certs
mkdir -p /tmp/$TESTNAME/ipsec.d/private

cp /testing/pluto/$TESTNAME/west.conf /tmp/$TESTNAME/ipsec.conf
cp /etc/ipsec.secrets                    /tmp/$TESTNAME
if [ -f /testing/pluto/$TESTNAME/west.secrets ] 
then
    cat /testing/pluto/$TESTNAME/west.secrets >>/tmp/$TESTNAME/ipsec.secrets
fi

mkdir -p /tmp/$TESTNAME/ipsec.d/policies
cp -r /etc/ipsec.d/*          /tmp/$TESTNAME/ipsec.d

IPSEC_CONFS=/tmp/$TESTNAME export IPSEC_CONFS
