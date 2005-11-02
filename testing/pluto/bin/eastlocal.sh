#!/bin/sh

# this script is used by "road" UMLs that want to have per-test
# configuration files, and will be hitting sunrise-oe to test with.

mkdir -p /tmp/$TESTNAME
mkdir -p /tmp/$TESTNAME/ipsec.d/cacerts
mkdir -p /tmp/$TESTNAME/ipsec.d/crls
mkdir -p /tmp/$TESTNAME/ipsec.d/certs
mkdir -p /tmp/$TESTNAME/ipsec.d/private

cp /testing/pluto/$TESTNAME/east.conf /tmp/$TESTNAME/ipsec.conf
cp /etc/ipsec.secrets                    /tmp/$TESTNAME
if [ -f /testing/pluto/$TESTNAME/east.secrets ] 
then
    cat /testing/pluto/$TESTNAME/east.secrets >>/tmp/$TESTNAME/ipsec.secrets
fi

mkdir -p /tmp/$TESTNAME/ipsec.d/policies
cp /etc/ipsec.d/*          /tmp/$TESTNAME/ipsec.d
cp /etc/ipsec.d/policies/* /tmp/$TESTNAME/ipsec.d/policies

IPSEC_CONFS=/tmp/$TESTNAME export IPSEC_CONFS
