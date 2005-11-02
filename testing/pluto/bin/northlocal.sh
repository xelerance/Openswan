#!/bin/sh

# this script is used by "north" UMLs that want to have per-test
# configuration files, and will be hitting sunrise-oe to test with.

mkdir -p /tmp/$TESTNAME
cp /testing/pluto/$TESTNAME/north.conf /tmp/$TESTNAME/ipsec.conf
cp /etc/ipsec.secrets                    /tmp/$TESTNAME

mkdir -p /tmp/$TESTNAME/ipsec.d/policies
cp /etc/ipsec.d/policies/* /tmp/$TESTNAME/ipsec.d/policies

IPSEC_CONFS=/tmp/$TESTNAME export IPSEC_CONFS
