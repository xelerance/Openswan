#!/bin/sh

: ==== start ====

TESTNAME=fail-x509-02
source /testing/pluto/bin/northlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north-east-x509-pluto-02
echo done
