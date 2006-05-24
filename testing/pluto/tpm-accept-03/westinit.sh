#!/bin/sh
: ==== start ====

TESTNAME=tpm-accept-03
source /testing/pluto/bin/westlocal.sh

ipsec setup start
ipsec auto --add west--east-psk
/testing/pluto/bin/wait-until-pluto-started
echo done



