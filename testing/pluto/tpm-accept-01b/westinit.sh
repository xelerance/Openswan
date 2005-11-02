#!/bin/sh
: ==== start ====

TESTNAME=tpm-accept-01
source /testing/pluto/bin/westlocal.sh

ipsec setup start
ipsec auto --add west--east-psk
echo done


