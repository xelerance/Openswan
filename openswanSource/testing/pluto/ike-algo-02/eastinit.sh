#!/bin/sh

: ==== start ====

TESTNAME=ike-algo-02
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add north-east-alg-test-01
ipsec auto --add north-east-alg-test-02
ipsec auto --add north-east-alg-test-03
ipsec auto --add north-east-alg-test-04
ipsec auto --add north-east-alg-test-05
ipsec auto --add north-east-alg-test-06
ipsec auto --add north-east-alg-test-07

echo done


