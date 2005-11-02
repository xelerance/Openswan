#!/bin/sh

# make sure that NAT is working
ping -c 4 -n sunrise

TESTNAME=nat-pluto-01 
source /testing/pluto/bin/northlocal.sh

ipsec setup start
ipsec auto --add northnet--eastnet-nat

