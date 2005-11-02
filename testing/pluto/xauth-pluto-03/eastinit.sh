#!/bin/sh

TESTNAME=xauth-pluto-03
source /testing/pluto/bin/eastlocal.sh

(ipsec setup stop >/dev/null)
ipsec setup start
ipsec auto --add xauth-road--eastnet


