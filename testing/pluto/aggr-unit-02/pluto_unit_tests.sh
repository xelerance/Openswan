#!/bin/sh

TESTING=${TESTING:-/testing}
PATH=${TESTING}/pluto/bin:$PATH export PATH
TESTNAME=aggr-unit-02

export PLUTO="ipsec pluto"
export WHACK="ipsec whack"
${TESTING}/pluto/bin/ifconfigs up
. CONFIG

cd /tmp
mkdir -p $TESTNAME
cd $TESTNAME

export HELPERS="--nhelpers 0 "

mkdir -p log.ref
mkdir -p log
LD=log
ln -s ${TESTING}/pluto/$TESTNAME/isakmp-aggr-psk-east.txt log.ref/pr-log
ln -s ${TESTING}/pluto/$TESTNAME/isakmp-aggr-psk-west.txt log.ref/pi-log
ln -s ${TESTING}/pluto/$TESTNAME/isakmp-aggr-psk-whack.txt log.ref/wi-log
ln -s ${TESTING}/pluto/ipsec.secrets .
ln -s ${TESTING}/pluto/ipsec.d/west .
ln -s ${TESTING}/pluto/ipsec.d/east .

# make sure that we can core dump!
ulimit -c unlimited

# start Initiator pluto (daemon forks to return control)
$DOPLUTO west >$LD/pi-log 2>&1
# start Responder pluto (daemon forks to return control)
$DOPLUTO east >$LD/pr-log 2>&1
$DOWHACK listen

sh $TESTING/pluto/$TESTNAME/dowhack.sh 

export HELPERS="--nhelpers 1 "

# start Initiator pluto (daemon forks to return control)
$DOPLUTO west >$LD/pi-log 2>&1
# start Responder pluto (daemon forks to return control)
$DOPLUTO east >$LD/pr-log 2>&1
$DOWHACK listen

sh $TESTING/pluto/$TESTNAME/dowhack.sh 

