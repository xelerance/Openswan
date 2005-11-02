#ipsec setup stop
#umount /var/tmp; mount /var/tmp
#umount /usr/local; mount /usr/local

TESTNAME=aggr-pluto-02
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet-aggr-psk
/testing/pluto/basic-pluto-01/eroutewait.sh trap
