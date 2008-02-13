: ==== start ====
TESTNAME=interop-ikev2-strongswan-01
source /testing/pluto/bin/eastlocal.sh

#strongswan way of starting
/usr/local/strongswan/sbin/ipsec start
# no conns are loaded
# 
/testing/pluto/bin/wait-until-pluto-started
