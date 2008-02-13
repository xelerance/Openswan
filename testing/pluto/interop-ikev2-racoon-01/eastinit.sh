: ==== start ====
TESTNAME=interop-ikev2-racoon-01
source /testing/pluto/bin/eastlocal.sh

#racoon way of starting
/usr/local/racoon2/etc/init.d/spmd start
# no conns are loaded
/usr/local/racoon2/etc/init.d/iked start
sleep 3
# 
