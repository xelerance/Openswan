: ==== start ====
TESTNAME=interop-ikev2-racoon-02
source /testing/pluto/bin/eastlocal.sh

/usr/local/racoon2/etc/init.d/spmd start
/usr/local/racoon2/etc/init.d/iked start

sleep 3
