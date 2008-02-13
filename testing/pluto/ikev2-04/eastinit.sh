: ==== start ====
TESTNAME=ikev2-04
source /testing/pluto/bin/eastlocal.sh

# tunnel_ike.conf and defaults.conf and vals.conf need to be
# linked to files here.

/usr/local/racoon2/etc/init.d/spmd start
/usr/local/racoon2/etc/init.d/iked start
sleep 2
echo done
