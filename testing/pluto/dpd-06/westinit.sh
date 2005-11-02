
# remove the block
iptables -F

# Tunnel should be back up now
ipsec eroute
echo done

TESTNAME=dpd-03
source /testing/pluto/bin/westlocal.sh

ipsec setup start

ipsec auto --add west-east

ipsec whack --debug-dpd --debug-control


