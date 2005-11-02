# ipsec setup stop; umount /usr/local; mount /usr/local
# iptables -F INPUT 
# iptables -F OUTPUT

TESTNAME=dpd-01
source /testing/pluto/bin/westlocal.sh

ipsec setup start
sleep 5
ipsec auto --add west-east

