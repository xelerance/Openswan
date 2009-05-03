: ==== cut ====
ipsec auto --status
: ==== tuc ====
cat /tmp/pluto.log
if [ -f /tmp/core ]; then echo CORE FOUND; mv /tmp/core /var/tmp; fi
: ==== end ====
