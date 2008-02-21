: ==== cut ====
if [ -n "`pidof pluto`" ]; then ipsec auto --status; fi
cat /tmp/*.log
: ==== tuc ====
if [ -f /tmp/core ]; then echo CORE FOUND; mv /tmp/core /var/tmp; fi
: ==== end ====
