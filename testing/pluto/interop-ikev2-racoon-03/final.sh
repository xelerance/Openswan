: ==== cut ====
if [ -n "`pidof pluto`" ]
then
	ipsec auto --status
	cat /tmp/pluto.log
fi
if [ -n "`pidof iked`" ]
then
	cat /tmp/racoon.log
fi
: ==== tuc ====
if [ -f /tmp/core ]; then echo CORE FOUND; mv /tmp/core /var/tmp; fi
: ==== end ====
