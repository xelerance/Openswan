: ==== cut ====
if [ -n "`pidof pluto`" ]
then
	ipsec auto --status
	cat /tmp/pluto.log
elif [ -n "`pidof charon`" ]
then
	grep charon /var/log/messages
fi
: ==== tuc ====
if [ -f /tmp/core ]; then echo CORE FOUND; mv /tmp/core /var/tmp; fi
: ==== end ====
