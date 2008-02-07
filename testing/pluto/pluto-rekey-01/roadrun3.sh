: check if eroute owner is the same as newest IPSEC
if ipsec whack --status | grep 'newest IPSEC' | grep 'eroute owner' >/dev/null;  then echo newest is eroute owner; else echo two SAs alive; fi



