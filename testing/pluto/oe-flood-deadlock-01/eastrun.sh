ipsec eroute

: ==== cut ====
: the nether world according to pluto
ifconfig eth0
route -n
ipsec auto --status
: ==== tuc ====

# This clearly demonstrated a lwdnsq bug (fixed 2002 Apr 2)
#	ipsec lwdnsq </testing/pluto/oe-flood-deadlock-01/bad-lwdnsq-queries

# This is interesting, but may slow down things enought to avoid a race:
#	ipsec whack --debug-dns

echo DONE
