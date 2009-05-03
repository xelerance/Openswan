: This should fail, but only because .1 of westnests has no TXT.
: We use --up so that the negotiation is logged.
: Failure should come before negotiation is actually started.
: No shunt eroute will be created because of using --oppohere/--oppothere.

ipsec auto --up simulate-OE-east-west-1

ipsec eroute

: the nether world according to pluto
: ==== cut ====
ipsec auto --status
: ==== tuc ====

echo end

