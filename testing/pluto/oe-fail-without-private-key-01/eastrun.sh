: This should fail, but only because we do not know our own secret.
: We use --oppohere/--oppothere so that the negotiation is logged.
: Failure should come before negotiation is actually started.
: No shunt eroute will be created because of using --oppohere/--oppothere.

ipsec whack --oppohere 192.1.2.23 --oppothere 192.0.1.3

ipsec eroute

: Try again, using traffic to prompt negotiation.
: This should result in a %drop

ping -c 2 -n 192.0.1.3

ipsec eroute

: the nether world according to pluto
: ==== cut ====
ipsec auto --status
: ==== tuc ====

echo end

