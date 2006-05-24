echo "Adding 1DES policy"

# set pluto such that it gives up when it gets unauthenticated informational
# messages. Normally not safe, but this is a test case.
ipsec whack --name west--east-psk-1des --delete
ipsec whack --name west--east-psk-3des --delete

ipsec whack --name west--east-psk-1des --encrypt --tunnel --pfs --dpdaction "hold" --psk --host "192.1.2.45" --nexthop "192.1.2.23" --updown "ipsec _updown" --id "192.1.2.45"  --sendcert "always" --to --host "192.1.2.23" --nexthop "192.1.2.45" --updown "ipsec _updown" --id "192.1.2.23"  --sendcert "always" --ipseclifetime "28800" --rekeymargin "540" --ikealg "des" --impair-die-oninfo --keyingtries "0"    

ipsec whack --name west--east-psk-1des --initiate

echo "Switching to 3DES policy"
ipsec whack --name west--east-psk-1des --delete

ipsec whack --name west--east-psk-3des --delete
ipsec whack --name west--east-psk-3des --encrypt --tunnel --pfs --dpdaction "hold" --psk --host "192.1.2.45" --nexthop "192.1.2.23" --updown "ipsec _updown" --id "192.1.2.45"  --sendcert "always" --to --host "192.1.2.23" --nexthop "192.1.2.45" --updown "ipsec _updown" --id "192.1.2.23"  --sendcert "always" --ipseclifetime "28800" --rekeymargin "540" --ikealg "3des" --keyingtries "0"    

ipsec whack --name west--east-psk-3des --initiate
