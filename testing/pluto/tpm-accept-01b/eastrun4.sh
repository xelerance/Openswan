echo "Adding 1DES policy"

# delete any previous policy.
/usr/local/libexec/ipsec/whack --name west--east-psk-1des --delete
/usr/local/libexec/ipsec/whack --name west--east-psk-3des --delete

/usr/local/libexec/ipsec/whack --name west--east-psk-aes --encrypt --tunnel \
	--pfs --dpdaction "hold" --psk \
	--host "205.150.200.252" --nexthop "205.150.200.251" --updown "ipsec _updown" \
	--id "205.150.200.252"  --sendcert "always" \
	--to \
	--host "205.150.200.251" --nexthop "205.150.200.252" --updown "ipsec _updown" \
	--id "205.150.200.251"  --sendcert "always" \
	--ipseclifetime "28800" --rekeymargin "540" \
	--ikealg "aes128" --impair-die-oninfo \
	--keyingtries "0"    

/usr/local/libexec/ipsec/whack --name west--east-psk-aes --initiate

