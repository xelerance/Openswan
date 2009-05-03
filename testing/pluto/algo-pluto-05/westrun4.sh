: east set up for both, expect 3des, since it has priority
ipsec auto --replace  westnet-eastnet-both
ipsec auto --up       westnet-eastnet-both
ipsec auto --delete   westnet-eastnet-both

: east set up for both, expect 3des
ipsec auto --replace  westnet-eastnet-3des
ipsec auto --up       westnet-eastnet-3des
ipsec auto --delete   westnet-eastnet-3des

: east set up for both, expect aes
ipsec auto --replace  westnet-eastnet-aes256
ipsec auto --up       westnet-eastnet-aes256
ipsec auto --delete   westnet-eastnet-aes256
echo done4

