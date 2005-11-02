# remove the block
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
sleep 10
# Tunnel should be back up now
ipsec eroute
echo done

