ipsec auto --up  westnet-eastnet-ipv6
ping6 -n -c 4 2001:db8:0:1::254 2001:db8:0:2::254
ip xfrm pol
ip xfrm state
echo done
