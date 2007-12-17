ipsec auto --up  westnet-eastnet
ip xfrm policy
ip xfrm state
ipsec auto --down  westnet-eastnet
sleep 1
ip xfrm policy
ip xfrm state
ipsec auto --delete  westnet-eastnet
sleep 1
ip xfrm policy
ip xfrm state
echo done
